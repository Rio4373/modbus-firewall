package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/logging"
	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
)

func TestHotReloadObserveToEnforceOnSameConnection(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamRequests := startCountingUpstreamServerForReload(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x000A})
	})
	proxyAddr := reserveTCPAddress(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	eventsDBPath := filepath.Join(tmpDir, "events.db")

	writeProxyConfigFile(t, configPath, config.ModeObserve, proxyAddr, upstreamAddr, eventsDBPath)
	writePolicyFile(t, policyPath, denyAllPolicyYAML())

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("не удалось загрузить config для теста: %v", err)
	}

	service := New(cfg, logging.NewDiscard(), nil, nil, WithHotReload(configPath, policyPath, 50*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	allowRequest := buildReadRequest(1, 1, 0x006B, 1)
	if err := writeAll(clientConn, allowRequest, time.Second); err != nil {
		t.Fatalf("не удалось отправить запрос в observe режиме: %v", err)
	}
	allowResponse, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать ответ в observe режиме: %v", err)
	}
	expectedAllow := buildReadResponse(allowRequest, []uint16{0x000A})
	if string(allowResponse) != string(expectedAllow) {
		t.Fatalf("unexpected observe response: want=% X got=% X", expectedAllow, allowResponse)
	}

	writeProxyConfigFile(t, configPath, config.ModeEnforce, proxyAddr, upstreamAddr, eventsDBPath)

	_, deniedResponse := waitUntilRequestDenied(t, clientConn, 0x006B, 1, 3*time.Second)
	if len(deniedResponse) != 9 {
		t.Fatalf("ожидали Modbus exception ответ, получили: % X", deniedResponse)
	}

	before := upstreamRequests.Load()
	secondDeniedRequest := buildReadRequest(999, 1, 0x006B, 1)
	if err := writeAll(clientConn, secondDeniedRequest, time.Second); err != nil {
		t.Fatalf("не удалось отправить второй deny запрос: %v", err)
	}
	secondDeniedResponse, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать второй deny ответ: %v", err)
	}
	if !isExceptionResponseForRequest(secondDeniedResponse, secondDeniedRequest, modbusExceptionIllegalFunction) {
		t.Fatalf("ожидали exception после observe->enforce: got=% X", secondDeniedResponse)
	}

	time.Sleep(150 * time.Millisecond)
	after := upstreamRequests.Load()
	if after != before {
		t.Fatalf("ожидали что deny запрос не попадет в upstream: before=%d after=%d", before, after)
	}

	cancel()
	waitServiceExit(t, errCh)
}

func TestHotReloadPolicyChangeWithoutRestart(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamRequests := startCountingUpstreamServerForReload(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x0011})
	})
	proxyAddr := reserveTCPAddress(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	eventsDBPath := filepath.Join(tmpDir, "events.db")

	writeProxyConfigFile(t, configPath, config.ModeEnforce, proxyAddr, upstreamAddr, eventsDBPath)
	writePolicyFile(t, policyPath, allowReadRangePolicyYAML(100, 120))

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("не удалось загрузить config для теста: %v", err)
	}

	policyCfg, err := policy.Load(policyPath)
	if err != nil {
		t.Fatalf("не удалось загрузить policy для теста: %v", err)
	}
	matcher, err := policy.NewMatcher(policyCfg)
	if err != nil {
		t.Fatalf("не удалось создать matcher для теста: %v", err)
	}

	service := New(cfg, logging.NewDiscard(), matcher, nil, WithHotReload(configPath, policyPath, 50*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	allowedRequest := buildReadRequest(10, 1, 0x006B, 1)
	if err := writeAll(clientConn, allowedRequest, time.Second); err != nil {
		t.Fatalf("не удалось отправить allow запрос: %v", err)
	}
	allowedResponse, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать allow ответ: %v", err)
	}
	expectedAllowed := buildReadResponse(allowedRequest, []uint16{0x0011})
	if string(allowedResponse) != string(expectedAllowed) {
		t.Fatalf("unexpected allow response: want=% X got=% X", expectedAllowed, allowedResponse)
	}

	writePolicyFile(t, policyPath, denyAllPolicyYAML())
	_, _ = waitUntilRequestDenied(t, clientConn, 0x006B, 1, 3*time.Second)

	before := upstreamRequests.Load()
	req := buildReadRequest(1001, 1, 0x006B, 1)
	if err := writeAll(clientConn, req, time.Second); err != nil {
		t.Fatalf("не удалось отправить проверочный deny запрос: %v", err)
	}
	resp, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать проверочный deny ответ: %v", err)
	}
	if !isExceptionResponseForRequest(resp, req, modbusExceptionIllegalFunction) {
		t.Fatalf("ожидали exception после hot reload policy: got=% X", resp)
	}

	time.Sleep(150 * time.Millisecond)
	after := upstreamRequests.Load()
	if after != before {
		t.Fatalf("ожидали что запрос после deny policy не попадет в upstream: before=%d after=%d", before, after)
	}

	cancel()
	waitServiceExit(t, errCh)
}

func waitUntilRequestDenied(t *testing.T, conn net.Conn, startAddress uint16, quantity uint16, timeout time.Duration) ([]byte, []byte) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	transactionID := uint16(100)
	for {
		request := buildReadRequest(transactionID, 1, startAddress, quantity)
		if err := writeAll(conn, request, time.Second); err != nil {
			t.Fatalf("не удалось отправить запрос при ожидании deny: %v", err)
		}

		response, err := readModbusADU(conn, time.Second)
		if err != nil {
			t.Fatalf("не удалось прочитать ответ при ожидании deny: %v", err)
		}

		if isExceptionResponseForRequest(response, request, modbusExceptionIllegalFunction) {
			return request, response
		}

		if time.Now().After(deadline) {
			t.Fatalf("не дождались deny ответа за %s, последний ответ=% X", timeout, response)
		}
		transactionID++
		time.Sleep(30 * time.Millisecond)
	}
}

func isExceptionResponseForRequest(response []byte, request []byte, exceptionCode uint8) bool {
	if len(response) != 9 || len(request) < 8 {
		return false
	}
	if response[0] != request[0] || response[1] != request[1] {
		return false
	}
	if response[2] != 0x00 || response[3] != 0x00 {
		return false
	}
	if response[4] != 0x00 || response[5] != 0x03 {
		return false
	}
	if response[6] != request[6] {
		return false
	}
	if response[7] != (request[7] | 0x80) {
		return false
	}
	return response[8] == exceptionCode
}

func startCountingUpstreamServerForReload(t *testing.T, responseBuilder func(request []byte) []byte) (string, *atomic.Int64) {
	t.Helper()

	counter := &atomic.Int64{}
	addr := startTestUpstreamServer(t, func(request []byte) []byte {
		counter.Add(1)
		return responseBuilder(request)
	})
	return addr, counter
}

func writeProxyConfigFile(t *testing.T, path string, mode config.Mode, listenAddr string, upstreamAddr string, eventsPath string) {
	t.Helper()

	content := fmt.Sprintf(`mode: %s
server:
  listen_addr: %q
proxy:
  upstream_addr: %q
  dial_timeout: "1s"
  read_timeout: "2s"
  write_timeout: "2s"
logging:
  level: "error"
  format: "text"
storage:
  events_path: %q
features:
  enable_replay: false
  enable_generator: false
`, mode, listenAddr, upstreamAddr, eventsPath)
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать config %q: %v", path, err)
	}
}

func writePolicyFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать policy %q: %v", path, err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func denyAllPolicyYAML() string {
	return `version: 1
default_action: deny
rules: []
`
}

func allowReadRangePolicyYAML(start uint16, end uint16) string {
	return fmt.Sprintf(`version: 1
default_action: deny
rules:
  - id: allow-read
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - start: %d
        end: %d
`, start, end)
}
