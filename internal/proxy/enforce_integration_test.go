package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/logging"
	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
)

func TestEnforceModeAllowedRequestPasses(t *testing.T) {
	t.Parallel()

	upstreamAddr, requestCount := startCountingUpstreamServer(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x000A, 0x0102})
	})

	proxyAddr := reserveTCPAddress(t)
	cfg := testProxyConfig(proxyAddr, upstreamAddr)
	cfg.Mode = config.ModeEnforce

	matcher := mustTestMatcher(t, policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules: []policy.Rule{
			{
				ID:             "allow-range",
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{"127.0.0.1"},
				DestinationIPs: []string{"127.0.0.1"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []policy.AddressRange{{Start: 100, End: 120}},
			},
		},
	})

	service := New(cfg, logging.NewDiscard(), matcher, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	request := buildReadRequest(1, 1, 0x006B, 2)
	if err := writeAll(clientConn, request, time.Second); err != nil {
		t.Fatalf("не удалось отправить запрос через proxy: %v", err)
	}

	response, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать ответ через proxy: %v", err)
	}

	expectedResponse := buildReadResponse(request, []uint16{0x000A, 0x0102})
	if string(response) != string(expectedResponse) {
		t.Fatalf("ответ через proxy не совпал:\nожидали: % X\nполучили: % X", expectedResponse, response)
	}

	if got := requestCount.Load(); got != 1 {
		t.Fatalf("ожидали 1 запрос в upstream, получили %d", got)
	}

	cancel()
	waitServiceExit(t, errCh)
}

func TestEnforceModeDeniedRequestBlocked(t *testing.T) {
	t.Parallel()

	upstreamAddr, requestCount := startCountingUpstreamServer(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x0011})
	})

	proxyAddr := reserveTCPAddress(t)
	cfg := testProxyConfig(proxyAddr, upstreamAddr)
	cfg.Mode = config.ModeEnforce

	matcher := mustTestMatcher(t, policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules: []policy.Rule{
			{
				ID:             "allow-small-range",
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{"127.0.0.1"},
				DestinationIPs: []string{"127.0.0.1"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []policy.AddressRange{{Start: 0, End: 10}},
			},
		},
	})

	service := New(cfg, logging.NewDiscard(), matcher, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	request := buildReadRequest(2, 1, 0x006B, 2)
	if err := writeAll(clientConn, request, time.Second); err != nil {
		t.Fatalf("не удалось отправить запрос через proxy: %v", err)
	}

	response, err := readModbusADU(clientConn, time.Second)
	if err != nil {
		t.Fatalf("не удалось прочитать exception ответ от proxy: %v", err)
	}

	expectedException := buildExpectedExceptionResponse(request, 0x01)
	if string(response) != string(expectedException) {
		t.Fatalf("exception ответ не совпал:\nожидали: % X\nполучили: % X", expectedException, response)
	}

	if !waitForUpstreamRequests(requestCount, 0, 300*time.Millisecond) {
		t.Fatalf("ожидали 0 запросов в upstream для заблокированного запроса, получили %d", requestCount.Load())
	}

	cancel()
	waitServiceExit(t, errCh)
}

func TestEnforceModeParseErrorSafeDeny(t *testing.T) {
	t.Parallel()

	upstreamAddr, requestCount := startCountingUpstreamServer(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x0001})
	})

	proxyAddr := reserveTCPAddress(t)
	cfg := testProxyConfig(proxyAddr, upstreamAddr)
	cfg.Mode = config.ModeEnforce

	matcher := mustTestMatcher(t, policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules: []policy.Rule{
			{
				ID:             "allow-read",
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{"127.0.0.1"},
				DestinationIPs: []string{"127.0.0.1"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []policy.AddressRange{{Start: 0, End: 100}},
			},
		},
	})

	service := New(cfg, logging.NewDiscard(), matcher, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	invalidRequest := []byte{
		0x00, 0x10,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x11,
		0x00, 0x01,
		0x00, 0x01,
	}
	if err := writeAll(clientConn, invalidRequest, time.Second); err != nil {
		t.Fatalf("не удалось отправить невалидный запрос через proxy: %v", err)
	}

	_, err := readModbusADU(clientConn, time.Second)
	if err == nil {
		t.Fatal("ожидали ошибку чтения ответа после safe deny по ошибке парсинга")
	}

	if !waitForUpstreamRequests(requestCount, 0, 300*time.Millisecond) {
		t.Fatalf("ожидали 0 запросов в upstream при ошибке парсинга, получили %d", requestCount.Load())
	}

	cancel()
	waitServiceExit(t, errCh)
}

func startCountingUpstreamServer(t *testing.T, responseBuilder func(request []byte) []byte) (string, *atomic.Int64) {
	t.Helper()

	counter := &atomic.Int64{}
	addr := startTestUpstreamServer(t, func(request []byte) []byte {
		counter.Add(1)
		return responseBuilder(request)
	})
	return addr, counter
}

func waitForUpstreamRequests(counter *atomic.Int64, expected int64, duration time.Duration) bool {
	deadline := time.Now().Add(duration)
	for {
		if counter.Load() == expected {
			if time.Now().After(deadline) {
				return true
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return false
	}
}

func buildExpectedExceptionResponse(request []byte, exceptionCode byte) []byte {
	return []byte{
		request[0], request[1],
		0x00, 0x00,
		0x00, 0x03,
		request[6],
		request[7] | 0x80,
		exceptionCode,
	}
}

func mustTestMatcher(t *testing.T, policyCfg policy.Policy) policy.Engine {
	t.Helper()

	matcher, err := policy.NewMatcher(policyCfg)
	if err != nil {
		t.Fatalf("не удалось создать matcher: %v", err)
	}
	return matcher
}
