package proxy

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/logging"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

func TestObserveModeForwardsTrafficAndStoresEvent(t *testing.T) {
	t.Parallel()

	upstreamAddr := startTestUpstreamServer(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x000A, 0x0102})
	})

	dbPath := filepath.Join(t.TempDir(), "events.db")
	eventStore, err := storage.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("не удалось создать sqlite store: %v", err)
	}
	defer func() {
		if closeErr := eventStore.Close(); closeErr != nil {
			t.Fatalf("не удалось закрыть sqlite store: %v", closeErr)
		}
	}()

	proxyAddr := reserveTCPAddress(t)
	cfg := testProxyConfig(proxyAddr, upstreamAddr)

	service := New(cfg, logging.NewDiscard(), nil, eventStore)
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

	assertEventuallyEventStored(t, eventStore, func(events []storage.ModbusEvent) {
		event := events[0]
		if event.FunctionCode != 3 {
			t.Fatalf("ожидали function_code=3, получили %d", event.FunctionCode)
		}
		if event.StartAddress != 0x006B {
			t.Fatalf("ожидали start_address=107, получили %d", event.StartAddress)
		}
		if event.Quantity != 2 {
			t.Fatalf("ожидали quantity=2, получили %d", event.Quantity)
		}
		if event.OperationType != storage.OperationTypeRead {
			t.Fatalf("ожидали operation_type=read, получили %q", event.OperationType)
		}
		if event.SourceIP == "" || event.DestinationIP == "" {
			t.Fatalf("ожидали заполненные source/destination ip, получили %+v", event)
		}
	})

	cancel()
	waitServiceExit(t, errCh)
}

func TestObserveModeDoesNotStopOnEventSaveError(t *testing.T) {
	t.Parallel()

	upstreamAddr := startTestUpstreamServer(t, func(request []byte) []byte {
		return buildReadResponse(request, []uint16{0x0011})
	})

	proxyAddr := reserveTCPAddress(t)
	cfg := testProxyConfig(proxyAddr, upstreamAddr)

	service := New(cfg, logging.NewDiscard(), nil, failingEventStore{})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Run(ctx)
	}()
	defer cancel()

	clientConn := dialWithRetry(t, proxyAddr, 3*time.Second)
	defer clientConn.Close()

	for i := 0; i < 2; i++ {
		request := buildReadRequest(uint16(i+1), 1, 0x0001, 1)
		if err := writeAll(clientConn, request, time.Second); err != nil {
			t.Fatalf("не удалось отправить запрос #%d: %v", i+1, err)
		}

		response, err := readModbusADU(clientConn, time.Second)
		if err != nil {
			t.Fatalf("не удалось прочитать ответ #%d: %v", i+1, err)
		}

		expectedResponse := buildReadResponse(request, []uint16{0x0011})
		if string(response) != string(expectedResponse) {
			t.Fatalf("ответ #%d не совпал: ожидали % X, получили % X", i+1, expectedResponse, response)
		}
	}

	cancel()
	waitServiceExit(t, errCh)
}

func startTestUpstreamServer(t *testing.T, responseBuilder func(request []byte) []byte) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось запустить тестовый upstream listener: %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				for {
					request, readErr := readModbusADU(c, 3*time.Second)
					if readErr != nil {
						return
					}

					response := responseBuilder(request)
					if writeErr := writeAll(c, response, 3*time.Second); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось зарезервировать адрес для proxy: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func dialWithRetry(t *testing.T, addr string, timeout time.Duration) net.Conn {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("не удалось подключиться к %s за %s: %v", addr, timeout, err)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func testProxyConfig(listenAddr string, upstreamAddr string) config.Config {
	return config.Config{
		Mode: config.ModeObserve,
		Server: config.ServerConfig{
			ListenAddr: listenAddr,
		},
		Proxy: config.ProxyConfig{
			UpstreamAddr: upstreamAddr,
			DialTimeout:  "1s",
			ReadTimeout:  "2s",
			WriteTimeout: "2s",
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "text",
		},
	}
}

func buildReadRequest(transactionID uint16, unitID uint8, startAddress uint16, quantity uint16) []byte {
	request := []byte{
		byte(transactionID >> 8), byte(transactionID),
		0x00, 0x00,
		0x00, 0x06,
		unitID,
		0x03,
		byte(startAddress >> 8), byte(startAddress),
		byte(quantity >> 8), byte(quantity),
	}
	return request
}

func buildReadResponse(request []byte, values []uint16) []byte {
	transactionIDHigh := request[0]
	transactionIDLow := request[1]
	unitID := request[6]
	functionCode := request[7]

	byteCount := len(values) * 2
	length := uint16(1 + 1 + 1 + byteCount)

	response := make([]byte, 0, 9+byteCount)
	response = append(response,
		transactionIDHigh,
		transactionIDLow,
		0x00,
		0x00,
		byte(length>>8),
		byte(length),
		unitID,
		functionCode,
		byte(byteCount),
	)
	for _, value := range values {
		response = append(response, byte(value>>8), byte(value))
	}
	return response
}

func assertEventuallyEventStored(t *testing.T, eventStore *storage.SQLiteStore, assertFn func(events []storage.ModbusEvent)) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := eventStore.ListEvents(context.Background(), storage.EventListFilter{Limit: 10})
		if err == nil && len(events) > 0 {
			assertFn(events)
			return
		}

		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("событие не появилось в storage: %v", err)
			}
			t.Fatal("событие не появилось в storage за отведенное время")
		}

		time.Sleep(30 * time.Millisecond)
	}
}

func waitServiceExit(t *testing.T, errCh <-chan error) {
	t.Helper()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("proxy завершился с ошибкой: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy не завершился после cancel")
	}
}

type failingEventStore struct{}

func (failingEventStore) SaveEvent(context.Context, storage.ModbusEvent) (int64, error) {
	return 0, errors.New("искусственная ошибка сохранения события")
}

func (failingEventStore) ListEvents(context.Context, storage.EventListFilter) ([]storage.ModbusEvent, error) {
	return nil, errors.New("метод не используется")
}

func (failingEventStore) ListEventsForReplay(context.Context, int) ([]storage.ModbusEvent, error) {
	return nil, errors.New("метод не используется")
}

func (failingEventStore) ListPolicyCandidates(context.Context, int) ([]storage.PolicyCandidate, error) {
	return nil, errors.New("метод не используется")
}

func (failingEventStore) Close() error {
	return nil
}
