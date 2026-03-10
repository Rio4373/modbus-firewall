package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/logging"
	"github.com/maratbagautdinov/modbus-firewall/internal/modbus"
	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

// Константы ограничений и таймаутов для прокси.
const (
	maxADULength                   = 260
	eventSaveTimeout               = 2 * time.Second
	modbusExceptionIllegalFunction = 0x01
	defaultHotReloadInterval       = 1 * time.Second
)

// proxyTimeouts хранит заранее распарсенные сетевые таймауты прокси.
type proxyTimeouts struct {
	Dial  time.Duration
	Read  time.Duration
	Write time.Duration
}

// runtimeState — атомарно обновляемое состояние режима и policy matcher.
type runtimeState struct {
	Mode    config.Mode
	Matcher policy.Engine
}

// hotReloadConfig описывает параметры периодического перечитывания config/policy.
type hotReloadConfig struct {
	Enabled    bool
	ConfigPath string
	PolicyPath string
	Interval   time.Duration
}

// fileSignature помогает недорого определять изменения файла по времени/размеру.
type fileSignature struct {
	ModTimeUnixNano int64
	Size            int64
}

// Option — функциональная опция конструктора Service.
type Option func(*Service)

// Service реализует Modbus TCP firewall proxy.
type Service struct {
	cfg        config.Config
	logger     *slog.Logger
	eventStore storage.EventStore

	runtime   atomic.Pointer[runtimeState]
	hotReload hotReloadConfig
}

// New создает и инициализирует сервис прокси.
func New(cfg config.Config, logger *slog.Logger, policyEngine policy.Engine, eventStore storage.EventStore, options ...Option) *Service {
	if logger == nil {
		logger = logging.NewDiscard()
	}

	service := &Service{
		cfg:        cfg,
		logger:     logger,
		eventStore: eventStore,
	}
	service.runtime.Store(&runtimeState{
		Mode:    cfg.Mode,
		Matcher: policyEngine,
	})

	for _, option := range options {
		if option != nil {
			option(service)
		}
	}

	return service
}

// WithHotReload включает периодическое перечитывание config/policy без рестарта сервиса.
func WithHotReload(configPath string, policyPath string, interval time.Duration) Option {
	return func(s *Service) {
		s.hotReload = hotReloadConfig{
			Enabled:    true,
			ConfigPath: configPath,
			PolicyPath: policyPath,
			Interval:   interval,
		}
	}
}

// Run поднимает TCP listener, принимает соединения и запускает обработчики.
func (s *Service) Run(ctx context.Context) error {
	timeouts, err := parseTimeouts(s.cfg.Proxy)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.cfg.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("не удалось запустить listener %q: %w", s.cfg.Server.ListenAddr, err)
	}
	defer listener.Close()

	active := s.currentRuntimeState()
	s.logger.Info(
		"proxy запущен",
		slog.String("mode", string(active.Mode)),
		slog.String("listen_addr", s.cfg.Server.ListenAddr),
		slog.String("upstream_addr", s.cfg.Proxy.UpstreamAddr),
		slog.Duration("dial_timeout", timeouts.Dial),
		slog.Duration("read_timeout", timeouts.Read),
		slog.Duration("write_timeout", timeouts.Write),
	)

	if s.hotReload.Enabled {
		interval := s.hotReload.Interval
		if interval <= 0 {
			interval = defaultHotReloadInterval
		}
		s.logger.Info(
			"hot reload включен",
			slog.String("config_path", s.hotReload.ConfigPath),
			slog.String("policy_path", s.hotReload.PolicyPath),
			slog.Duration("interval", interval),
		)
		go s.runHotReload(ctx)
	}

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		clientConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			s.logger.Error("ошибка accept клиентского соединения", slog.String("error", acceptErr.Error()))
			continue
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			if err := s.handleConnection(ctx, conn, timeouts); err != nil && !isConnectionTermination(err) {
				s.logger.Warn("соединение завершено с ошибкой", slog.String("error", err.Error()))
			}
		}(clientConn)
	}

	wg.Wait()

	s.logger.Info("proxy остановлен", slog.String("reason", contextReason(ctx)))
	return nil
}

// handleConnection проксирует один клиентский TCP поток в upstream PLC.
func (s *Service) handleConnection(ctx context.Context, clientConn net.Conn, timeouts proxyTimeouts) error {
	defer clientConn.Close()

	dialer := &net.Dialer{Timeout: timeouts.Dial}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", s.cfg.Proxy.UpstreamAddr)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к upstream %q: %w", s.cfg.Proxy.UpstreamAddr, err)
	}
	defer upstreamConn.Close()

	s.logger.Debug(
		"установлено соединение",
		slog.String("client", clientConn.RemoteAddr().String()),
		slog.String("upstream", upstreamConn.RemoteAddr().String()),
	)

	clientIP := extractIP(clientConn.RemoteAddr())
	upstreamIP := extractIP(upstreamConn.RemoteAddr())

	for {
		requestADU, err := readModbusADU(clientConn, timeouts.Read)
		if err != nil {
			return err
		}

		active := s.currentRuntimeState()
		parsedRequest, parseErr := modbus.ParseRequest(requestADU)
		if parseErr != nil {
			if active.Mode == config.ModeEnforce {
				s.logger.Warn(
					"запрос заблокирован: ошибка парсинга в enforce режиме",
					slog.String("source_ip", clientIP),
					slog.String("destination_ip", upstreamIP),
					slog.String("error", parseErr.Error()),
				)
				return fmt.Errorf("enforce safe deny: не удалось распарсить запрос: %w", parseErr)
			}
			s.logger.Warn("не удалось распарсить Modbus запрос", slog.String("error", parseErr.Error()))
		} else {
			s.saveParsedEvent(ctx, parsedRequest, clientIP, upstreamIP)
		}

		if active.Mode == config.ModeEnforce {
			if parseErr != nil {
				return fmt.Errorf("enforce safe deny: невалидный Modbus запрос")
			}

			allowed, reason := s.isRequestAllowed(parsedRequest, clientIP, upstreamIP, active.Matcher)
			if !allowed {
				s.logger.Info(
					"запрос заблокирован политикой",
					slog.String("source_ip", clientIP),
					slog.String("destination_ip", upstreamIP),
					slog.Int("unit_id", int(parsedRequest.UnitID)),
					slog.Int("function_code", int(parsedRequest.FunctionCode)),
					slog.Int("start_address", int(parsedRequest.StartAddress)),
					slog.Int("quantity", int(parsedRequest.Quantity)),
					slog.String("reason", reason),
				)

				exceptionResponse := buildExceptionResponse(parsedRequest, modbusExceptionIllegalFunction)
				if err := writeAll(clientConn, exceptionResponse, timeouts.Write); err != nil {
					return fmt.Errorf("не удалось отправить exception ответ клиенту: %w", err)
				}
				continue
			}
		}

		if err := writeAll(upstreamConn, requestADU, timeouts.Write); err != nil {
			return fmt.Errorf("не удалось отправить запрос upstream: %w", err)
		}

		responseADU, err := readModbusADU(upstreamConn, timeouts.Read)
		if err != nil {
			return fmt.Errorf("не удалось прочитать ответ upstream: %w", err)
		}

		if err := writeAll(clientConn, responseADU, timeouts.Write); err != nil {
			return fmt.Errorf("не удалось отправить ответ клиенту: %w", err)
		}
	}
}

// saveParsedEvent сохраняет распарсенное событие в storage и не роняет прокси при ошибке.
func (s *Service) saveParsedEvent(ctx context.Context, parsed modbus.ParsedRequest, sourceIP string, destinationIP string) {
	if s.eventStore == nil {
		return
	}

	event := storage.ModbusEvent{
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		UnitID:        parsed.UnitID,
		FunctionCode:  uint8(parsed.FunctionCode),
		StartAddress:  parsed.StartAddress,
		Quantity:      parsed.Quantity,
		OperationType: operationTypeByFunctionCode(uint8(parsed.FunctionCode)),
	}

	saveCtx, cancel := context.WithTimeout(ctx, eventSaveTimeout)
	defer cancel()

	if _, err := s.eventStore.SaveEvent(saveCtx, event); err != nil {
		s.logger.Warn("не удалось сохранить событие в storage", slog.String("error", err.Error()))
	}
}

// isRequestAllowed проверяет запрос через matcher и формирует reason для логов.
func (s *Service) isRequestAllowed(parsed modbus.ParsedRequest, sourceIP string, destinationIP string, matcher policy.Engine) (bool, string) {
	if matcher == nil {
		return false, "policy matcher не загружен (default deny)"
	}

	decision, err := matcher.Evaluate(policy.MatchRequest{
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		UnitID:        parsed.UnitID,
		FunctionCode:  uint8(parsed.FunctionCode),
		StartAddress:  parsed.StartAddress,
		Quantity:      parsed.Quantity,
	})
	if err != nil {
		return false, fmt.Sprintf("ошибка matcher: %v", err)
	}
	if decision != policy.DecisionAllow {
		return false, "policy decision deny"
	}

	return true, ""
}

// runHotReload периодически проверяет изменения файлов и атомарно подменяет runtimeState.
func (s *Service) runHotReload(ctx context.Context) {
	interval := s.hotReload.Interval
	if interval <= 0 {
		interval = defaultHotReloadInterval
	}

	configSig, err := readFileSignature(s.hotReload.ConfigPath)
	if err != nil {
		s.logger.Warn("не удалось получить сигнатуру config для hot reload", slog.String("error", err.Error()))
	}
	policySig, err := readFileSignature(s.hotReload.PolicyPath)
	if err != nil {
		s.logger.Warn("не удалось получить сигнатуру policy для hot reload", slog.String("error", err.Error()))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newConfigSig, configErr := readFileSignature(s.hotReload.ConfigPath)
			if configErr != nil {
				s.logger.Warn("hot reload: ошибка чтения config", slog.String("error", configErr.Error()))
				continue
			}

			newPolicySig, policyErr := readFileSignature(s.hotReload.PolicyPath)
			if policyErr != nil {
				s.logger.Warn("hot reload: ошибка чтения policy", slog.String("error", policyErr.Error()))
				continue
			}

			if newConfigSig == configSig && newPolicySig == policySig {
				continue
			}

			previous, next, reloadErr := s.reloadRuntimeState()
			if reloadErr != nil {
				s.logger.Warn("hot reload: не удалось применить новую конфигурацию", slog.String("error", reloadErr.Error()))
				configSig = newConfigSig
				policySig = newPolicySig
				continue
			}

			configSig = newConfigSig
			policySig = newPolicySig
			s.logger.Info(
				"hot reload успешно применен",
				slog.String("previous_mode", string(previous.Mode)),
				slog.String("new_mode", string(next.Mode)),
			)
		}
	}
}

// reloadRuntimeState перечитывает config/policy и публикует новое состояние через atomic pointer.
func (s *Service) reloadRuntimeState() (runtimeState, runtimeState, error) {
	if !s.hotReload.Enabled {
		current := s.currentRuntimeState()
		return current, current, nil
	}

	loadedConfig, err := config.Load(s.hotReload.ConfigPath)
	if err != nil {
		return runtimeState{}, runtimeState{}, fmt.Errorf("не удалось загрузить config: %w", err)
	}

	next := runtimeState{Mode: loadedConfig.Mode}
	if loadedConfig.Mode == config.ModeEnforce {
		policyCfg, policyErr := policy.Load(s.hotReload.PolicyPath)
		if policyErr != nil {
			return runtimeState{}, runtimeState{}, fmt.Errorf("не удалось загрузить policy для enforce: %w", policyErr)
		}

		matcher, matcherErr := policy.NewMatcher(policyCfg)
		if matcherErr != nil {
			return runtimeState{}, runtimeState{}, fmt.Errorf("не удалось создать matcher: %w", matcherErr)
		}
		next.Matcher = matcher
	}

	previous := s.currentRuntimeState()
	s.runtime.Store(&next)
	return previous, next, nil
}

// currentRuntimeState читает актуальное состояние без блокировок.
func (s *Service) currentRuntimeState() runtimeState {
	state := s.runtime.Load()
	if state == nil {
		return runtimeState{Mode: s.cfg.Mode}
	}
	return *state
}

// readFileSignature возвращает сигнатуру файла для сравнения изменений.
func readFileSignature(path string) (fileSignature, error) {
	if path == "" {
		return fileSignature{}, fmt.Errorf("путь к файлу не задан")
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileSignature{}, nil
		}
		return fileSignature{}, err
	}

	return fileSignature{ModTimeUnixNano: info.ModTime().UnixNano(), Size: info.Size()}, nil
}

// parseTimeouts валидирует и преобразует строковые таймауты из конфига.
func parseTimeouts(cfg config.ProxyConfig) (proxyTimeouts, error) {
	dialTimeout, err := time.ParseDuration(cfg.DialTimeout)
	if err != nil {
		return proxyTimeouts{}, fmt.Errorf("proxy.dial_timeout: %w", err)
	}
	if dialTimeout <= 0 {
		return proxyTimeouts{}, fmt.Errorf("proxy.dial_timeout должен быть > 0")
	}

	readTimeout, err := time.ParseDuration(cfg.ReadTimeout)
	if err != nil {
		return proxyTimeouts{}, fmt.Errorf("proxy.read_timeout: %w", err)
	}
	if readTimeout <= 0 {
		return proxyTimeouts{}, fmt.Errorf("proxy.read_timeout должен быть > 0")
	}

	writeTimeout, err := time.ParseDuration(cfg.WriteTimeout)
	if err != nil {
		return proxyTimeouts{}, fmt.Errorf("proxy.write_timeout: %w", err)
	}
	if writeTimeout <= 0 {
		return proxyTimeouts{}, fmt.Errorf("proxy.write_timeout должен быть > 0")
	}

	return proxyTimeouts{Dial: dialTimeout, Read: readTimeout, Write: writeTimeout}, nil
}

// readModbusADU читает полный ADU кадр, начиная с MBAP заголовка.
func readModbusADU(conn net.Conn, readTimeout time.Duration) ([]byte, error) {
	if err := setReadDeadline(conn, readTimeout); err != nil {
		return nil, err
	}

	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[4:6])
	if length < 2 {
		return nil, fmt.Errorf("некорректный MBAP length=%d, должно быть >= 2", length)
	}

	totalLength := int(length) + len(header)
	if totalLength > maxADULength {
		return nil, fmt.Errorf("слишком большой ADU: %d байт", totalLength)
	}

	rest := make([]byte, length)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}

	adu := make([]byte, totalLength)
	copy(adu[:6], header)
	copy(adu[6:], rest)
	return adu, nil
}

// writeAll гарантирует запись всего буфера в сокет.
func writeAll(conn net.Conn, payload []byte, writeTimeout time.Duration) error {
	if err := setWriteDeadline(conn, writeTimeout); err != nil {
		return err
	}

	written := 0
	for written < len(payload) {
		n, err := conn.Write(payload[written:])
		if err != nil {
			return err
		}
		written += n
	}

	return nil
}

// setReadDeadline задает read deadline, если таймаут положительный.
func setReadDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("не удалось установить read deadline: %w", err)
	}
	return nil
}

// setWriteDeadline задает write deadline, если таймаут положительный.
func setWriteDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("не удалось установить write deadline: %w", err)
	}
	return nil
}

// contextReason формирует причину штатной остановки прокси для логов.
func contextReason(ctx context.Context) string {
	if ctx == nil {
		return "неизвестно"
	}
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return "listener закрыт"
}

// isConnectionTermination определяет ожидаемое завершение соединения.
func isConnectionTermination(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// extractIP извлекает IP из net.Addr в нормализованном виде.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}

	return addr.String()
}

// operationTypeByFunctionCode сопоставляет FC с типом read/write для хранения событий.
func operationTypeByFunctionCode(fc uint8) storage.OperationType {
	switch fc {
	case 1, 2, 3, 4:
		return storage.OperationTypeRead
	case 5, 6, 15, 16:
		return storage.OperationTypeWrite
	default:
		return storage.OperationTypeUnknown
	}
}

// buildExceptionResponse формирует Modbus exception-ответ для заблокированного запроса.
func buildExceptionResponse(request modbus.ParsedRequest, exceptionCode uint8) []byte {
	response := make([]byte, 9)
	binary.BigEndian.PutUint16(response[0:2], request.TransactionID)
	binary.BigEndian.PutUint16(response[2:4], request.ProtocolID)
	binary.BigEndian.PutUint16(response[4:6], 0x0003)
	response[6] = request.UnitID
	response[7] = uint8(request.FunctionCode) | 0x80
	response[8] = exceptionCode
	return response
}
