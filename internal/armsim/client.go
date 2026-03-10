package armsim

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// maxADULength ограничивает размер одного Modbus TCP кадра для MVP.
const maxADULength = 260

// Client — минимальный Modbus TCP клиент для сценарного прогона через firewall.
type Client struct {
	target  string
	timeout time.Duration
}

// Response содержит распарсенный ответ Modbus TCP.
type Response struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
	FunctionCode  uint8
	Data          []byte
	Raw           []byte
}

// OperationResult описывает результат выполнения одной операции сценария.
type OperationResult struct {
	Operation Operation
	Response  Response
	Duration  time.Duration
	Err       error
}

// NewClient валидирует параметры подключения и создает клиент.
func NewClient(target string, timeout time.Duration) (*Client, error) {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("некорректный target %q: %w", target, err)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout должен быть > 0")
	}

	return &Client{
		target:  target,
		timeout: timeout,
	}, nil
}

// ExecuteScenario последовательно выполняет список операций в одном TCP-соединении.
func (c *Client) ExecuteScenario(ctx context.Context, operations []Operation) ([]OperationResult, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("список операций пуст")
	}

	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.target)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к %s: %w", c.target, err)
	}
	defer conn.Close()

	results := make([]OperationResult, 0, len(operations))
	for i, op := range operations {
		select {
		case <-ctx.Done():
			return results, fmt.Errorf("сценарий прерван: %w", ctx.Err())
		default:
		}

		start := time.Now()

		if err := writeADU(conn, op.ADU, c.timeout); err != nil {
			result := OperationResult{
				Operation: op,
				Duration:  time.Since(start),
				Err:       fmt.Errorf("операция %q: ошибка отправки запроса: %w", op.Name, err),
			}
			results = append(results, result)
			return results, fmt.Errorf("ошибка на операции %d: %w", i+1, result.Err)
		}

		responseADU, err := readADU(conn, c.timeout)
		if err != nil {
			result := OperationResult{
				Operation: op,
				Duration:  time.Since(start),
				Err:       fmt.Errorf("операция %q: ошибка чтения ответа: %w", op.Name, err),
			}
			results = append(results, result)
			return results, fmt.Errorf("ошибка на операции %d: %w", i+1, result.Err)
		}

		parsedResponse, err := parseResponse(responseADU)
		if err != nil {
			result := OperationResult{
				Operation: op,
				Duration:  time.Since(start),
				Err:       fmt.Errorf("операция %q: не удалось распарсить ответ: %w", op.Name, err),
			}
			results = append(results, result)
			return results, fmt.Errorf("ошибка на операции %d: %w", i+1, result.Err)
		}

		results = append(results, OperationResult{
			Operation: op,
			Response:  parsedResponse,
			Duration:  time.Since(start),
		})
	}

	return results, nil
}

// IsException возвращает true, если ответ содержит Modbus exception (FC | 0x80).
func (r Response) IsException() bool {
	return r.FunctionCode&0x80 != 0
}

// ExceptionCode возвращает код исключения для exception-ответов.
func (r Response) ExceptionCode() uint8 {
	if !r.IsException() || len(r.Data) == 0 {
		return 0
	}
	return r.Data[0]
}

// writeADU надежно отправляет весь буфер ADU в соединение.
func writeADU(conn net.Conn, adu []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("не удалось установить write deadline: %w", err)
	}

	written := 0
	for written < len(adu) {
		n, err := conn.Write(adu[written:])
		if err != nil {
			return err
		}
		written += n
	}

	return nil
}

// readADU читает MBAP заголовок и полезную нагрузку ответа.
func readADU(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("не удалось установить read deadline: %w", err)
	}

	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[4:6])
	if length < 2 {
		return nil, fmt.Errorf("некорректный MBAP length=%d", length)
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

// parseResponse выполняет базовую валидацию ответа Modbus TCP.
func parseResponse(adu []byte) (Response, error) {
	if len(adu) < 8 {
		return Response{}, fmt.Errorf("ответ короче минимального ADU")
	}

	transactionID := binary.BigEndian.Uint16(adu[0:2])
	protocolID := binary.BigEndian.Uint16(adu[2:4])
	length := binary.BigEndian.Uint16(adu[4:6])
	unitID := adu[6]
	functionCode := adu[7]
	data := append([]byte(nil), adu[8:]...)

	if protocolID != 0 {
		return Response{}, fmt.Errorf("protocol id должен быть 0, получено %d", protocolID)
	}

	expectedLength := int(length) + 6
	if len(adu) != expectedLength {
		return Response{}, fmt.Errorf("несовпадение длины ответа: mbap=%d adu=%d", expectedLength, len(adu))
	}

	return Response{
		TransactionID: transactionID,
		ProtocolID:    protocolID,
		Length:        length,
		UnitID:        unitID,
		FunctionCode:  functionCode,
		Data:          data,
		Raw:           append([]byte(nil), adu...),
	}, nil
}
