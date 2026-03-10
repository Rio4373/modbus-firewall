package modbus

import (
	"encoding/binary"
	"fmt"
)

// FunctionCode представляет поддерживаемые коды Modbus функций.
type FunctionCode uint8

const (
	FunctionCodeReadCoils            FunctionCode = 0x01
	FunctionCodeReadDiscreteInputs   FunctionCode = 0x02
	FunctionCodeReadHoldingRegisters FunctionCode = 0x03
	FunctionCodeReadInputRegisters   FunctionCode = 0x04
	FunctionCodeWriteSingleCoil      FunctionCode = 0x05
	FunctionCodeWriteSingleRegister  FunctionCode = 0x06
	FunctionCodeWriteMultipleCoils   FunctionCode = 0x0F
	FunctionCodeWriteMultipleRegs    FunctionCode = 0x10
)

// ParsedRequest содержит нормализованный результат парсинга Modbus TCP запроса.
type ParsedRequest struct {
	TransactionID  uint16
	ProtocolID     uint16
	Length         uint16
	UnitID         uint8
	FunctionCode   FunctionCode
	StartAddress   uint16
	Quantity       uint16
	CoilValues     []bool
	RegisterValues []uint16
	RawData        []byte
}

// ParseError возвращается при валидации/парсинге некорректного пакета.
type ParseError struct {
	Field  string
	Reason string
}

// Error возвращает человекочитаемое описание ошибки парсинга.
func (e ParseError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

// ParseRequest парсит ADU Modbus TCP и извлекает поля запроса для поддерживаемых FC.
func ParseRequest(adu []byte) (ParsedRequest, error) {
	if len(adu) < 7 {
		return ParsedRequest{}, ParseError{Field: "adu", Reason: "пакет короче MBAP заголовка (7 байт)"}
	}

	transactionID := binary.BigEndian.Uint16(adu[0:2])
	protocolID := binary.BigEndian.Uint16(adu[2:4])
	length := binary.BigEndian.Uint16(adu[4:6])
	unitID := adu[6]

	if protocolID != 0 {
		return ParsedRequest{}, ParseError{Field: "protocol_id", Reason: fmt.Sprintf("ожидался 0, получено %d", protocolID)}
	}

	expectedADULength := int(length) + 6
	if len(adu) != expectedADULength {
		return ParsedRequest{}, ParseError{
			Field:  "length",
			Reason: fmt.Sprintf("несовпадение длины: в MBAP=%d (ожидается ADU=%d), фактически=%d", length, expectedADULength, len(adu)),
		}
	}

	if length < 2 {
		return ParsedRequest{}, ParseError{Field: "length", Reason: "должна включать минимум unit_id и function_code"}
	}

	if len(adu) < 8 {
		return ParsedRequest{}, ParseError{Field: "pdu", Reason: "отсутствует function code"}
	}

	pdu := adu[7:]
	request := ParsedRequest{
		TransactionID: transactionID,
		ProtocolID:    protocolID,
		Length:        length,
		UnitID:        unitID,
		FunctionCode:  FunctionCode(pdu[0]),
		RawData:       append([]byte(nil), pdu...),
	}

	switch request.FunctionCode {
	case FunctionCodeReadCoils,
		FunctionCodeReadDiscreteInputs,
		FunctionCodeReadHoldingRegisters,
		FunctionCodeReadInputRegisters:
		if err := parseReadRequest(pdu, &request); err != nil {
			return ParsedRequest{}, err
		}
	case FunctionCodeWriteSingleCoil:
		if err := parseWriteSingleCoilRequest(pdu, &request); err != nil {
			return ParsedRequest{}, err
		}
	case FunctionCodeWriteSingleRegister:
		if err := parseWriteSingleRegisterRequest(pdu, &request); err != nil {
			return ParsedRequest{}, err
		}
	case FunctionCodeWriteMultipleCoils:
		if err := parseWriteMultipleCoilsRequest(pdu, &request); err != nil {
			return ParsedRequest{}, err
		}
	case FunctionCodeWriteMultipleRegs:
		if err := parseWriteMultipleRegistersRequest(pdu, &request); err != nil {
			return ParsedRequest{}, err
		}
	default:
		return ParsedRequest{}, ParseError{Field: "function_code", Reason: fmt.Sprintf("неподдерживаемый FC 0x%02X", uint8(request.FunctionCode))}
	}

	return request, nil
}

// parseReadRequest обрабатывает FC 01/02/03/04.
func parseReadRequest(pdu []byte, request *ParsedRequest) error {
	if len(pdu) != 5 {
		return ParseError{Field: "pdu", Reason: fmt.Sprintf("для read-команды ожидается 5 байт, получено %d", len(pdu))}
	}

	request.StartAddress = binary.BigEndian.Uint16(pdu[1:3])
	request.Quantity = binary.BigEndian.Uint16(pdu[3:5])
	if request.Quantity == 0 {
		return ParseError{Field: "quantity", Reason: "должно быть > 0"}
	}

	return nil
}

// parseWriteSingleCoilRequest обрабатывает FC 05.
func parseWriteSingleCoilRequest(pdu []byte, request *ParsedRequest) error {
	if len(pdu) != 5 {
		return ParseError{Field: "pdu", Reason: fmt.Sprintf("для FC05 ожидается 5 байт, получено %d", len(pdu))}
	}

	request.StartAddress = binary.BigEndian.Uint16(pdu[1:3])
	request.Quantity = 1

	value := binary.BigEndian.Uint16(pdu[3:5])
	switch value {
	case 0x0000:
		request.CoilValues = []bool{false}
	case 0xFF00:
		request.CoilValues = []bool{true}
	default:
		return ParseError{Field: "coil_value", Reason: fmt.Sprintf("для FC05 поддерживаются только 0x0000 и 0xFF00, получено 0x%04X", value)}
	}

	return nil
}

// parseWriteSingleRegisterRequest обрабатывает FC 06.
func parseWriteSingleRegisterRequest(pdu []byte, request *ParsedRequest) error {
	if len(pdu) != 5 {
		return ParseError{Field: "pdu", Reason: fmt.Sprintf("для FC06 ожидается 5 байт, получено %d", len(pdu))}
	}

	request.StartAddress = binary.BigEndian.Uint16(pdu[1:3])
	request.Quantity = 1
	request.RegisterValues = []uint16{binary.BigEndian.Uint16(pdu[3:5])}
	return nil
}

// parseWriteMultipleCoilsRequest обрабатывает FC 15.
func parseWriteMultipleCoilsRequest(pdu []byte, request *ParsedRequest) error {
	if len(pdu) < 6 {
		return ParseError{Field: "pdu", Reason: fmt.Sprintf("для FC15 ожидается минимум 6 байт, получено %d", len(pdu))}
	}

	request.StartAddress = binary.BigEndian.Uint16(pdu[1:3])
	request.Quantity = binary.BigEndian.Uint16(pdu[3:5])
	if request.Quantity == 0 {
		return ParseError{Field: "quantity", Reason: "должно быть > 0"}
	}

	byteCount := int(pdu[5])
	if len(pdu) != 6+byteCount {
		return ParseError{Field: "byte_count", Reason: fmt.Sprintf("для FC15 byte_count=%d, но фактическая длина data=%d", byteCount, len(pdu)-6)}
	}

	expectedByteCount := int((request.Quantity + 7) / 8)
	if byteCount != expectedByteCount {
		return ParseError{Field: "byte_count", Reason: fmt.Sprintf("для FC15 ожидалось %d байт данных, получено %d", expectedByteCount, byteCount)}
	}

	request.CoilValues = parseCoilValues(pdu[6:], request.Quantity)
	return nil
}

// parseWriteMultipleRegistersRequest обрабатывает FC 16.
func parseWriteMultipleRegistersRequest(pdu []byte, request *ParsedRequest) error {
	if len(pdu) < 6 {
		return ParseError{Field: "pdu", Reason: fmt.Sprintf("для FC16 ожидается минимум 6 байт, получено %d", len(pdu))}
	}

	request.StartAddress = binary.BigEndian.Uint16(pdu[1:3])
	request.Quantity = binary.BigEndian.Uint16(pdu[3:5])
	if request.Quantity == 0 {
		return ParseError{Field: "quantity", Reason: "должно быть > 0"}
	}

	byteCount := int(pdu[5])
	if len(pdu) != 6+byteCount {
		return ParseError{Field: "byte_count", Reason: fmt.Sprintf("для FC16 byte_count=%d, но фактическая длина data=%d", byteCount, len(pdu)-6)}
	}

	expectedByteCount := int(request.Quantity) * 2
	if byteCount != expectedByteCount {
		return ParseError{Field: "byte_count", Reason: fmt.Sprintf("для FC16 ожидалось %d байт данных, получено %d", expectedByteCount, byteCount)}
	}

	request.RegisterValues = make([]uint16, 0, request.Quantity)
	for i := 0; i < byteCount; i += 2 {
		request.RegisterValues = append(request.RegisterValues, binary.BigEndian.Uint16(pdu[6+i:8+i]))
	}

	return nil
}

// parseCoilValues разворачивает битовую упаковку значений coil в срез bool.
func parseCoilValues(data []byte, quantity uint16) []bool {
	values := make([]bool, 0, quantity)
	for i := uint16(0); i < quantity; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		bit := (data[byteIndex] >> bitIndex) & 0x01
		values = append(values, bit == 1)
	}
	return values
}
