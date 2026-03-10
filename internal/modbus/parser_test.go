package modbus

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRequestSupportedFunctionCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		adu              []byte
		expectedTxID     uint16
		expectedUnitID   uint8
		expectedFC       FunctionCode
		expectedStart    uint16
		expectedQuantity uint16
		expectedCoils    []bool
		expectedRegs     []uint16
	}{
		{
			name:             "FC01 Read Coils",
			adu:              buildADU(1, 1, FunctionCodeReadCoils, []byte{0x00, 0x13, 0x00, 0x25}),
			expectedTxID:     1,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeReadCoils,
			expectedStart:    0x0013,
			expectedQuantity: 0x0025,
		},
		{
			name:             "FC02 Read Discrete Inputs",
			adu:              buildADU(2, 1, FunctionCodeReadDiscreteInputs, []byte{0x00, 0x10, 0x00, 0x08}),
			expectedTxID:     2,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeReadDiscreteInputs,
			expectedStart:    0x0010,
			expectedQuantity: 0x0008,
		},
		{
			name:             "FC03 Read Holding Registers",
			adu:              buildADU(3, 1, FunctionCodeReadHoldingRegisters, []byte{0x00, 0x6B, 0x00, 0x03}),
			expectedTxID:     3,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeReadHoldingRegisters,
			expectedStart:    0x006B,
			expectedQuantity: 0x0003,
		},
		{
			name:             "FC04 Read Input Registers",
			adu:              buildADU(4, 1, FunctionCodeReadInputRegisters, []byte{0x00, 0x08, 0x00, 0x01}),
			expectedTxID:     4,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeReadInputRegisters,
			expectedStart:    0x0008,
			expectedQuantity: 0x0001,
		},
		{
			name:             "FC05 Write Single Coil",
			adu:              buildADU(5, 1, FunctionCodeWriteSingleCoil, []byte{0x00, 0xAC, 0xFF, 0x00}),
			expectedTxID:     5,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeWriteSingleCoil,
			expectedStart:    0x00AC,
			expectedQuantity: 1,
			expectedCoils:    []bool{true},
		},
		{
			name:             "FC06 Write Single Register",
			adu:              buildADU(6, 1, FunctionCodeWriteSingleRegister, []byte{0x00, 0x01, 0x00, 0x03}),
			expectedTxID:     6,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeWriteSingleRegister,
			expectedStart:    0x0001,
			expectedQuantity: 1,
			expectedRegs:     []uint16{0x0003},
		},
		{
			name:             "FC15 Write Multiple Coils",
			adu:              buildADU(7, 1, FunctionCodeWriteMultipleCoils, []byte{0x00, 0x13, 0x00, 0x0A, 0x02, 0x4D, 0x01}),
			expectedTxID:     7,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeWriteMultipleCoils,
			expectedStart:    0x0013,
			expectedQuantity: 10,
			expectedCoils:    []bool{true, false, true, true, false, false, true, false, true, false},
		},
		{
			name:             "FC16 Write Multiple Registers",
			adu:              buildADU(8, 1, FunctionCodeWriteMultipleRegs, []byte{0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02}),
			expectedTxID:     8,
			expectedUnitID:   1,
			expectedFC:       FunctionCodeWriteMultipleRegs,
			expectedStart:    0x0001,
			expectedQuantity: 2,
			expectedRegs:     []uint16{0x000A, 0x0102},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseRequest(tt.adu)
			if err != nil {
				t.Fatalf("ожидали успешный парсинг, получили ошибку: %v", err)
			}

			if parsed.TransactionID != tt.expectedTxID {
				t.Fatalf("transaction id: ожидали %d, получили %d", tt.expectedTxID, parsed.TransactionID)
			}
			if parsed.ProtocolID != 0 {
				t.Fatalf("protocol id: ожидали 0, получили %d", parsed.ProtocolID)
			}
			expectedLength := uint16(len(tt.adu) - 6)
			if parsed.Length != expectedLength {
				t.Fatalf("length: ожидали %d, получили %d", expectedLength, parsed.Length)
			}
			if parsed.UnitID != tt.expectedUnitID {
				t.Fatalf("unit id: ожидали %d, получили %d", tt.expectedUnitID, parsed.UnitID)
			}
			if parsed.FunctionCode != tt.expectedFC {
				t.Fatalf("function code: ожидали %v, получили %v", tt.expectedFC, parsed.FunctionCode)
			}
			if parsed.StartAddress != tt.expectedStart {
				t.Fatalf("start address: ожидали %d, получили %d", tt.expectedStart, parsed.StartAddress)
			}
			if parsed.Quantity != tt.expectedQuantity {
				t.Fatalf("quantity: ожидали %d, получили %d", tt.expectedQuantity, parsed.Quantity)
			}
			if !reflect.DeepEqual(parsed.CoilValues, tt.expectedCoils) {
				t.Fatalf("coil values: ожидали %v, получили %v", tt.expectedCoils, parsed.CoilValues)
			}
			if !reflect.DeepEqual(parsed.RegisterValues, tt.expectedRegs) {
				t.Fatalf("register values: ожидали %v, получили %v", tt.expectedRegs, parsed.RegisterValues)
			}
		})
	}
}

func TestParseRequestInvalidPackets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		adu          []byte
		errorContain string
	}{
		{
			name:         "too short",
			adu:          []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06},
			errorContain: "пакет короче MBAP",
		},
		{
			name:         "protocol id is not zero",
			adu:          []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01},
			errorContain: "protocol_id",
		},
		{
			name:         "length mismatch",
			adu:          []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00},
			errorContain: "несовпадение длины",
		},
		{
			name:         "unsupported function code",
			adu:          buildADU(1, 1, 0x11, []byte{0x00, 0x01, 0x00, 0x01}),
			errorContain: "неподдерживаемый FC",
		},
		{
			name:         "fc05 invalid coil value",
			adu:          buildADU(1, 1, FunctionCodeWriteSingleCoil, []byte{0x00, 0x01, 0x12, 0x34}),
			errorContain: "coil_value",
		},
		{
			name:         "fc16 invalid byte count",
			adu:          buildADU(1, 1, FunctionCodeWriteMultipleRegs, []byte{0x00, 0x01, 0x00, 0x02, 0x03, 0x00, 0x0A, 0x01}),
			errorContain: "byte_count",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseRequest(tt.adu)
			if err == nil {
				t.Fatal("ожидали ошибку, получили nil")
			}
			if !strings.Contains(err.Error(), tt.errorContain) {
				t.Fatalf("ожидали подстроку %q в ошибке, получили: %v", tt.errorContain, err)
			}
		})
	}
}

func buildADU(transactionID uint16, unitID uint8, fc FunctionCode, payload []byte) []byte {
	pdu := append([]byte{byte(fc)}, payload...)
	length := uint16(1 + len(pdu))
	adu := make([]byte, 7+len(pdu))

	adu[0] = byte(transactionID >> 8)
	adu[1] = byte(transactionID)
	adu[2] = 0x00
	adu[3] = 0x00
	adu[4] = byte(length >> 8)
	adu[5] = byte(length)
	adu[6] = unitID
	copy(adu[7:], pdu)

	return adu
}
