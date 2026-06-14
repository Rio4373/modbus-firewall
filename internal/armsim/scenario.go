package armsim

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Scenario — имя тестового сценария поведения ARM-клиента.
type Scenario string

const (
	ScenarioNormalRead     Scenario = "normal-read"
	ScenarioRepeatedWrite  Scenario = "repeated-write"
	ScenarioRareWrite      Scenario = "rare-write"
	ScenarioForbiddenWrite Scenario = "forbidden-write"
)

// Operation описывает одну Modbus-операцию в рамках сценария.
type Operation struct {
	Name         string
	FunctionCode uint8
	StartAddress uint16
	Quantity     uint16
	Registers    []uint16
	ADU          []byte
}

// ParseScenario валидирует имя сценария, переданное через CLI.
func ParseScenario(value string) (Scenario, error) {
	switch Scenario(strings.ToLower(strings.TrimSpace(value))) {
	case ScenarioNormalRead:
		return ScenarioNormalRead, nil
	case ScenarioRepeatedWrite:
		return ScenarioRepeatedWrite, nil
	case ScenarioRareWrite:
		return ScenarioRareWrite, nil
	case ScenarioForbiddenWrite:
		return ScenarioForbiddenWrite, nil
	default:
		return "", fmt.Errorf("неподдерживаемый сценарий %q", value)
	}
}

// ListScenarios возвращает все поддерживаемые сценарии для help/вывода.
func ListScenarios() []Scenario {
	return []Scenario{
		ScenarioNormalRead,
		ScenarioRepeatedWrite,
		ScenarioRareWrite,
		ScenarioForbiddenWrite,
	}
}

// BuildScenarioOperations формирует список запросов для выбранного сценария.
func BuildScenarioOperations(scenario Scenario, unitID uint8, repeat int) ([]Operation, error) {
	if unitID == 0 {
		return nil, fmt.Errorf("unit-id должен быть > 0")
	}

	switch scenario {
	case ScenarioNormalRead:
		return buildNormalReadOperations(unitID), nil
	case ScenarioRepeatedWrite:
		if repeat <= 0 {
			return nil, fmt.Errorf("repeat должен быть > 0 для repeated-write")
		}
		return buildRepeatedWriteOperations(unitID, repeat), nil
	case ScenarioRareWrite:
		return buildRareWriteOperations(unitID), nil
	case ScenarioForbiddenWrite:
		return buildForbiddenWriteOperations(unitID), nil
	default:
		return nil, fmt.Errorf("неподдерживаемый сценарий %q", scenario)
	}
}

// buildNormalReadOperations формирует типовой читающий трафик (FC03).
func buildNormalReadOperations(unitID uint8) []Operation {
	return []Operation{
		newReadHoldingOp(1, unitID, "normal-read-1", 0, 2),
		newReadHoldingOp(2, unitID, "normal-read-2", 10, 2),
		newReadHoldingOp(3, unitID, "normal-read-3", 20, 2),
	}
}

// buildRepeatedWriteOperations формирует повторяющиеся записи в один адрес (FC06).
func buildRepeatedWriteOperations(unitID uint8, repeat int) []Operation {
	ops := make([]Operation, 0, repeat)
	for i := 0; i < repeat; i++ {
		txID := uint16(i + 1)
		ops = append(ops, newWriteSingleRegisterOp(txID, unitID, fmt.Sprintf("repeated-write-%d", i+1), 12, 1234))
	}
	return ops
}

// buildRareWriteOperations формирует редкую запись пачки регистров (FC16).
func buildRareWriteOperations(unitID uint8) []Operation {
	return []Operation{
		newWriteMultipleRegistersOp(1, unitID, "rare-write-1", 80, []uint16{777, 888}),
	}
}

// buildForbiddenWriteOperations формирует запись в адрес, который обычно не разрешен policy.
func buildForbiddenWriteOperations(unitID uint8) []Operation {
	return []Operation{
		newWriteSingleRegisterOp(1, unitID, "forbidden-write-1", 50, 9999),
	}
}

// newReadHoldingOp собирает ADU для FC03 (Read Holding Registers).
func newReadHoldingOp(txID uint16, unitID uint8, name string, startAddress uint16, quantity uint16) Operation {
	adu := make([]byte, 12)
	binary.BigEndian.PutUint16(adu[0:2], txID)
	binary.BigEndian.PutUint16(adu[2:4], 0x0000)
	binary.BigEndian.PutUint16(adu[4:6], 0x0006)
	adu[6] = unitID
	adu[7] = 0x03
	binary.BigEndian.PutUint16(adu[8:10], startAddress)
	binary.BigEndian.PutUint16(adu[10:12], quantity)

	return Operation{
		Name:         name,
		FunctionCode: 0x03,
		StartAddress: startAddress,
		Quantity:     quantity,
		ADU:          adu,
	}
}

// newWriteSingleRegisterOp собирает ADU для FC06 (Write Single Register).
func newWriteSingleRegisterOp(txID uint16, unitID uint8, name string, address uint16, value uint16) Operation {
	adu := make([]byte, 12)
	binary.BigEndian.PutUint16(adu[0:2], txID)
	binary.BigEndian.PutUint16(adu[2:4], 0x0000)
	binary.BigEndian.PutUint16(adu[4:6], 0x0006)
	adu[6] = unitID
	adu[7] = 0x06
	binary.BigEndian.PutUint16(adu[8:10], address)
	binary.BigEndian.PutUint16(adu[10:12], value)

	return Operation{
		Name:         name,
		FunctionCode: 0x06,
		StartAddress: address,
		Quantity:     1,
		Registers:    []uint16{value},
		ADU:          adu,
	}
}

// newWriteMultipleRegistersOp собирает ADU для FC16 (Write Multiple Registers).
func newWriteMultipleRegistersOp(txID uint16, unitID uint8, name string, startAddress uint16, values []uint16) Operation {
	quantity := uint16(len(values))
	byteCount := len(values) * 2

	pduLength := 6 + byteCount
	adu := make([]byte, 7+pduLength)
	binary.BigEndian.PutUint16(adu[0:2], txID)
	binary.BigEndian.PutUint16(adu[2:4], 0x0000)
	binary.BigEndian.PutUint16(adu[4:6], uint16(1+pduLength))
	adu[6] = unitID
	adu[7] = 0x10
	binary.BigEndian.PutUint16(adu[8:10], startAddress)
	binary.BigEndian.PutUint16(adu[10:12], quantity)
	adu[12] = uint8(byteCount)
	offset := 13
	for _, value := range values {
		binary.BigEndian.PutUint16(adu[offset:offset+2], value)
		offset += 2
	}

	registers := make([]uint16, len(values))
	copy(registers, values)

	return Operation{
		Name:         name,
		FunctionCode: 0x10,
		StartAddress: startAddress,
		Quantity:     quantity,
		Registers:    registers,
		ADU:          adu,
	}
}
