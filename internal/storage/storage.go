package storage

import (
	"context"
	"time"
)

// OperationType классифицирует Modbus событие как read/write/unknown.
type OperationType string

const (
	OperationTypeRead    OperationType = "read"
	OperationTypeWrite   OperationType = "write"
	OperationTypeUnknown OperationType = "unknown"
)

// ModbusEvent — нормализованная запись события для хранения в БД.
type ModbusEvent struct {
	ID            int64
	Timestamp     time.Time
	SourceIP      string
	DestinationIP string
	UnitID        uint8
	FunctionCode  uint8
	StartAddress  uint16
	Quantity      uint16
	OperationType OperationType
}

// EventListFilter определяет фильтрацию и пагинацию при чтении событий.
type EventListFilter struct {
	From          *time.Time
	To            *time.Time
	FunctionCode  *uint8
	OperationType OperationType
	Limit         int
	Offset        int
}

// PolicyCandidate — агрегированная запись для генерации policy.
type PolicyCandidate struct {
	SourceIP      string
	DestinationIP string
	UnitID        uint8
	FunctionCode  uint8
	StartAddress  uint16
	Quantity      uint16
	OperationType OperationType
	Hits          int64
	FirstSeen     time.Time
	LastSeen      time.Time
}

// EventStore описывает минимальный контракт слоя хранения событий.
type EventStore interface {
	SaveEvent(ctx context.Context, event ModbusEvent) (int64, error)
	ListEvents(ctx context.Context, filter EventListFilter) ([]ModbusEvent, error)
	ListEventsForReplay(ctx context.Context, limit int) ([]ModbusEvent, error)
	ListPolicyCandidates(ctx context.Context, limit int) ([]PolicyCandidate, error)
	Close() error
}
