package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Значения по умолчанию для методов выборки.
const (
	defaultListLimit   = 100
	defaultReplayLimit = 200
	defaultPolicyLimit = 200
)

// schemaSQL инициализирует таблицу и индексы для событий Modbus.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS modbus_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    unit_id INTEGER NOT NULL CHECK (unit_id BETWEEN 0 AND 255),
    function_code INTEGER NOT NULL CHECK (function_code BETWEEN 0 AND 255),
    start_address INTEGER NOT NULL CHECK (start_address BETWEEN 0 AND 65535),
    quantity INTEGER NOT NULL CHECK (quantity BETWEEN 0 AND 65535),
    operation_type TEXT NOT NULL CHECK (operation_type IN ('read', 'write', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_modbus_events_timestamp ON modbus_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_modbus_events_function_code ON modbus_events(function_code);
CREATE INDEX IF NOT EXISTS idx_modbus_events_operation_type ON modbus_events(operation_type);
`

// SQLiteStore — реализация EventStore поверх SQLite без ORM.
type SQLiteStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewSQLiteStore открывает RW-подключение, создает схему и возвращает store.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("путь к sqlite базе обязателен")
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("не удалось создать директорию для sqlite %q: %w", dir, err)
		}
	}

	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", path)
	db, err := openSQLite(dsn)
	if err != nil {
		return nil, err
	}

	store := &SQLiteStore{
		db:  db,
		now: func() time.Time { return time.Now().UTC() },
	}

	if err := store.initSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

// NewSQLiteReadOnlyStore открывает SQLite в режиме read-only для replay.
func NewSQLiteReadOnlyStore(path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("путь к sqlite базе обязателен")
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&_busy_timeout=5000", path)
	db, err := openSQLite(dsn)
	if err != nil {
		return nil, err
	}

	return &SQLiteStore{
		db:  db,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// openSQLite настраивает базовые параметры пула и проверяет доступность БД.
func openSQLite(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("не удалось подключиться к sqlite: %w", err)
	}

	return db, nil
}

// Close закрывает подключение к БД.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveEvent валидирует и сохраняет событие в таблицу modbus_events.
func (s *SQLiteStore) SaveEvent(ctx context.Context, event ModbusEvent) (int64, error) {
	if err := validateEvent(event); err != nil {
		return 0, err
	}

	timestamp := event.Timestamp.UTC()
	if event.Timestamp.IsZero() {
		timestamp = s.now()
	}

	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO modbus_events (
			timestamp,
			source_ip,
			destination_ip,
			unit_id,
			function_code,
			start_address,
			quantity,
			operation_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		timestamp.Format(time.RFC3339Nano),
		event.SourceIP,
		event.DestinationIP,
		event.UnitID,
		event.FunctionCode,
		event.StartAddress,
		event.Quantity,
		event.OperationType,
	)
	if err != nil {
		return 0, fmt.Errorf("не удалось сохранить событие: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("не удалось получить id сохраненного события: %w", err)
	}

	return id, nil
}

// ListEvents возвращает список событий по фильтру с пагинацией.
func (s *SQLiteStore) ListEvents(ctx context.Context, filter EventListFilter) ([]ModbusEvent, error) {
	if filter.OperationType != "" && !isSupportedOperationType(filter.OperationType) {
		return nil, fmt.Errorf("operation_type %q не поддерживается", filter.OperationType)
	}

	query := strings.Builder{}
	query.WriteString(`SELECT
		id,
		timestamp,
		source_ip,
		destination_ip,
		unit_id,
		function_code,
		start_address,
		quantity,
		operation_type
	FROM modbus_events
	WHERE 1=1`)

	args := make([]any, 0, 8)
	if filter.From != nil {
		query.WriteString(" AND timestamp >= ?")
		args = append(args, filter.From.UTC().Format(time.RFC3339Nano))
	}
	if filter.To != nil {
		query.WriteString(" AND timestamp <= ?")
		args = append(args, filter.To.UTC().Format(time.RFC3339Nano))
	}
	if filter.FunctionCode != nil {
		query.WriteString(" AND function_code = ?")
		args = append(args, *filter.FunctionCode)
	}
	if filter.OperationType != "" {
		query.WriteString(" AND operation_type = ?")
		args = append(args, filter.OperationType)
	}

	query.WriteString(" ORDER BY timestamp ASC, id ASC")

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	query.WriteString(" LIMIT ? OFFSET ?")
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список событий: %w", err)
	}
	defer rows.Close()

	events := make([]ModbusEvent, 0, limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при чтении списка событий: %w", err)
	}

	return events, nil
}

// ListEventsForReplay возвращает последние события в хронологическом порядке.
func (s *SQLiteStore) ListEventsForReplay(ctx context.Context, limit int) ([]ModbusEvent, error) {
	if limit <= 0 {
		limit = defaultReplayLimit
	}

	rows, err := s.db.QueryContext(ctx, `SELECT
		id,
		timestamp,
		source_ip,
		destination_ip,
		unit_id,
		function_code,
		start_address,
		quantity,
		operation_type
	FROM modbus_events
	ORDER BY timestamp DESC, id DESC
	LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить события для replay: %w", err)
	}
	defer rows.Close()

	events := make([]ModbusEvent, 0, limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при чтении событий для replay: %w", err)
	}

	reverseEvents(events)
	return events, nil
}

// ListPolicyCandidates возвращает агрегированные данные для генерации policy.
func (s *SQLiteStore) ListPolicyCandidates(ctx context.Context, limit int) ([]PolicyCandidate, error) {
	if limit <= 0 {
		limit = defaultPolicyLimit
	}

	rows, err := s.db.QueryContext(ctx, `SELECT
		source_ip,
		destination_ip,
		unit_id,
		function_code,
		start_address,
		quantity,
		operation_type,
		COUNT(*) AS hits,
		MIN(timestamp) AS first_seen,
		MAX(timestamp) AS last_seen
	FROM modbus_events
	GROUP BY
		source_ip,
		destination_ip,
		unit_id,
		function_code,
		start_address,
		quantity,
		operation_type
	ORDER BY hits DESC, last_seen DESC
	LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить выборку для policy generation: %w", err)
	}
	defer rows.Close()

	candidates := make([]PolicyCandidate, 0, limit)
	for rows.Next() {
		var (
			candidate     PolicyCandidate
			unitID        int64
			functionCode  int64
			startAddress  int64
			quantity      int64
			operationType string
			firstSeenRaw  string
			lastSeenRaw   string
		)
		if err := rows.Scan(
			&candidate.SourceIP,
			&candidate.DestinationIP,
			&unitID,
			&functionCode,
			&startAddress,
			&quantity,
			&operationType,
			&candidate.Hits,
			&firstSeenRaw,
			&lastSeenRaw,
		); err != nil {
			return nil, fmt.Errorf("не удалось прочитать выборку policy generation: %w", err)
		}

		firstSeen, err := time.Parse(time.RFC3339Nano, firstSeenRaw)
		if err != nil {
			return nil, fmt.Errorf("не удалось распарсить first_seen: %w", err)
		}
		lastSeen, err := time.Parse(time.RFC3339Nano, lastSeenRaw)
		if err != nil {
			return nil, fmt.Errorf("не удалось распарсить last_seen: %w", err)
		}

		candidate.UnitID = uint8(unitID)
		candidate.FunctionCode = uint8(functionCode)
		candidate.StartAddress = uint16(startAddress)
		candidate.Quantity = uint16(quantity)
		candidate.OperationType = OperationType(operationType)
		candidate.FirstSeen = firstSeen
		candidate.LastSeen = lastSeen
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при чтении выборки policy generation: %w", err)
	}

	return candidates, nil
}

// initSchema применяет DDL-схему при инициализации хранилища.
func (s *SQLiteStore) initSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("не удалось инициализировать schema sqlite: %w", err)
	}
	return nil
}

// scanEvent считывает одну строку результата в структуру ModbusEvent.
func scanEvent(scanner interface{ Scan(dest ...any) error }) (ModbusEvent, error) {
	var (
		event         ModbusEvent
		timestampRaw  string
		unitID        int64
		functionCode  int64
		startAddress  int64
		quantity      int64
		operationType string
	)

	if err := scanner.Scan(
		&event.ID,
		&timestampRaw,
		&event.SourceIP,
		&event.DestinationIP,
		&unitID,
		&functionCode,
		&startAddress,
		&quantity,
		&operationType,
	); err != nil {
		return ModbusEvent{}, fmt.Errorf("не удалось прочитать событие из sqlite: %w", err)
	}

	timestamp, err := time.Parse(time.RFC3339Nano, timestampRaw)
	if err != nil {
		return ModbusEvent{}, fmt.Errorf("не удалось распарсить timestamp %q: %w", timestampRaw, err)
	}

	event.Timestamp = timestamp
	event.UnitID = uint8(unitID)
	event.FunctionCode = uint8(functionCode)
	event.StartAddress = uint16(startAddress)
	event.Quantity = uint16(quantity)
	event.OperationType = OperationType(operationType)

	return event, nil
}

// reverseEvents разворачивает порядок событий на месте.
func reverseEvents(events []ModbusEvent) {
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
}

// validateEvent проверяет обязательные поля события перед сохранением.
func validateEvent(event ModbusEvent) error {
	if strings.TrimSpace(event.SourceIP) == "" {
		return errors.New("source_ip обязателен")
	}
	if strings.TrimSpace(event.DestinationIP) == "" {
		return errors.New("destination_ip обязателен")
	}

	if !isSupportedOperationType(event.OperationType) {
		return fmt.Errorf("operation_type %q не поддерживается", event.OperationType)
	}

	return nil
}

// isSupportedOperationType ограничивает допустимые значения operation_type.
func isSupportedOperationType(value OperationType) bool {
	switch value {
	case OperationTypeRead, OperationTypeWrite, OperationTypeUnknown:
		return true
	default:
		return false
	}
}
