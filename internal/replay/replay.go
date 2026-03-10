package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

// defaultReplayBatchSize задает размер порции чтения событий для replay.
const defaultReplayBatchSize = 1000

// Report описывает сводный результат replay-анализа.
type Report struct {
	TotalEvents         int                  `json:"total_events"`
	CoveredEvents       int                  `json:"covered_events"`
	BlockedEvents       int                  `json:"blocked_events"`
	UncoveredOperations []UncoveredOperation `json:"uncovered_operations"`
}

// UncoveredOperation агрегирует операцию, не покрытую текущей policy.
type UncoveredOperation struct {
	SourceIP      string                `json:"source_ip"`
	DestinationIP string                `json:"destination_ip"`
	UnitID        uint8                 `json:"unit_id"`
	FunctionCode  uint8                 `json:"function_code"`
	StartAddress  uint16                `json:"start_address"`
	EndAddress    uint16                `json:"end_address"`
	Quantity      uint16                `json:"quantity"`
	OperationType storage.OperationType `json:"operation_type"`
	Count         int                   `json:"count"`
}

// uncoveredKey используется как ключ карты для агрегации непокрытых операций.
type uncoveredKey struct {
	sourceIP      string
	destinationIP string
	unitID        uint8
	functionCode  uint8
	startAddress  uint16
	endAddress    uint16
	quantity      uint16
	operationType storage.OperationType
}

// Run загружает события из storage и запускает анализ через matcher.
func Run(ctx context.Context, eventStore storage.EventStore, matcher policy.Engine) (Report, error) {
	events, err := loadAllEvents(ctx, eventStore, defaultReplayBatchSize)
	if err != nil {
		return Report{}, err
	}

	return AnalyzeEvents(events, matcher)
}

// AnalyzeEvents прогоняет все события через matcher и формирует report.
func AnalyzeEvents(events []storage.ModbusEvent, matcher policy.Engine) (Report, error) {
	if matcher == nil {
		return Report{}, fmt.Errorf("matcher обязателен")
	}

	report := Report{TotalEvents: len(events)}
	uncovered := make(map[uncoveredKey]*UncoveredOperation)

	for _, event := range events {
		decision, err := matcher.Evaluate(policy.MatchRequest{
			SourceIP:      event.SourceIP,
			DestinationIP: event.DestinationIP,
			UnitID:        event.UnitID,
			FunctionCode:  event.FunctionCode,
			StartAddress:  event.StartAddress,
			Quantity:      event.Quantity,
		})
		if err != nil || decision == policy.DecisionDeny {
			report.BlockedEvents++
			addUncovered(uncovered, event)
			continue
		}

		report.CoveredEvents++
	}

	report.UncoveredOperations = flattenUncovered(uncovered)
	return report, nil
}

// SaveReportJSON сохраняет replay report в JSON-файл.
func SaveReportJSON(path string, report Report) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("путь для отчёта обязателен")
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("не удалось создать директорию для отчёта %q: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать replay report в JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("не удалось записать replay report %q: %w", path, err)
	}

	return nil
}

// loadAllEvents постранично читает события из EventStore.
func loadAllEvents(ctx context.Context, eventStore storage.EventStore, batchSize int) ([]storage.ModbusEvent, error) {
	if eventStore == nil {
		return nil, fmt.Errorf("eventStore обязателен")
	}
	if batchSize <= 0 {
		batchSize = defaultReplayBatchSize
	}

	allEvents := make([]storage.ModbusEvent, 0, batchSize)
	offset := 0
	for {
		batch, err := eventStore.ListEvents(ctx, storage.EventListFilter{Limit: batchSize, Offset: offset})
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать события из storage: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		allEvents = append(allEvents, batch...)
		offset += len(batch)
	}

	return allEvents, nil
}

// addUncovered увеличивает счетчик для конкретной непокрытой операции.
func addUncovered(uncovered map[uncoveredKey]*UncoveredOperation, event storage.ModbusEvent) {
	endAddress := calculateEndAddress(event.StartAddress, event.Quantity)
	key := uncoveredKey{
		sourceIP:      event.SourceIP,
		destinationIP: event.DestinationIP,
		unitID:        event.UnitID,
		functionCode:  event.FunctionCode,
		startAddress:  event.StartAddress,
		endAddress:    endAddress,
		quantity:      event.Quantity,
		operationType: event.OperationType,
	}

	record, exists := uncovered[key]
	if !exists {
		record = &UncoveredOperation{
			SourceIP:      event.SourceIP,
			DestinationIP: event.DestinationIP,
			UnitID:        event.UnitID,
			FunctionCode:  event.FunctionCode,
			StartAddress:  event.StartAddress,
			EndAddress:    endAddress,
			Quantity:      event.Quantity,
			OperationType: event.OperationType,
		}
		uncovered[key] = record
	}
	record.Count++
}

// calculateEndAddress безопасно вычисляет конец диапазона с ограничением uint16.
func calculateEndAddress(startAddress uint16, quantity uint16) uint16 {
	if quantity == 0 {
		return startAddress
	}
	end := uint32(startAddress) + uint32(quantity) - 1
	if end > 0xFFFF {
		return 0xFFFF
	}
	return uint16(end)
}

// flattenUncovered преобразует map в срез и сортирует для стабильного вывода.
func flattenUncovered(uncovered map[uncoveredKey]*UncoveredOperation) []UncoveredOperation {
	result := make([]UncoveredOperation, 0, len(uncovered))
	for _, item := range uncovered {
		result = append(result, *item)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		if result[i].SourceIP != result[j].SourceIP {
			return result[i].SourceIP < result[j].SourceIP
		}
		if result[i].DestinationIP != result[j].DestinationIP {
			return result[i].DestinationIP < result[j].DestinationIP
		}
		if result[i].UnitID != result[j].UnitID {
			return result[i].UnitID < result[j].UnitID
		}
		if result[i].FunctionCode != result[j].FunctionCode {
			return result[i].FunctionCode < result[j].FunctionCode
		}
		if result[i].StartAddress != result[j].StartAddress {
			return result[i].StartAddress < result[j].StartAddress
		}
		if result[i].EndAddress != result[j].EndAddress {
			return result[i].EndAddress < result[j].EndAddress
		}
		if result[i].Quantity != result[j].Quantity {
			return result[i].Quantity < result[j].Quantity
		}
		return result[i].OperationType < result[j].OperationType
	})

	return result
}

// NewReportContext создает context c дефолтным таймаутом replay-анализа.
func NewReportContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}
