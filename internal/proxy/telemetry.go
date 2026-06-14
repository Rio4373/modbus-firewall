package proxy

import (
	"sync"
	"time"
)

const (
	trafficBufferSize = 300
	systemBufferSize  = 160
	latencyBufferSize = 1000
)

// TrafficEvent is the normalized live event shown in the demo dashboard.
type TrafficEvent struct {
	ID            int64             `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	Mode          string            `json:"mode"`
	SourceIP      string            `json:"source_ip"`
	DestinationIP string            `json:"destination_ip"`
	UnitID        uint8             `json:"unit_id"`
	FunctionCode  uint8             `json:"function_code"`
	StartAddress  uint16            `json:"start_address"`
	Quantity      uint16            `json:"quantity"`
	Result        string            `json:"result"`
	Reason        string            `json:"reason,omitempty"`
	Latency       time.Duration     `json:"-"`
	LatencyMS     float64           `json:"latency_ms"`
	Meta          map[string]string `json:"meta,omitempty"`
}

// SystemEvent is a dashboard-ready event for policy reloads, mode changes and errors.
type SystemEvent struct {
	ID        int64             `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Telemetry holds bounded in-memory counters for the demonstration API.
type Telemetry struct {
	mu sync.RWMutex

	startedAt         time.Time
	activeConnections int64
	nextTrafficID     int64
	nextSystemID      int64

	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
	errorRequests   int64
	latencyTotalMS  float64
	latenciesMS     []float64
	lastSecond      int64
	requestsThisSec int64
	blockedThisSec  int64
	requestsPerSec  float64
	blockedPerSec   float64

	traffic []TrafficEvent
	system  []SystemEvent
}

// NewTelemetry creates a telemetry accumulator.
func NewTelemetry() *Telemetry {
	return &Telemetry{
		startedAt:   time.Now(),
		traffic:     make([]TrafficEvent, 0, trafficBufferSize),
		system:      make([]SystemEvent, 0, systemBufferSize),
		latenciesMS: make([]float64, 0, latencyBufferSize),
	}
}

// ConnectionOpened increments active TCP connection count.
func (t *Telemetry) ConnectionOpened() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.activeConnections++
}

// ConnectionClosed decrements active TCP connection count.
func (t *Telemetry) ConnectionClosed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.activeConnections > 0 {
		t.activeConnections--
	}
}

// RecordTraffic records one handled Modbus request.
func (t *Telemetry) RecordTraffic(event TrafficEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}
	if event.LatencyMS == 0 && event.Latency > 0 {
		event.LatencyMS = float64(event.Latency.Microseconds()) / 1000
	}

	currentSecond := event.Timestamp.Unix()
	if t.lastSecond == 0 {
		t.lastSecond = currentSecond
	}
	if currentSecond != t.lastSecond {
		t.requestsPerSec = float64(t.requestsThisSec) / float64(maxInt64(1, currentSecond-t.lastSecond))
		t.blockedPerSec = float64(t.blockedThisSec) / float64(maxInt64(1, currentSecond-t.lastSecond))
		t.requestsThisSec = 0
		t.blockedThisSec = 0
		t.lastSecond = currentSecond
	}

	t.nextTrafficID++
	event.ID = t.nextTrafficID
	t.totalRequests++
	t.requestsThisSec++
	t.latencyTotalMS += event.LatencyMS
	t.latenciesMS = append(t.latenciesMS, event.LatencyMS)
	if len(t.latenciesMS) > latencyBufferSize {
		t.latenciesMS = append([]float64(nil), t.latenciesMS[len(t.latenciesMS)-latencyBufferSize:]...)
	}

	switch event.Result {
	case "ALLOW":
		t.allowedRequests++
	case "BLOCK":
		t.blockedRequests++
		t.blockedThisSec++
	default:
		t.errorRequests++
	}

	t.traffic = append(t.traffic, event)
	if len(t.traffic) > trafficBufferSize {
		t.traffic = append([]TrafficEvent(nil), t.traffic[len(t.traffic)-trafficBufferSize:]...)
	}
}

// RecordSystemEvent stores an operational event.
func (t *Telemetry) RecordSystemEvent(eventType string, message string, severity string, fields map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.nextSystemID++
	t.system = append(t.system, SystemEvent{
		ID:        t.nextSystemID,
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		Message:   message,
		Fields:    fields,
	})
	if len(t.system) > systemBufferSize {
		t.system = append([]SystemEvent(nil), t.system[len(t.system)-systemBufferSize:]...)
	}
}

// Snapshot returns dashboard counters and recent event buffers.
func (t *Telemetry) Snapshot() TelemetrySnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	avgLatency := 0.0
	if t.totalRequests > 0 {
		avgLatency = t.latencyTotalMS / float64(t.totalRequests)
	}

	traffic := append([]TrafficEvent(nil), t.traffic...)
	system := append([]SystemEvent(nil), t.system...)
	latencies := append([]float64(nil), t.latenciesMS...)

	return TelemetrySnapshot{
		StartedAt:         t.startedAt,
		ActiveConnections: t.activeConnections,
		TotalRequests:     t.totalRequests,
		AllowedRequests:   t.allowedRequests,
		BlockedRequests:   t.blockedRequests,
		ErrorRequests:     t.errorRequests,
		AverageLatencyMS:  avgLatency,
		P95LatencyMS:      percentile(latencies, 0.95),
		P99LatencyMS:      percentile(latencies, 0.99),
		RequestsPerSec:    t.requestsPerSec,
		BlockedPerSec:     t.blockedPerSec,
		Traffic:           traffic,
		System:            system,
	}
}

// TelemetrySnapshot is a point-in-time telemetry export.
type TelemetrySnapshot struct {
	StartedAt         time.Time      `json:"started_at"`
	ActiveConnections int64          `json:"active_connections"`
	TotalRequests     int64          `json:"total_requests"`
	AllowedRequests   int64          `json:"allowed_requests"`
	BlockedRequests   int64          `json:"blocked_requests"`
	ErrorRequests     int64          `json:"error_requests"`
	AverageLatencyMS  float64        `json:"average_latency_ms"`
	P95LatencyMS      float64        `json:"p95_latency_ms"`
	P99LatencyMS      float64        `json:"p99_latency_ms"`
	RequestsPerSec    float64        `json:"requests_per_sec"`
	BlockedPerSec     float64        `json:"blocked_per_sec"`
	Traffic           []TrafficEvent `json:"traffic"`
	System            []SystemEvent  `json:"system"`
}

func maxInt64(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func percentile(values []float64, ratio float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	for i := 1; i < len(sorted); i++ {
		value := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > value {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = value
	}
	index := int(float64(len(sorted)-1) * ratio)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
