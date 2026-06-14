package policy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decision — результат policy-проверки запроса.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Policy описывает YAML-политику firewall.
type Policy struct {
	Version       int      `yaml:"version"`
	DefaultAction Decision `yaml:"default_action"`
	Rules         []Rule   `yaml:"rules"`
}

// Rule — одно правило policy с набором фильтров и действием.
type Rule struct {
	ID             string         `yaml:"id"`
	Action         Decision       `yaml:"action"`
	SourceIPs      []string       `yaml:"source_ips"`
	DestinationIPs []string       `yaml:"destination_ips"`
	UnitIDs        []uint8        `yaml:"unit_ids"`
	FunctionCodes  []uint8        `yaml:"function_codes"`
	AddressRanges  []AddressRange `yaml:"address_ranges"`
}

// AddressRange задает допустимый диапазон Modbus адресов.
type AddressRange struct {
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end"`
}

// MatchRequest — нормализованный запрос для policy matcher.
type MatchRequest struct {
	SourceIP      string
	DestinationIP string
	UnitID        uint8
	FunctionCode  uint8
	StartAddress  uint16
	Quantity      uint16
}

// Engine — интерфейс движка policy для прокси и replay.
type Engine interface {
	Evaluate(req MatchRequest) (Decision, error)
}

// Matcher выполняет последовательную проверку правил policy.
type Matcher struct {
	policy Policy
}

// Load читает policy.yaml, применяет дефолты и валидирует структуру.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("не удалось прочитать policy %q: %w", path, err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("не удалось распарсить policy YAML %q: %w", path, err)
	}

	policy.applyDefaults()
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("невалидная policy %q: %w", path, err)
	}

	return policy, nil
}

// NewMatcher создает matcher из уже загруженной policy.
func NewMatcher(policy Policy) (*Matcher, error) {
	policy.applyDefaults()
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	return &Matcher{policy: policy}, nil
}

// Evaluate применяет правила по порядку, либо возвращает default_action.
func (m *Matcher) Evaluate(req MatchRequest) (Decision, error) {
	decision, _, err := m.EvaluateDetailed(req)
	return decision, err
}

// EvaluateDetailed возвращает решение и id совпавшего правила для allow/deny rule.
func (m *Matcher) EvaluateDetailed(req MatchRequest) (Decision, string, error) {
	sourceAddr, destinationAddr, err := parseAndValidateMatchRequest(req)
	if err != nil {
		return DecisionDeny, "", err
	}

	for _, rule := range m.policy.Rules {
		if ruleMatches(rule, req, sourceAddr, destinationAddr) {
			return rule.Action, rule.ID, nil
		}
	}

	return m.policy.DefaultAction, "", nil
}

// applyDefaults заполняет дефолтную версию и default_action.
func (p *Policy) applyDefaults() {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.DefaultAction == "" {
		p.DefaultAction = DecisionDeny
	}
}

// Validate проверяет policy на корректность и безопасные ограничения MVP.
func (p Policy) Validate() error {
	if p.Version <= 0 {
		return fmt.Errorf("version должен быть > 0")
	}

	if p.DefaultAction != DecisionDeny {
		return fmt.Errorf("для MVP default_action должен быть deny")
	}

	for i, rule := range p.Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}

	return nil
}

// validateRule проверяет корректность одного правила.
func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("id обязателен")
	}

	switch rule.Action {
	case DecisionAllow, DecisionDeny:
	default:
		return fmt.Errorf("action должен быть allow или deny")
	}

	if len(rule.SourceIPs) == 0 {
		return fmt.Errorf("source_ips обязателен")
	}
	if len(rule.DestinationIPs) == 0 {
		return fmt.Errorf("destination_ips обязателен")
	}
	if len(rule.UnitIDs) == 0 {
		return fmt.Errorf("unit_ids обязателен")
	}
	if len(rule.FunctionCodes) == 0 {
		return fmt.Errorf("function_codes обязателен")
	}
	if len(rule.AddressRanges) == 0 {
		return fmt.Errorf("address_ranges обязателен")
	}

	for _, value := range rule.SourceIPs {
		if err := validateIPAddress(value); err != nil {
			return fmt.Errorf("source_ips: %w", err)
		}
	}
	for _, value := range rule.DestinationIPs {
		if err := validateIPAddress(value); err != nil {
			return fmt.Errorf("destination_ips: %w", err)
		}
	}
	for _, fc := range rule.FunctionCodes {
		if !isSupportedFunctionCode(fc) {
			return fmt.Errorf("function_codes содержит неподдерживаемый FC: %d", fc)
		}
	}
	for i, r := range rule.AddressRanges {
		if r.Start > r.End {
			return fmt.Errorf("address_ranges[%d]: start не может быть больше end", i)
		}
	}

	return nil
}

// parseAndValidateMatchRequest валидирует входные параметры перед матчингом.
func parseAndValidateMatchRequest(req MatchRequest) (netip.Addr, netip.Addr, error) {
	sourceAddr, err := netip.ParseAddr(req.SourceIP)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("source_ip: невалидный IP %q", req.SourceIP)
	}

	destinationAddr, err := netip.ParseAddr(req.DestinationIP)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("destination_ip: невалидный IP %q", req.DestinationIP)
	}

	if req.Quantity == 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("quantity должен быть > 0")
	}
	if !isSupportedFunctionCode(req.FunctionCode) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("function_code %d не поддерживается", req.FunctionCode)
	}

	endAddress := uint32(req.StartAddress) + uint32(req.Quantity) - 1
	if endAddress > 0xFFFF {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("диапазон адресов запроса выходит за пределы 0..65535")
	}

	return sourceAddr, destinationAddr, nil
}

// validateIPAddress проверяет одиночный IP (без CIDR).
func validateIPAddress(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("IP обязателен")
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return fmt.Errorf("невалидный IP %q", value)
	}
	return nil
}

// ruleMatches проверяет, подходит ли конкретный запрос под конкретное правило.
func ruleMatches(rule Rule, req MatchRequest, sourceAddr netip.Addr, destinationAddr netip.Addr) bool {
	if !containsIP(rule.SourceIPs, sourceAddr) {
		return false
	}
	if !containsIP(rule.DestinationIPs, destinationAddr) {
		return false
	}
	if !containsUint8(rule.UnitIDs, req.UnitID) {
		return false
	}
	if !containsUint8(rule.FunctionCodes, req.FunctionCode) {
		return false
	}
	if !requestRangeWithinAnyRuleRange(rule.AddressRanges, req.StartAddress, req.Quantity) {
		return false
	}

	return true
}

// requestRangeWithinAnyRuleRange проверяет полное вхождение диапазона запроса в один из policy-диапазонов.
func requestRangeWithinAnyRuleRange(ranges []AddressRange, startAddress uint16, quantity uint16) bool {
	requestStart := uint32(startAddress)
	requestEnd := requestStart + uint32(quantity) - 1

	for _, r := range ranges {
		rangeStart := uint32(r.Start)
		rangeEnd := uint32(r.End)
		if requestStart >= rangeStart && requestEnd <= rangeEnd {
			return true
		}
	}

	return false
}

// containsIP проверяет наличие IP в списке rule-поля.
func containsIP(values []string, target netip.Addr) bool {
	for _, value := range values {
		candidate, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		if candidate == target {
			return true
		}
	}
	return false
}

// containsUint8 проверяет наличие числового значения в списке.
func containsUint8(values []uint8, target uint8) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// isSupportedFunctionCode ограничивает policy поддерживаемыми FC в рамках MVP.
func isSupportedFunctionCode(fc uint8) bool {
	switch fc {
	case 1, 2, 3, 4, 5, 6, 15, 16:
		return true
	default:
		return false
	}
}
