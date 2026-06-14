package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicySuccess(t *testing.T) {
	t.Parallel()

	path := writePolicy(t, `version: 1
default_action: deny
rules:
  - id: allow-arm-read
    action: allow
    source_ips: ["10.0.0.10"]
    destination_ips: ["10.0.0.20"]
    unit_ids: [1]
    function_codes: [3, 4]
    address_ranges:
      - start: 0
        end: 100
`)

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("ожидали успешную загрузку policy, получили ошибку: %v", err)
	}

	if policy.DefaultAction != DecisionDeny {
		t.Fatalf("ожидали default_action=deny, получили %q", policy.DefaultAction)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("ожидали 1 правило, получили %d", len(policy.Rules))
	}
}

func TestMatcherRuleMatch(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules: []Rule{
			{
				ID:             "allow-main",
				Action:         DecisionAllow,
				SourceIPs:      []string{"10.0.0.10"},
				DestinationIPs: []string{"10.0.0.20"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3, 4},
				AddressRanges: []AddressRange{
					{Start: 0, End: 100},
				},
			},
		},
	})

	decision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      5,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if decision != DecisionAllow {
		t.Fatalf("ожидали allow, получили %q", decision)
	}
}

func TestMatcherEvaluateDetailedReturnsMatchedRuleID(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules: []Rule{
			{
				ID:             "allow-main",
				Action:         DecisionAllow,
				SourceIPs:      []string{"10.0.0.10"},
				DestinationIPs: []string{"10.0.0.20"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []AddressRange{{Start: 0, End: 100}},
			},
		},
	})

	decision, ruleID, err := matcher.EvaluateDetailed(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      1,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку EvaluateDetailed, получили: %v", err)
	}
	if decision != DecisionAllow {
		t.Fatalf("ожидали allow, получили %q", decision)
	}
	if ruleID != "allow-main" {
		t.Fatalf("ожидали matched rule id allow-main, получили %q", ruleID)
	}
}

func TestMatcherMismatchSourceDestination(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules: []Rule{
			{
				ID:             "allow-main",
				Action:         DecisionAllow,
				SourceIPs:      []string{"10.0.0.10"},
				DestinationIPs: []string{"10.0.0.20"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []AddressRange{{Start: 0, End: 100}},
			},
		},
	})

	decision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.11",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      1,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("ожидали deny при несовпадении source, получили %q", decision)
	}

	decision, err = matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.21",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      1,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("ожидали deny при несовпадении destination, получили %q", decision)
	}
}

func TestMatcherMismatchFunctionCode(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules: []Rule{
			{
				ID:             "allow-read",
				Action:         DecisionAllow,
				SourceIPs:      []string{"10.0.0.10"},
				DestinationIPs: []string{"10.0.0.20"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []AddressRange{{Start: 0, End: 100}},
			},
		},
	})

	decision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  6,
		StartAddress:  10,
		Quantity:      1,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("ожидали deny при несовпадении FC, получили %q", decision)
	}
}

func TestMatcherAddressRange(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules: []Rule{
			{
				ID:             "allow-range",
				Action:         DecisionAllow,
				SourceIPs:      []string{"10.0.0.10"},
				DestinationIPs: []string{"10.0.0.20"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []AddressRange{{Start: 100, End: 110}},
			},
		},
	})

	allowDecision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  102,
		Quantity:      3,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if allowDecision != DecisionAllow {
		t.Fatalf("ожидали allow при попадании в диапазон, получили %q", allowDecision)
	}

	denyDecision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  109,
		Quantity:      3,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if denyDecision != DecisionDeny {
		t.Fatalf("ожидали deny при выходе из диапазона, получили %q", denyDecision)
	}
}

func TestMatcherDefaultDenyAll(t *testing.T) {
	t.Parallel()

	matcher := mustNewMatcher(t, Policy{
		Version:       1,
		DefaultAction: DecisionDeny,
		Rules:         nil,
	})

	decision, err := matcher.Evaluate(MatchRequest{
		SourceIP:      "10.0.0.10",
		DestinationIP: "10.0.0.20",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  0,
		Quantity:      1,
	})
	if err != nil {
		t.Fatalf("не ожидали ошибку Evaluate, получили: %v", err)
	}
	if decision != DecisionDeny {
		t.Fatalf("ожидали default deny all, получили %q", decision)
	}
}

func TestLoadPolicyInvalidDefaultAction(t *testing.T) {
	t.Parallel()

	path := writePolicy(t, `version: 1
default_action: allow
rules: []
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("ожидали ошибку при default_action=allow")
	}
	if !strings.Contains(err.Error(), "default_action") {
		t.Fatalf("ожидали ошибку про default_action, получили: %v", err)
	}
}

func mustNewMatcher(t *testing.T, policy Policy) *Matcher {
	t.Helper()

	matcher, err := NewMatcher(policy)
	if err != nil {
		t.Fatalf("не удалось создать matcher: %v", err)
	}
	return matcher
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать policy: %v", err)
	}

	return path
}
