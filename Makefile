GO ?= go
DOCKER_COMPOSE ?= docker compose
BINARY ?= ./bin/firewall
CONFIG ?= ./configs/config.yaml
POLICY ?= ./configs/policy.yaml
CANDIDATE_POLICY ?= ./configs/policy.candidate.yaml
BASELINE_POLICY ?= ./configs/policy.generated.yaml

.PHONY: build test run-observe run-enforce validate-config generate-policy validate-policy reset-candidate apply-policy replay stand-up stand-down stand-logs stand-arm-normal stand-arm-repeated stand-arm-rare stand-arm-forbidden demo-prepare demo-observe demo-generate-policy demo-replay demo-enforce demo-hot-reload demo-all test-load benchmark test-reliability generate-report operational-smoke

build:
	$(GO) build -o $(BINARY) ./cmd/firewall

test:
	$(GO) test ./...

run-observe:
	$(GO) run ./cmd/firewall run --config $(CONFIG) --mode observe

run-enforce:
	$(GO) run ./cmd/firewall run --config $(CONFIG) --mode enforce --policy ./configs/policy.yaml

validate-config:
	$(GO) run ./cmd/firewall validate-config --config $(CONFIG)

generate-policy:
	$(GO) run ./cmd/firewall generate-policy --config $(CONFIG) --output $(CANDIDATE_POLICY) --baseline-output $(BASELINE_POLICY) --write-threshold 2

validate-policy:
	$(GO) run ./cmd/firewall validate-policy --policy $(CANDIDATE_POLICY)

reset-candidate:
	$(GO) run ./cmd/firewall reset-candidate --baseline $(BASELINE_POLICY) --candidate $(CANDIDATE_POLICY)

apply-policy:
	$(GO) run ./cmd/firewall apply-policy --candidate $(CANDIDATE_POLICY) --active $(POLICY)

replay:
	$(GO) run ./cmd/firewall replay --config $(CONFIG) --policy $(CANDIDATE_POLICY) --output ./reports/replay-report.json

stand-up:
	$(DOCKER_COMPOSE) up --build -d

stand-down:
	$(DOCKER_COMPOSE) down

stand-logs:
	$(DOCKER_COMPOSE) logs -f plc-sim firewall

stand-arm-normal:
	$(DOCKER_COMPOSE) exec -T arm-sim arm-sim --target firewall:1502 --scenario normal-read

stand-arm-repeated:
	$(DOCKER_COMPOSE) exec -T arm-sim arm-sim --target firewall:1502 --scenario repeated-write --repeat 10

stand-arm-rare:
	$(DOCKER_COMPOSE) exec -T arm-sim arm-sim --target firewall:1502 --scenario rare-write

stand-arm-forbidden:
	$(DOCKER_COMPOSE) exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write

demo-prepare:
	./scripts/demo/00_prepare.sh

demo-observe:
	./scripts/demo/01_observe.sh

demo-generate-policy:
	./scripts/demo/02_generate_policy.sh

demo-replay:
	./scripts/demo/03_replay.sh

demo-enforce:
	./scripts/demo/04_enforce.sh

demo-hot-reload:
	./scripts/demo/05_hot_reload.sh

demo-all:
	./scripts/demo/run_all.sh

test-load:
	BENCHMARK_REQUESTS=$${BENCHMARK_REQUESTS:-500000} LATENCY_REQUESTS=$${LATENCY_REQUESTS:-3000} STABILITY_SECONDS=$${STABILITY_SECONDS:-60} ./scripts/testing/operational_benchmark.py

benchmark:
	BENCHMARK_REQUESTS=$${BENCHMARK_REQUESTS:-500000} LATENCY_REQUESTS=$${LATENCY_REQUESTS:-5000} STABILITY_SECONDS=$${STABILITY_SECONDS:-300} ./scripts/testing/operational_benchmark.py

test-reliability:
	BENCHMARK_REQUESTS=$${BENCHMARK_REQUESTS:-100000} LATENCY_REQUESTS=$${LATENCY_REQUESTS:-3000} STABILITY_SECONDS=$${STABILITY_SECONDS:-43200} ./scripts/testing/operational_benchmark.py

generate-report:
	./scripts/testing/operational_benchmark.py --skip-build --requests $${BENCHMARK_REQUESTS:-500000} --latency-requests $${LATENCY_REQUESTS:-3000} --stability-seconds $${STABILITY_SECONDS:-60}

operational-smoke:
	BENCHMARK_REQUESTS=200 LATENCY_REQUESTS=60 STABILITY_SECONDS=2 ./scripts/testing/operational_benchmark.py
