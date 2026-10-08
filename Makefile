.PHONY: verify-phase0 verify-phase1 verify-phase2 verify-phase3 verify-phase4 verify-phase5 verify-phase6-core verify-phase6 clean-clone-verify demo verify

verify-phase0:
	python3 scripts/verify_phase0.py

verify-phase1: verify-phase0
	python3 scripts/verify_phase1.py
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test ./...
	go test -race ./...
	GOMAXPROCS=2 go test ./internal/policy -run '^$$' -fuzz '^FuzzDecodeExecute$$' -fuzztime=2s -parallel=2
	GOMAXPROCS=2 go test ./internal/policy -run '^$$' -fuzz '^FuzzNormalize$$' -fuzztime=2s -parallel=2

verify-phase2: verify-phase1
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test ./...
	go test -race ./...
	python3 scripts/verify_phase2.py

verify-phase3: verify-phase2
	python3 scripts/prepare_dependencies.py
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test ./...
	go test -race ./...
	GOMAXPROCS=2 go test ./internal/authorization -run '^$$' -fuzz '^FuzzPaymasterEncoding$$' -fuzztime=2s -parallel=2
	GOMAXPROCS=2 go test ./internal/authorization -run '^$$' -fuzz '^FuzzPaymasterAndData$$' -fuzztime=2s -parallel=2
	forge fmt --check
	forge test
	python3 scripts/verify_phase3.py

verify-phase4: verify-phase3
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test ./...
	go test -race ./...
	forge fmt --check
	forge test --fuzz-runs 256
	python3 scripts/verify_phase4.py
	python3 scripts/verify_phase4.py --bundler

verify-phase5: verify-phase4
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test ./...
	go test -race ./...
	python3 scripts/verify_phase5.py

demo:
	LOCAL_DEMO_API=1 LOCAL_DEMO_FULL=1 python3 scripts/verify_phase4.py --bundler
	python3 scripts/verify_phase6.py

verify-phase6-core: verify-phase5
	@test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go mod verify
	go vet ./...
	go test -count=1 ./...
	go test -race -count=1 ./...
	python3 scripts/verify_phase0.py
	python3 scripts/verify_phase1.py
	python3 scripts/verify_phase3.py
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
	forge test --fuzz-runs 256
	$(MAKE) demo
	docker build -t gasless-policy-engine:local .
	docker run --rm --network none gasless-policy-engine:local --selfcheck
	trivy image --quiet --severity HIGH,CRITICAL --exit-code 1 gasless-policy-engine:local

clean-clone-verify:
	python3 scripts/clean_clone_verify.py

verify-phase6: verify-phase6-core
	$(MAKE) clean-clone-verify
	python3 scripts/release_local.py

verify: verify-phase6
