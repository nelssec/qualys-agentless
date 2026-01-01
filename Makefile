BINARY_NAME := qualys-k8s
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

GO := go
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildTime=$(BUILD_TIME)

BUILD_DIR := build
CONTROLS_DIR := controls

.PHONY: all build build-small build-minimal build-all clean test lint fmt deps help install docker docker-push upx

all: build

build: deps
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

build-small: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; \
	fi

build-minimal: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "nocloud,nohelm" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; \
	fi

build-nohelm: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "nohelm" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

build-aws-only: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noazure,nogcp" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

build-azure-only: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noaws,nogcp" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

build-gcp-only: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noaws,noazure" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

build-all: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/qualys-k8s
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/qualys-k8s
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/qualys-k8s
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/qualys-k8s

upx:
	@if command -v upx >/dev/null 2>&1; then \
		for f in $(BUILD_DIR)/$(BINARY_NAME)-linux-*; do upx --best --lzma "$$f" 2>/dev/null || true; done; \
	fi

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

deps:
	$(GO) mod download
	$(GO) mod tidy

test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

test-coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...
	@command -v goimports >/dev/null 2>&1 || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

verify-policies:
	@command -v opa >/dev/null 2>&1 || { echo "OPA not installed"; exit 1; }
	@for f in $(CONTROLS_DIR)/**/*.rego; do opa check "$$f" || exit 1; done

run-scan:
	$(BUILD_DIR)/$(BINARY_NAME) scan --output console

run-inventory:
	$(BUILD_DIR)/$(BINARY_NAME) inventory --output yaml

docker:
	docker build -t qualys-k8s:$(VERSION) -t qualys-k8s:latest .

docker-push:
	docker push qualys-k8s:$(VERSION)
	docker push qualys-k8s:latest

clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

help:
	@echo "qualys-k8s - Agentless Kubernetes Security Scanner"
	@echo ""
	@echo "Supports: EKS, AKS, GKE, OpenShift, Rancher, k3s, k0s, on-prem, any K8s"
	@echo ""
	@echo "Build targets:"
	@echo "  build           Full build with Helm + managed K8s auth (~70MB)"
	@echo "  build-nohelm    Without Helm SDK (~58MB)"
	@echo "  build-small     Linux amd64 + UPX compression (~15MB)"
	@echo "  build-minimal   Kubeconfig-only auth, no Helm + UPX (~10MB)"
	@echo "  build-aws-only  EKS auth only (no Azure/GCP SDKs)"
	@echo "  build-azure-only AKS auth only (no AWS/GCP SDKs)"
	@echo "  build-gcp-only  GKE auth only (no AWS/Azure SDKs)"
	@echo "  build-all       Cross-compile for all platforms"
	@echo "  upx             Compress Linux binaries with UPX"
	@echo ""
	@echo "Other targets:"
	@echo "  test            Run tests"
	@echo "  lint            Run linter"
	@echo "  fmt             Format code"
	@echo "  docker          Build Docker image"
	@echo "  clean           Clean build artifacts"
	@echo ""
	@echo "Version: $(VERSION)"
