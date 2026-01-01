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

.PHONY: all build build-linux build-nohelm build-minimal build-all clean test lint fmt deps help install docker docker-push

all: build

# Local build (native platform, no UPX - for development)
build: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qualys-k8s

# Linux build with UPX compression (~13MB)
build-linux: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; \
	else \
		echo "Warning: UPX not installed, binary not compressed"; \
	fi

# Linux build without Helm SDK + UPX (~11MB)
build-nohelm: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "nohelm" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; \
	else \
		echo "Warning: UPX not installed, binary not compressed"; \
	fi

# Minimal Linux build: kubeconfig-only + UPX (~10MB)
build-minimal: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "nocloud,nohelm" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; \
	else \
		echo "Warning: UPX not installed, binary not compressed"; \
	fi

# Single cloud provider builds (with UPX)
build-aws-only: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noazure,nogcp" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; fi

build-azure-only: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noaws,nogcp" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; fi

build-gcp-only: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "noaws,noazure" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64; fi

# Cross-compile for all platforms (UPX for Linux only)
build-all: deps
	@mkdir -p $(BUILD_DIR)
	@echo "Building linux/amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/qualys-k8s
	@echo "Building linux/arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/qualys-k8s
	@echo "Building darwin/amd64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/qualys-k8s
	@echo "Building darwin/arm64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/qualys-k8s
	@echo "Building windows/amd64..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/qualys-k8s
	@if command -v upx >/dev/null 2>&1; then \
		echo "Compressing Linux binaries with UPX..."; \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64; \
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
	@echo "Build targets (all Linux builds use UPX compression):"
	@echo "  build           Local dev build, native platform (~70MB)"
	@echo "  build-linux     Full build, Linux amd64 + UPX (~13MB)"
	@echo "  build-nohelm    Without Helm SDK + UPX (~11MB)"
	@echo "  build-minimal   Kubeconfig-only, no Helm/cloud SDKs + UPX (~10MB)"
	@echo "  build-aws-only  EKS auth only + UPX"
	@echo "  build-azure-only AKS auth only + UPX"
	@echo "  build-gcp-only  GKE auth only + UPX"
	@echo "  build-all       Cross-compile all platforms (UPX on Linux)"
	@echo ""
	@echo "Other targets:"
	@echo "  test            Run tests"
	@echo "  lint            Run linter"
	@echo "  fmt             Format code"
	@echo "  docker          Build Docker image"
	@echo "  clean           Clean build artifacts"
	@echo ""
	@echo "Version: $(VERSION)"
