GOFLAGS := -ldflags="-s -w"
BIN     := bin

.PHONY: all proto build test clean deps

all: proto build

deps:
	@which protoc >/dev/null 2>&1 || (echo "Install protoc: apt install protobuf-compiler" && exit 1)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

proto:
	mkdir -p pkg/proto
	protoc --go_out=pkg/proto --go_opt=paths=source_relative \
	       --go-grpc_out=pkg/proto --go-grpc_opt=paths=source_relative \
	       -I proto/ proto/spectre.proto

build:
	mkdir -p $(BIN)
	go build $(GOFLAGS) -o $(BIN)/spectre-server  ./cmd/server/
	go build $(GOFLAGS) -o $(BIN)/spectre-agent   ./cmd/agent/
	go build $(GOFLAGS) -o $(BIN)/spectre-console ./cmd/console/
	@echo "[+] Built: $(BIN)/spectre-server $(BIN)/spectre-agent $(BIN)/spectre-console"

build-agent-linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/spectre-agent-linux-amd64 ./cmd/agent/

test:
	go test ./... -v -race -timeout 30s

clean:
	rm -rf $(BIN)/ pkg/proto/
