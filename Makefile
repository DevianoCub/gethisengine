BINARY  := gethisengine
VERSION ?= 0.1.0
PKG     := gethisengine/internal/cli
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION)

.PHONY: build test vet fmt cross clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/gethisengine

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

cross:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/gethisengine
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/gethisengine
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/gethisengine
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/gethisengine
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/gethisengine

clean:
	rm -rf bin dist
