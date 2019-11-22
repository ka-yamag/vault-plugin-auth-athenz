#
# Makefile to build vault-plugin-auth-athenz
# Prerequisite: Go development environment
#

GOPKGNAME = github.com/katyamag/vault-plugin-auth-athenz
PKG_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S')
BINARY=vault-plugin-auth-athenz
SRC=./cmd/vault-plugin-auth-athenz/main.go
GOFMT_FILE?=$$(find . -name "*.go" | grep -v vendor)

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)

ifdef GO
GO_VER_GTEQ11 := $(shell expr `go version | cut -f 3 -d' ' | cut -f2 -d.` \>= 11)
ifneq "$(GO_VER_GTEQ11)" "1"
all:
	@echo "Please install 1.11.x or newer version of golang"
else
.PHONY: mod fmt test linux darwin
all: mod fmt test linux darwin
endif

else

all:
	@echo "go is not available please install golang"

endif

mod:
	go mod tidy

fmt:
	gofmt -l .

test: mod fmt
	go test --race -v ./...

darwin:
	@echo "Building darwin client..."
	GOOS=darwin go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/darwin/$(BINARY) $(SRC)

linux:
	@echo "Building linux client..."
	GOOS=linux go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/linux/$(BINARY) $(SRC)

clean:
	rm -rf target
