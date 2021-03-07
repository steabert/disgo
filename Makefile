GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

SRC = cmd/disgo/main.go
NAME = disgo
SUPPORTED_PLATFORMS = \
	windows-amd64 \
	linux-amd64 \
	darwin-amd64

debug:
	go build -v -race -o $(NAME) $(SRC)

test:
	go test -v ./...

windows-%: EXT = .exe

$(SUPPORTED_PLATFORMS): OS = $(word 1,$(subst -, ,$*))
$(SUPPORTED_PLATFORMS): ARCH = $(word 2,$(subst -, ,$*))
%:
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags="-s -w" -v -o $(NAME)-$(OS)-$(ARCH)$(EXT) $(SRC)

.PHONY: build
build: $(GOOS)-$(GOARCH)

.PHONY: all
all: $(SUPPORTED_PLATFORMS)
