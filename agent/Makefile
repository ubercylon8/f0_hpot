BINARY := f0-deception-agent
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
OUT := bin

PLATFORMS := \
	linux/amd64 linux/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64

.PHONY: build release vet fmt clean

build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(OUT)/$(BINARY) .

vet:
	go vet ./...

fmt:
	gofmt -l -w .

release:
	@mkdir -p $(OUT)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		suffix=""; [ "$$os" = "windows" ] && suffix=".exe"; \
		echo "== $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(OUT)/$(BINARY)-$$os-$$arch$$suffix .; \
	done
	@ls -la $(OUT)
	@if [ -n "$(RELEASE_PRIVKEY)" ]; then \
		./sign_release.sh $(RELEASE_PRIVKEY) $(OUT)/f0-deception-agent-*; \
	fi

clean:
	rm -rf $(OUT)
