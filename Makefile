#!/usr/bin/make -f
BUILDDIR ?= $(CURDIR)/build

export GO111MODULE = on

build-linux: go.sum
	@echo "--> Running go generate"
	@go generate
	@echo "--> Building Linux binary"
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -extldflags '-static'" -o $(BUILDDIR)/texporter ./cmd/texporter

go.sum: go.mod
	@echo "--> Ensure dependencies have not been modified"
	@go mod verify

clean:
	rm -f $(BUILDDIR)/*