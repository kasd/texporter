#!/usr/bin/make -f
BUILDDIR ?= $(CURDIR)/build

export GO111MODULE = on

build-linux: go.sum
	@echo "--> Running go generate"
	@go generate
	@echo "--> Building Linux binary"
	CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags '-w' -o $(BUILDDIR)/texporter ./cmd/texporter

go.sum: go.mod
	@echo "--> Ensure dependencies have not been modified"
	@go mod verify

clean:
	rm -f $(BUILDDIR)/*