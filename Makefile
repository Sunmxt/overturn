.PHONY: dependencies format all ovtd-deps ovtd-debug ovtd-clean

export GOPATH:=$(shell pwd)

OVTD_MAIN_PATH:=overturn/main/ovtd

all: ovtd-debug

clean: ovtd-clean

dependencies: ovtd-deps

format:
	go fmt overturn/...

ovtd-deps:
	go get $(OVTD_MAIN_PATH)

ovtd-debug: format ovtd-deps
	go install $(OVTD_MAIN_PATH)

ovtd-clean:
	go clean -i $(OVTD_MAIN_PATH)
