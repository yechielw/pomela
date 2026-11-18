.PHONY: build test
build:
	go build -buildvcs=false -trimpath -o pomela .
test:
	go test ./...
