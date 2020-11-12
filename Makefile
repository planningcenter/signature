GO_FILES := $(shell find . -type f -name '*.go')

.PHONY: test
test:
	go test ./...

coverage.out: ${GO_FILES}
	go test -coverprofile=coverage.out ./...

.PHONY: coverage
coverage: coverage.out
	go tool cover -html=coverage.out

.PHONY: clean
clean:
	go mod tidy
	go clean
	-rm coverage.out
