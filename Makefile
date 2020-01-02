.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	-rf cmd/generate/generate

.PHONY: generate
generate: cmd/generate/generate
	cmd/generate/generate

cmd/generate/generate:
	cd cmd/generate && go build -o generate .
