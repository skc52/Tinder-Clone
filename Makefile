build:
	@go build -o bin/tinder_clone cmd/main.go

test:
	@go test -v ./...

run: build 
	@./bin/tinder_clone