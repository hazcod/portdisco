
all: run

run:
	go run ./cmd/... -log=debug

update:
	go get -u ./... && go mod tidy
