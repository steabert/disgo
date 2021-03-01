build:
	go build -v -o disgo.exe cmd/disgo/main.go

run:
	go run cmd/disgo/main.go

default: build
