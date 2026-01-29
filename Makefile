.PHONY: build run swagger test migrate-up migrate-down docker-up

build:
	go build -o hermes ./cmd/server

run:
	go run ./cmd/server

swagger:
	swag init -g cmd/server/main.go --parseDependency --parseInternal -o docs

test:
	go test ./...

migrate-up:
	migrate -path database/migrations -database "$${POSTGRES_DSN}" up

migrate-down:
	migrate -path database/migrations -database "$${POSTGRES_DSN}" down

docker-up:
	docker-compose up -d
