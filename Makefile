.PHONY: help build run test test-race lint tidy migrate-up migrate-down docker-up docker-down docker-build clean

BIN          := bin/server
PKG          := ./...
MIGRATE      := migrate
MIGRATIONS   := internal/store/postgres/migrations
DATABASE_URL ?= postgres://oidc:oidc@localhost:5433/oidc?sslmode=disable

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the server binary
	go build -trimpath -o $(BIN) ./cmd/server

run: ## Run the server locally (loads .env)
	go run ./cmd/server

test: ## Run unit + integration tests
	go test $(PKG)

test-race: ## Run tests with the race detector
	go test -race $(PKG)

lint: ## Run golangci-lint
	golangci-lint run

tidy: ## go mod tidy
	go mod tidy

migrate-up: ## Apply all pending migrations
	$(MIGRATE) -path $(MIGRATIONS) -database "$(DATABASE_URL)" up

migrate-down: ## Roll back the most recent migration
	$(MIGRATE) -path $(MIGRATIONS) -database "$(DATABASE_URL)" down 1

docker-up: ## Start postgres + redis + op
	docker compose up -d

docker-down: ## Stop and remove containers
	docker compose down

docker-build: ## Rebuild the op image
	docker compose build op

clean: ## Remove build artifacts
	rm -rf bin/
