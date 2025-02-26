# Makefile for managing migrations, generating SQLC code, and running the Go application
include dev.env
export

# Variables
GOPATH_BIN=$(shell go env GOPATH)/bin
MIGRATION_NAME=$(name)
MIGRATIONS_DIR=./db/migrations
GO_CMD=go run main.go run

build:
	go build -tags jsoniter,netgo,osusergo -ldflags="-linkmode 'external' -extldflags '-static'" -o ./dist/jwtplus-latest; 

create-migration:
	@echo "Creating new migration with name: $(MIGRATION_NAME)..."
	@if [ -z "$(MIGRATION_NAME)" ]; then \
		echo "Error: Please provide a migration name using 'make create-migration name=<migration_name>'"; \
		exit 1; \
	fi
	@export PATH=$$PATH:$(GOPATH_BIN) && migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(MIGRATION_NAME)

# Command to run migrations up
migrate-up:
	@echo "Running migrations up..."
	@export PATH=$$PATH:$(GOPATH_BIN) && migrate -path $(MIGRATIONS_DIR) -database "mysql://$(DB_USER):$(DB_PASSWORD)@tcp($(DB_HOST):$(DB_PORT))/$(DB_NAME)" up

# Command to run migrations down
migrate-down:
	@echo "Running migrations down..."
	@export PATH=$$PATH:$(GOPATH_BIN) && migrate -path $(MIGRATIONS_DIR) -database "mysql://$(DB_USER):$(DB_PASSWORD)@tcp($(DB_HOST):$(DB_PORT))/$(DB_NAME)" down 1

migrate-test-up:
	@echo "Running migrations testdb up..."
	@export PATH=$$PATH:$(GOPATH_BIN) && migrate -path $(MIGRATIONS_DIR) -database "mysql://$(TEST_DB_USER):$(TEST_DB_PASSWORD)@tcp($(TEST_DB_HOST):$(TEST_DB_PORT))/$(TEST_DB_NAME)" up

migrate-test-down:
	@echo "Running migrations testdb up..."
	@export PATH=$$PATH:$(GOPATH_BIN) && migrate -path $(MIGRATIONS_DIR) -database "mysql://$(TEST_DB_USER):$(TEST_DB_PASSWORD)@tcp($(TEST_DB_HOST):$(TEST_DB_PORT))/$(TEST_DB_NAME)" down 1

# Command to generate SQLC code
sqlc-generate:
	@echo "Generating SQLC code..."
	@export PATH=$$PATH:$(GOPATH_BIN) && sqlc -f ./sqlc.yaml generate

# Command to run the Go application
run:
	@echo "Running Go application..."
	$(GO_CMD)

# Run tests with verbose output
test:
	@echo "Running tests..."
	go test ./... -v

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test ./... -v -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

benchmark:
	@echo "Running benchmark"
	go test -bench=. -benchmem ./...

# Phony targets to prevent conflicts with filenames
.PHONY: build create-migration migrate-up migrate-down migrate-test-up migrate-test-down sqlc-generate run test test-coverage migrate-test-up benchmark
