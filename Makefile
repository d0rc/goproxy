# Output directory
TARGET_DIR := ./target
# Source file for the main package
SOURCE_FILE := src/goproxy.go
# Base name for the binary
BINARY_NAME := goproxy

# Default target: build all specified platforms
all: native linux-amd64 linux-arm64

# Rule to create the target directory if it doesn't exist
$(TARGET_DIR):
	@echo "Creating directory $(TARGET_DIR)..."
	@mkdir -p $(TARGET_DIR)

# Build for the native platform (current machine)
native: $(TARGET_DIR)
	@echo "Building $(BINARY_NAME) for native platform..."
	@go build -o $(TARGET_DIR)/$(BINARY_NAME) $(SOURCE_FILE)
	@echo "Native binary created at $(TARGET_DIR)/$(BINARY_NAME)"

# Build for Linux (amd64)
linux-amd64: $(TARGET_DIR)
	@echo "Building $(BINARY_NAME) for Linux (amd64)..."
	@GOOS=linux GOARCH=amd64 go build -o $(TARGET_DIR)/$(BINARY_NAME)-linux-amd64 $(SOURCE_FILE)
	@echo "Linux (amd64) binary created at $(TARGET_DIR)/$(BINARY_NAME)-linux-amd64"

# Build for Linux (arm64)
linux-arm64: $(TARGET_DIR)
	@echo "Building $(BINARY_NAME) for Linux (arm64)..."
	@GOOS=linux GOARCH=arm64 go build -o $(TARGET_DIR)/$(BINARY_NAME)-linux-arm64 $(SOURCE_FILE)
	@echo "Linux (arm64) binary created at $(TARGET_DIR)/$(BINARY_NAME)-linux-arm64"

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(TARGET_DIR)
	@echo "Cleaned."

# Phony targets to prevent conflicts with files of the same name
.PHONY: all native linux-amd64 linux-arm64 clean

