.PHONY: all build clean install load-module unload-module help

# Build variables
BINARY_NAME=process-monitor-daemon
CONFIG_PUBLISHER=config-publisher
KERNEL_MODULE=monitor_hide
BUILD_DIR=build
CMD_DIR=cmd
KERNEL_DIR=kernel
INSTALL_DIR=/usr/local/bin
MODULE_DIR=/lib/modules/$(shell uname -r)/extra
CONFIG_DIR=/etc/process-monitor

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

all: build

## build: Build the daemon and kernel module
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/daemon
	$(GOBUILD) -o $(BUILD_DIR)/$(CONFIG_PUBLISHER) ./$(CMD_DIR)/config-publisher
	@echo "Building kernel module..."
	$(MAKE) -C $(KERNEL_DIR)

## clean: Clean build files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(KERNEL_DIR) clean

## install: Install binaries and setup
install: build
	@echo "Installing..."
	install -d $(CONFIG_DIR)
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	install -m 755 $(BUILD_DIR)/$(CONFIG_PUBLISHER) $(INSTALL_DIR)/
	install -m 644 configs/*.service /etc/systemd/system/ 2>/dev/null || true
	systemctl daemon-reload

## load-module: Load the kernel module
load-module:
	@echo "Loading kernel module..."
	insmod $(KERNEL_DIR)/$(KERNEL_MODULE).ko || true

## unload-module: Unload the kernel module
unload-module:
	@echo "Unloading kernel module..."
	rmmod $(KERNEL_MODULE) || true

## dev: Quick rebuild for development
dev:
	@$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/daemon && sudo $(BUILD_DIR)/$(BINARY_NAME)

## test: Run tests
test:
	$(GOTEST) -v ./...

## deps: Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
