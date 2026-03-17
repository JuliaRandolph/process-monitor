package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jrandolph2/process-monitor/internal/config"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: encrypt-config <input.yaml> <output.enc>")
		os.Exit(1)
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	// Read input file
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
	}

	// Parse YAML
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
		os.Exit(1)
	}

	// Set timestamps
	cfg.CreatedAt = time.Now()
	cfg.UpdatedAt = time.Now()

	// Generate master key
	masterKey, err := config.GenerateMasterKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating master key: %v\n", err)
		os.Exit(1)
	}

	// Create config manager
	cfgManager := config.NewConfigManager(outputPath, masterKey)

	// Save encrypted
	if err := cfgManager.Save(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving encrypted config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted configuration saved to: %s\n", outputPath)
	fmt.Printf("Original configuration: %s\n", inputPath)
}
