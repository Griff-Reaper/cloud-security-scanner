package main

import (
	"fmt"
	"os"
	"strings"
)

// CLIFlags holds command-line configuration
type CLIFlags struct {
	Severity string
	Output   string
	Region   string
	Quiet    bool
}

// ParseFlags processes command-line arguments
func ParseFlags() CLIFlags {
	flags := CLIFlags{
		Severity: "all",
		Output:   "json",
		Region:   "",
		Quiet:    false,
	}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--severity", "-s":
			if i+1 < len(args) {
				flags.Severity = strings.ToLower(args[i+1])
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				flags.Output = strings.ToLower(args[i+1])
				i++
			}
		case "--region", "-r":
			if i+1 < len(args) {
				flags.Region = args[i+1]
				i++
			}
		case "--quiet", "-q":
			flags.Quiet = true
		case "--help", "-h":
			printHelp()
			os.Exit(0)
		default:
			fmt.Printf("Unknown flag: %s\n", arg)
			printHelp()
			os.Exit(1)
		}
	}

	return flags
}

func printHelp() {
	help := `
🔐 Cloud Security Scanner - AWS Security Auditing Tool

USAGE:
    go run main.go [OPTIONS]

OPTIONS:
    -s, --severity <level>    Filter findings by severity
                              Values: all, critical, high, medium, low
                              Default: all
                              Example: --severity critical

    -o, --output <format>     Output format
                              Values: json, text, html
                              Default: json
                              Example: --output html

    -r, --region <region>     AWS region to scan
                              Default: uses AWS_REGION from .env
                              Example: --region us-west-2

    -q, --quiet               Suppress terminal output (only save report)

    -h, --help                Show this help message

EXAMPLES:
    # Scan with default settings
    go run main.go

    # Show only critical findings
    go run main.go --severity critical

    # Generate HTML report
    go run main.go --output html

    # Scan specific region
    go run main.go --region us-west-2

    # Quiet mode (no terminal output)
    go run main.go --quiet

    # Combined flags
    go run main.go --severity high --output html --quiet

SECURITY CHECKS:
    📦 S3 Buckets (3 checks)
    🔒 Security Groups (1 check)
    👥 IAM Users (2 checks)
    🗄️  RDS Instances (4 checks)
    📋 CloudTrail (4 checks)

OUTPUT:
    Reports are saved to: security-report-YYYY-MM-DD-HH-MM-SS.[format]

DOCUMENTATION:
    https://github.com/Griff-Reaper/cloud-security-scanner
`
	fmt.Println(help)
}

// ShouldIncludeFinding checks if finding matches severity filter
func ShouldIncludeFinding(finding Finding, severityFilter string) bool {
	if severityFilter == "all" {
		return true
	}
	return strings.ToLower(finding.Severity) == severityFilter
}