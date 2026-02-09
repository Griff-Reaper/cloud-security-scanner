package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gookit/color"
	"github.com/joho/godotenv"
)

// CostEstimate holds cost information
type CostEstimate struct {
	MonthlyCost      float64 `json:"monthly_cost,omitempty"`
	PotentialSavings float64 `json:"potential_savings,omitempty"`
	CostImpact       string  `json:"cost_impact,omitempty"`
}

// ComplianceMapping holds compliance framework references
type ComplianceMapping struct {
	CISBenchmark string   `json:"cis_benchmark,omitempty"`
	Framework    []string `json:"frameworks,omitempty"`
}

// Finding represents a security issue discovered
type Finding struct {
	CheckName    string            `json:"check_name"`
	Severity     string            `json:"severity"`
	Resource     string            `json:"resource"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	Compliance   ComplianceMapping `json:"compliance"`
	Cost         CostEstimate      `json:"cost"`
	Timestamp    time.Time         `json:"timestamp"`
}

// Report holds all findings from the scan
type Report struct {
	ScanTime time.Time `json:"scan_time"`
	Region   string    `json:"region"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

// Summary provides count of findings by severity
type Summary struct {
	Critical              int     `json:"critical"`
	High                  int     `json:"high"`
	Medium                int     `json:"medium"`
	Low                   int     `json:"low"`
	Total                 int     `json:"total"`
	TotalMonthlyCost      float64 `json:"total_monthly_cost"`
	TotalPotentialSavings float64 `json:"total_potential_savings"`
}

// CLIFlags holds command-line configuration
type CLIFlags struct {
	Severity string
	Output   string
	Region   string
	Quiet    bool
}

func main() {
	// Parse command-line flags
	flags := ParseFlags()

	if !flags.Quiet {
		fmt.Println("🔐 Cloud Security Scanner - Starting...")
	}

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Load AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	// Override region if specified
	if flags.Region != "" {
		cfg.Region = flags.Region
	}

	// Create AWS service clients
	s3Client := s3.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	rdsClient := rds.NewFromConfig(cfg)
	cloudtrailClient := cloudtrail.NewFromConfig(cfg)

	if !flags.Quiet {
		fmt.Println("✅ Connected to AWS")
		fmt.Println("🔍 Running security checks...\n")
	}

	// Initialize report
	report := Report{
		ScanTime: time.Now(),
		Region:   cfg.Region,
		Findings: []Finding{},
	}

	// Run checks
	s3Findings := checkS3Buckets(ctx, s3Client, flags.Quiet)
	ec2Findings := checkSecurityGroups(ctx, ec2Client, flags.Quiet)
	iamFindings := checkIAMUsers(ctx, iamClient, flags.Quiet)
	rdsFindings := checkRDSInstances(ctx, rdsClient, flags.Quiet)
	cloudtrailFindings := checkCloudTrail(ctx, cloudtrailClient, flags.Quiet)

	// Combine all findings
	report.Findings = append(report.Findings, s3Findings...)
	report.Findings = append(report.Findings, ec2Findings...)
	report.Findings = append(report.Findings, iamFindings...)
	report.Findings = append(report.Findings, rdsFindings...)
	report.Findings = append(report.Findings, cloudtrailFindings...)

	// Filter by severity if specified
	if flags.Severity != "all" {
		filtered := []Finding{}
		for _, finding := range report.Findings {
			if ShouldIncludeFinding(finding, flags.Severity) {
				filtered = append(filtered, finding)
			}
		}
		report.Findings = filtered
	}

	// Calculate costs and savings
var totalMonthlyCost float64
var totalPotentialSavings float64

for i := range report.Findings {
	finding := &report.Findings[i]
	
	// Calculate cost based on finding type
	var monthlyCost float64
	switch {
	case strings.Contains(finding.CheckName, "S3"):
		monthlyCost = estimateS3BucketCost([]Finding{*finding})
	case strings.Contains(finding.CheckName, "RDS"):
		monthlyCost = estimateRDSCost("t3.small", false, false)
	case strings.Contains(finding.CheckName, "CloudTrail"):
		monthlyCost = estimateCloudTrailCost()
	}
	
	// Calculate potential savings
	savings := calculatePotentialSavings(finding.CheckName, finding.Severity)
	
	finding.Cost = CostEstimate{
		MonthlyCost:      monthlyCost,
		PotentialSavings: savings,
		CostImpact:       getCostImpact(savings),
	}
	
	totalMonthlyCost += monthlyCost
	totalPotentialSavings += savings
}

	// Calculate summary
	for _, finding := range report.Findings {
		report.Summary.Total++
		switch finding.Severity {
		case "CRITICAL":
			report.Summary.Critical++
		case "HIGH":
			report.Summary.High++
		case "MEDIUM":
			report.Summary.Medium++
		case "LOW":
			report.Summary.Low++
		}
	}
	
	// Add cost totals to summary
	report.Summary.TotalMonthlyCost = totalMonthlyCost
	report.Summary.TotalPotentialSavings = totalPotentialSavings
	
	// Print summary
	if !flags.Quiet {
		fmt.Println("\n" + strings.Repeat("=", 60))
		color.Bold.Println("📊 SCAN SUMMARY")
		fmt.Println(strings.Repeat("=", 60))
		color.Red.Printf("🔴 Critical: %d\n", report.Summary.Critical)
		color.Yellow.Printf("🟠 High:     %d\n", report.Summary.High)
		color.Cyan.Printf("🟡 Medium:   %d\n", report.Summary.Medium)
		color.Green.Printf("🟢 Low:      %d\n", report.Summary.Low)
		color.Bold.Printf("📝 Total:    %d\n", report.Summary.Total)

		// Cost analysis section
	if report.Summary.TotalMonthlyCost > 0 || report.Summary.TotalPotentialSavings > 0 {
		fmt.Println(strings.Repeat("-", 60))
		color.Bold.Println("💰 COST ANALYSIS")
		if report.Summary.TotalMonthlyCost > 0 {
			fmt.Printf("💵 Monthly Resource Cost:    $%.2f\n", report.Summary.TotalMonthlyCost)
		}
		if report.Summary.TotalPotentialSavings > 0 {
			color.Red.Printf("⚠️  Monthly Risk Exposure:    $%.2f\n", report.Summary.TotalPotentialSavings)
			color.Green.Printf("✅ Annual Risk Reduction:    $%.2f/year\n", report.Summary.TotalPotentialSavings*12)
		}
	}
}

	// Generate report based on output format
	var reportData []byte
	var filename string

	switch flags.Output {
	case "json":
		reportData, err = json.MarshalIndent(report, "", "  ")
		filename = fmt.Sprintf("security-report-%s.json", time.Now().Format("2006-01-02-15-04-05"))
	case "html":
		reportData = []byte(generateHTMLReport(report))
		filename = fmt.Sprintf("security-report-%s.html", time.Now().Format("2006-01-02-15-04-05"))
	case "text":
		reportData = []byte(generateTextReport(report))
		filename = fmt.Sprintf("security-report-%s.txt", time.Now().Format("2006-01-02-15-04-05"))
	default:
		log.Fatalf("Unknown output format: %s", flags.Output)
	}

	if err != nil {
		log.Fatalf("Error creating report: %v", err)
	}

	if err := os.WriteFile(filename, reportData, 0644); err != nil {
		log.Fatalf("Error writing report: %v", err)
	}

	if !flags.Quiet {
		fmt.Printf("\n✅ Report saved to: %s\n", filename)
	}
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

func checkS3Buckets(ctx context.Context, client *s3.Client, quiet bool) []Finding {
	findings := []Finding{}

	bucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Printf("Error listing S3 buckets: %v", err)
		return findings
	}

	if !quiet {
		color.Cyan.Printf("📦 Checking %d S3 buckets...\n", len(bucketsOutput.Buckets))
	}

	for _, bucket := range bucketsOutput.Buckets {
		bucketName := *bucket.Name

		// Check public access block
		publicAccessBlock, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: &bucketName,
		})

		if err != nil || publicAccessBlock.PublicAccessBlockConfiguration == nil {
			findings = append(findings, Finding{
					CheckName:   "S3 Public Access",
					Severity:    "HIGH",
					Resource:    bucketName,
					Description: "S3 bucket does not have public access block enabled",
					Remediation: fmt.Sprintf("Enable public access block: AWS Console → S3 → %s → Permissions → Block public access → Edit → Enable all settings", bucketName),
					Compliance: ComplianceMapping{
						CISBenchmark: "2.1.5",
						Framework:    []string{"PCI-DSS 1.2.1", "SOC2 CC6.1", "HIPAA 164.312(a)(1)"},
					},
					Timestamp: time.Now(),
			})
		} else {
			config := publicAccessBlock.PublicAccessBlockConfiguration
			if !*config.BlockPublicAcls || !*config.BlockPublicPolicy ||
				!*config.IgnorePublicAcls || !*config.RestrictPublicBuckets {
				findings = append(findings, Finding{
					CheckName:   "S3 Public Access",
					Severity:    "HIGH",
					Resource:    bucketName,
					Description: "S3 bucket has incomplete public access block configuration",
					Remediation: fmt.Sprintf("Complete public access block settings: AWS Console → S3 → %s → Permissions → Block public access → Enable all four settings", bucketName),
					Compliance: ComplianceMapping{
						CISBenchmark: "2.1.5",
						Framework:    []string{"PCI-DSS 1.2.1", "SOC2 CC6.1", "HIPAA 164.312(a)(1)"},
					},
					Timestamp: time.Now(),
				})
			}
		}

		// Check bucket encryption
		encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: &bucketName,
		})
		if err != nil || encryption.ServerSideEncryptionConfiguration == nil {
			findings = append(findings, Finding{
				CheckName:   "S3 Encryption",
				Severity:    "MEDIUM",
				Resource:    bucketName,
				Description: "S3 bucket does not have default encryption enabled",
				Remediation: fmt.Sprintf("Enable default encryption: AWS Console → S3 → %s → Properties → Default encryption → Edit → Enable with SSE-S3 or SSE-KMS", bucketName),
				Compliance: ComplianceMapping{
					CISBenchmark: "2.1.1",
					Framework:    []string{"PCI-DSS 3.4", "SOC2 CC6.1", "HIPAA 164.312(a)(2)(iv)"},
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

func checkSecurityGroups(ctx context.Context, client *ec2.Client, quiet bool) []Finding {
	findings := []Finding{}

	sgOutput, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		log.Printf("Error listing security groups: %v", err)
		return findings
	}

	if !quiet {
		color.Cyan.Printf("🔒 Checking %d security groups...\n", len(sgOutput.SecurityGroups))
	}

	for _, sg := range sgOutput.SecurityGroups {
		sgName := *sg.GroupName
		sgID := *sg.GroupId

		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				if *ipRange.CidrIp == "0.0.0.0/0" {
					var port string
					if rule.FromPort != nil {
						port = fmt.Sprintf("port %d", *rule.FromPort)
					} else {
						port = "all ports"
					}

					severity := "MEDIUM"
					remediation := fmt.Sprintf("Restrict access: AWS Console → EC2 → Security Groups → %s → Inbound rules → Edit → Change source from 0.0.0.0/0 to specific IP ranges or security groups", sgID)

					if rule.FromPort != nil && (*rule.FromPort == 22 || *rule.FromPort == 3389) {
						severity = "CRITICAL"
						portName := "SSH"
						if *rule.FromPort == 3389 {
							portName = "RDP"
						}
						remediation = fmt.Sprintf("URGENT: Remove public %s access: AWS Console → EC2 → Security Groups → %s → Inbound rules → Delete the 0.0.0.0/0 rule on port %d. Use bastion host or VPN instead.", portName, sgID, *rule.FromPort)
					}

					findings = append(findings, Finding{
						CheckName:   "Security Group Open to Internet",
						Severity:    severity,
						Resource:    fmt.Sprintf("%s (%s)", sgName, sgID),
						Description: fmt.Sprintf("Security group allows inbound traffic from 0.0.0.0/0 on %s", port),
						Remediation: remediation,
						Compliance: ComplianceMapping{
							CISBenchmark: "5.2",
							Framework:    []string{"PCI-DSS 1.3", "SOC2 CC6.6", "NIST 800-53 AC-4"},
						},
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func checkIAMUsers(ctx context.Context, client *iam.Client, quiet bool) []Finding {
	findings := []Finding{}

	usersOutput, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		log.Printf("Error listing IAM users: %v", err)
		return findings
	}

	if !quiet {
		color.Cyan.Printf("👥 Checking %d IAM users...\n", len(usersOutput.Users))
	}

	for _, user := range usersOutput.Users {
		userName := *user.UserName

		// Check MFA
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: &userName,
		})

		if err != nil || len(mfaDevices.MFADevices) == 0 {
			findings = append(findings, Finding{
				CheckName:   "IAM User Without MFA",
				Severity:    "HIGH",
				Resource:    userName,
				Description: "IAM user does not have MFA (multi-factor authentication) enabled",
				Remediation: fmt.Sprintf("Enable MFA: AWS Console → IAM → Users → %s → Security credentials → Assign MFA device → Use virtual MFA device (Google Authenticator, Authy, etc.)", userName),
				Compliance: ComplianceMapping{
					CISBenchmark: "1.2",
					Framework:    []string{"PCI-DSS 8.3", "SOC2 CC6.1", "NIST 800-53 IA-2"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check access keys
		accessKeys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: &userName,
		})

		if err == nil {
			for _, key := range accessKeys.AccessKeyMetadata {
				keyAge := time.Since(*key.CreateDate)
				if keyAge > 90*24*time.Hour {
					findings = append(findings, Finding{
						CheckName:   "Old IAM Access Key",
						Severity:    "MEDIUM",
						Resource:    fmt.Sprintf("%s (%s)", userName, *key.AccessKeyId),
						Description: fmt.Sprintf("IAM access key is %d days old (recommend rotation every 90 days)", int(keyAge.Hours()/24)),
						Remediation: fmt.Sprintf("Rotate access key: AWS Console → IAM → Users → %s → Security credentials → Create new access key → Update applications → Deactivate old key → Delete after verification", userName),
						Compliance: ComplianceMapping{
							CISBenchmark: "1.4",
							Framework:    []string{"PCI-DSS 8.2.4", "SOC2 CC6.1"},
						},
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func checkRDSInstances(ctx context.Context, client *rds.Client, quiet bool) []Finding {
	findings := []Finding{}

	instancesOutput, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		log.Printf("Error listing RDS instances: %v", err)
		return findings
	}

	if !quiet {
		color.Cyan.Printf("🗄️  Checking %d RDS instances...\n", len(instancesOutput.DBInstances))
	}

	for _, instance := range instancesOutput.DBInstances {
		dbName := *instance.DBInstanceIdentifier

		// Check if instance is publicly accessible
		if instance.PubliclyAccessible != nil && *instance.PubliclyAccessible {
			findings = append(findings, Finding{
				CheckName:   "RDS Public Access",
				Severity:    "CRITICAL",
				Resource:    dbName,
				Description: "RDS database instance is publicly accessible from the internet",
				Remediation: fmt.Sprintf("Disable public access: AWS Console → RDS → Databases → %s → Modify → Connectivity → Additional configuration → Publicly accessible → No → Apply immediately", dbName),
				Compliance: ComplianceMapping{
					CISBenchmark: "6.4",
					Framework:    []string{"PCI-DSS 1.3.1", "SOC2 CC6.6", "HIPAA 164.312(e)(1)"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check if encryption is enabled
		if instance.StorageEncrypted != nil && !*instance.StorageEncrypted {
			findings = append(findings, Finding{
				CheckName:   "RDS Encryption",
				Severity:    "HIGH",
				Resource:    dbName,
				Description: "RDS database does not have encryption at rest enabled",
				Remediation: fmt.Sprintf("Note: Encryption cannot be enabled on existing instances. Create encrypted snapshot: AWS Console → RDS → Databases → %s → Actions → Take snapshot → Then restore snapshot with encryption enabled", dbName),
				Compliance: ComplianceMapping{
					CISBenchmark: "6.2",
					Framework:    []string{"PCI-DSS 3.4", "SOC2 CC6.1", "HIPAA 164.312(a)(2)(iv)"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check backup retention
		if instance.BackupRetentionPeriod != nil && *instance.BackupRetentionPeriod < 7 {
			findings = append(findings, Finding{
				CheckName:   "RDS Backup Retention",
				Severity:    "MEDIUM",
				Resource:    dbName,
				Description: fmt.Sprintf("RDS backup retention period is only %d days (recommended: 7+ days)", *instance.BackupRetentionPeriod),
				Remediation: fmt.Sprintf("Increase backup retention: AWS Console → RDS → Databases → %s → Modify → Backup retention period → Set to 7 or higher → Apply immediately", dbName),
				Compliance: ComplianceMapping{
					CISBenchmark: "6.6",
					Framework:    []string{"SOC2 A1.2", "NIST 800-53 CP-9"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check multi-AZ
		if instance.MultiAZ != nil && !*instance.MultiAZ {
			findings = append(findings, Finding{
				CheckName:   "RDS Multi-AZ",
				Severity:    "MEDIUM",
				Resource:    dbName,
				Description: "RDS instance is not configured for Multi-AZ (high availability)",
				Remediation: fmt.Sprintf("Enable Multi-AZ: AWS Console → RDS → Databases → %s → Modify → Availability & durability → Multi-AZ deployment → Create a standby instance → Apply immediately", dbName),
				Compliance: ComplianceMapping{
					CISBenchmark: "6.5",
					Framework:    []string{"SOC2 A1.2"},
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

func checkCloudTrail(ctx context.Context, client *cloudtrail.Client, quiet bool) []Finding {
	findings := []Finding{}

	trailsOutput, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		log.Printf("Error listing CloudTrail trails: %v", err)
		return findings
	}

	if !quiet {
		color.Cyan.Printf("📋 Checking %d CloudTrail trails...\n", len(trailsOutput.TrailList))
	}

	if len(trailsOutput.TrailList) == 0 {
		findings = append(findings, Finding{
			CheckName:   "CloudTrail Not Enabled",
			Severity:    "CRITICAL",
			Resource:    "Account",
			Description: "No CloudTrail trails configured - API activity logging is disabled",
			Remediation: "Enable CloudTrail: AWS Console → CloudTrail → Create trail → Apply trail to all regions → Enable log file validation → Create new S3 bucket for logs",
			Compliance: ComplianceMapping{
				CISBenchmark: "3.1",
				Framework:    []string{"PCI-DSS 10.1", "SOC2 CC7.2", "HIPAA 164.312(b)"},
			},
			Timestamp: time.Now(),
		})
		return findings
	}

	for _, trail := range trailsOutput.TrailList {
		trailName := *trail.Name

		// Check if trail is logging
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})

		if err != nil || (status.IsLogging != nil && !*status.IsLogging) {
			findings = append(findings, Finding{
				CheckName:   "CloudTrail Not Logging",
				Severity:    "HIGH",
				Resource:    trailName,
				Description: "CloudTrail trail exists but is not actively logging",
				Remediation: fmt.Sprintf("Start logging: AWS Console → CloudTrail → Trails → %s → Logging → Turn on", trailName),
				Compliance: ComplianceMapping{
					CISBenchmark: "3.4",
					Framework:    []string{"PCI-DSS 10.2", "SOC2 CC7.2"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check if trail is multi-region
		if trail.IsMultiRegionTrail != nil && !*trail.IsMultiRegionTrail {
			findings = append(findings, Finding{
				CheckName:   "CloudTrail Single Region",
				Severity:    "MEDIUM",
				Resource:    trailName,
				Description: "CloudTrail trail only logs events in one region",
				Remediation: fmt.Sprintf("Enable multi-region: AWS Console → CloudTrail → Trails → %s → General details → Edit → Apply trail to all regions", trailName),
				Compliance: ComplianceMapping{
					CISBenchmark: "3.1",
					Framework:    []string{"SOC2 CC7.2"},
				},
				Timestamp: time.Now(),
			})
		}

		// Check log file validation
		if trail.LogFileValidationEnabled != nil && !*trail.LogFileValidationEnabled {
			findings = append(findings, Finding{
				CheckName:   "CloudTrail Log Validation Disabled",
				Severity:    "MEDIUM",
				Resource:    trailName,
				Description: "CloudTrail log file validation is not enabled (cannot verify log integrity)",
				Remediation: fmt.Sprintf("Enable log validation: AWS Console → CloudTrail → Trails → %s → General details → Edit → Enable log file validation", trailName),
				Compliance: ComplianceMapping{
					CISBenchmark: "3.2",
					Framework:    []string{"PCI-DSS 10.5.2", "SOC2 CC7.2"},
				},
				Timestamp: time.Now(),
			})
		}
	}

	return findings
}

func generateHTMLReport(report Report) string {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Report - %s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; }
        .critical { background: #fee; border-left: 4px solid #dc3545; }
        .high { background: #fff3cd; border-left: 4px solid #ffc107; }
        .medium { background: #cfe2ff; border-left: 4px solid #0dcaf0; }
        .low { background: #d1e7dd; border-left: 4px solid #198754; }
        .summary-card h3 { margin: 0; font-size: 32px; }
        .summary-card p { margin: 5px 0 0 0; color: #666; }
        .finding { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .severity-badge { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #ffc107; color: black; }
        .badge-medium { background: #0dcaf0; color: white; }
        .badge-low { background: #198754; color: white; }
        .finding-content { margin: 10px 0; }
        .finding-content h4 { margin: 10px 0 5px 0; color: #555; }
        .remediation { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 10px; border-left: 4px solid #007bff; }
        .metadata { color: #666; font-size: 14px; margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Cloud Security Scan Report</h1>
        <p><strong>Scan Time:</strong> %s</p>
        <p><strong>Region:</strong> %s</p>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>%d</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>%d</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>%d</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>%d</h3>
                <p>Low</p>
            </div>
        </div>

        <h2>Findings (%d total)</h2>
`,
		report.ScanTime.Format("2006-01-02 15:04:05"),
		report.ScanTime.Format("2006-01-02 15:04:05"),
		report.Region,
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
		report.Summary.Total,
	)

	for _, finding := range report.Findings {
		badgeClass := "badge-" + strings.ToLower(finding.Severity)
		html += fmt.Sprintf(`
        <div class="finding">
            <div class="finding-header">
                <h3>%s</h3>
                <span class="severity-badge %s">%s</span>
            </div>
            <div class="finding-content">
                <p><strong>Resource:</strong> %s</p>
                <h4>Description:</h4>
                <p>%s</p>
                <div class="remediation">
                    <h4>💡 Remediation:</h4>
                    <p>%s</p>
                </div>
            </div>
            <div class="metadata">
                <strong>Detected:</strong> %s
            </div>
        </div>
`,
			finding.CheckName,
			badgeClass,
			finding.Severity,
			finding.Resource,
			finding.Description,
			finding.Remediation,
			finding.Timestamp.Format("2006-01-02 15:04:05"),
		)
	}

	html += `
    </div>
</body>
</html>`

	return html
}

func generateTextReport(report Report) string {
	var text strings.Builder

	text.WriteString("=" + strings.Repeat("=", 60) + "\n")
	text.WriteString("  CLOUD SECURITY SCAN REPORT\n")
	text.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	text.WriteString(fmt.Sprintf("Scan Time: %s\n", report.ScanTime.Format("2006-01-02 15:04:05")))
	text.WriteString(fmt.Sprintf("Region:    %s\n\n", report.Region))

	text.WriteString("SUMMARY:\n")
	text.WriteString(fmt.Sprintf("  Critical: %d\n", report.Summary.Critical))
	text.WriteString(fmt.Sprintf("  High:     %d\n", report.Summary.High))
	text.WriteString(fmt.Sprintf("  Medium:   %d\n", report.Summary.Medium))
	text.WriteString(fmt.Sprintf("  Low:      %d\n", report.Summary.Low))
	text.WriteString(fmt.Sprintf("  Total:    %d\n\n", report.Summary.Total))

	text.WriteString("FINDINGS:\n")
	text.WriteString(strings.Repeat("-", 60) + "\n\n")

	for i, finding := range report.Findings {
		text.WriteString(fmt.Sprintf("[%d] %s\n", i+1, finding.CheckName))
		text.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
		text.WriteString(fmt.Sprintf("Resource: %s\n", finding.Resource))
		text.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
		text.WriteString(fmt.Sprintf("Remediation: %s\n", finding.Remediation))
		text.WriteString(fmt.Sprintf("Detected: %s\n", finding.Timestamp.Format("2006-01-02 15:04:05")))
		text.WriteString("\n" + strings.Repeat("-", 60) + "\n\n")
	}

	return text.String()
}

// Cost estimation helpers - rough AWS pricing estimates
func estimateS3BucketCost(findings []Finding) float64 {
	// S3 storage: ~$0.023 per GB/month
	// Assume average bucket is 100GB
	return 100 * 0.023 // $2.30/month per bucket
}

func estimateRDSCost(instanceType string, encrypted bool, multiAZ bool) float64 {
	// db.t3.micro: $15/month
	// db.t3.small: $30/month
	// db.t3.medium: $60/month
	// Rough average
	baseCost := 40.0
	
	// Multi-AZ doubles cost
	if multiAZ {
		baseCost *= 2
	}
	
	return baseCost
}

func estimateSecurityGroupCost() float64 {
	// Security groups are free, but open ports = potential breach cost
	// Estimated incident response cost for breach
	return 0 // No direct cost, but high risk
}

func estimateCloudTrailCost() float64 {
	// CloudTrail: First trail free, $2 per 100,000 events
	// Typical account: ~$10-20/month
	return 15.0
}

func calculatePotentialSavings(checkName string, severity string) float64 {
	// Estimated savings from remediating issues
	switch checkName {
	case "RDS Public Access":
		// Preventing breach: Average cost $4.24M (IBM 2023)
		// Conservative estimate: prevent $100k potential incident
		return 100000.0 / 12 // Monthly risk value
		
	case "Security Group Open to Internet":
		if severity == "CRITICAL" {
			return 50000.0 / 12 // SSH/RDP exposure = $4k/month risk
		}
		return 5000.0 / 12 // Other ports = $400/month risk
		
	case "CloudTrail Not Enabled":
		// Without logging, can't detect breaches
		// Estimated cost of undetected breach
		return 20000.0 / 12 // $1,666/month risk
		
	case "IAM User Without MFA":
		// Account takeover risk
		return 10000.0 / 12 // $833/month risk
		
	case "RDS Encryption":
		// Compliance violation fines + breach risk
		return 15000.0 / 12 // $1,250/month risk
		
	case "S3 Public Access":
		// Data leak risk
		return 25000.0 / 12 // $2,083/month risk
		
	case "S3 Encryption":
		// Compliance + data exposure
		return 5000.0 / 12 // $416/month risk
		
	case "RDS Multi-AZ":
		// Downtime cost: $5,600/minute (Gartner)
		// Assume 2 outages/year, 30min each = $336k
		return 336000.0 / 12 // $28k/month risk
		
	case "RDS Backup Retention":
		// Data loss + recovery cost
		return 8000.0 / 12 // $666/month risk
		
	default:
		return 0
	}
}

func getCostImpact(savings float64) string {
	if savings >= 5000 {
		return "CRITICAL - High financial risk"
	} else if savings >= 1000 {
		return "HIGH - Significant cost exposure"
	} else if savings >= 100 {
		return "MEDIUM - Moderate risk"
	} else if savings > 0 {
		return "LOW - Minor cost consideration"
	}
	return "No direct cost impact"
}