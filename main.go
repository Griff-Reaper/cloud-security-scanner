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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/joho/godotenv"
)

// Finding represents a security issue discovered
type Finding struct {
	CheckName   string    `json:"check_name"`
	Severity    string    `json:"severity"`
	Resource    string    `json:"resource"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// Report holds all findings from the scan
type Report struct {
	ScanTime time.Time  `json:"scan_time"`
	Region   string     `json:"region"`
	Findings []Finding  `json:"findings"`
	Summary  Summary    `json:"summary"`
}

// Summary provides count of findings by severity
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

func main() {
	fmt.Println("🔐 Cloud Security Scanner - Starting...")
	
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

	// Create AWS service clients
	s3Client := s3.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)

	fmt.Println("✅ Connected to AWS")
	fmt.Println("🔍 Running security checks...\n")

	// Initialize report
	report := Report{
		ScanTime: time.Now(),
		Region:   cfg.Region,
		Findings: []Finding{},
	}

	// Run checks
	s3Findings := checkS3Buckets(ctx, s3Client)
	ec2Findings := checkSecurityGroups(ctx, ec2Client)
	iamFindings := checkIAMUsers(ctx, iamClient)

	// Combine all findings
	report.Findings = append(report.Findings, s3Findings...)
	report.Findings = append(report.Findings, ec2Findings...)
	report.Findings = append(report.Findings, iamFindings...)

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

	// Print summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🔴 Critical: %d\n", report.Summary.Critical)
	fmt.Printf("🟠 High:     %d\n", report.Summary.High)
	fmt.Printf("🟡 Medium:   %d\n", report.Summary.Medium)
	fmt.Printf("🟢 Low:      %d\n", report.Summary.Low)
	fmt.Printf("📝 Total:    %d\n", report.Summary.Total)

	// Save report to JSON
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Error creating JSON report: %v", err)
	}

	filename := fmt.Sprintf("security-report-%s.json", time.Now().Format("2006-01-02-15-04-05"))
	if err := os.WriteFile(filename, reportJSON, 0644); err != nil {
		log.Fatalf("Error writing report: %v", err)
	}

	fmt.Printf("\n✅ Report saved to: %s\n", filename)
}

func checkS3Buckets(ctx context.Context, client *s3.Client) []Finding {
	findings := []Finding{}
	
	// List all S3 buckets
	bucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Printf("Error listing S3 buckets: %v", err)
		return findings
	}

	fmt.Printf("📦 Checking %d S3 buckets...\n", len(bucketsOutput.Buckets))

	for _, bucket := range bucketsOutput.Buckets {
		bucketName := *bucket.Name
		
		// Check public access block configuration
		publicAccessBlock, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: &bucketName,
		})

		// If there's no public access block or it's not configured properly
		if err != nil || publicAccessBlock.PublicAccessBlockConfiguration == nil {
			findings = append(findings, Finding{
				CheckName:   "S3 Public Access",
				Severity:    "HIGH",
				Resource:    bucketName,
				Description: "S3 bucket does not have public access block enabled",
				Timestamp:   time.Now(),
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
					Timestamp:   time.Now(),
				})
			}
		}

		// Check bucket encryption
		encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: &bucketName,
		})
		if err != nil {
			findings = append(findings, Finding{
				CheckName:   "S3 Encryption",
				Severity:    "MEDIUM",
				Resource:    bucketName,
				Description: "S3 bucket does not have default encryption enabled",
				Timestamp:   time.Now(),
			})
		} else if encryption.ServerSideEncryptionConfiguration == nil {
			findings = append(findings, Finding{
				CheckName:   "S3 Encryption",
				Severity:    "MEDIUM",
				Resource:    bucketName,
				Description: "S3 bucket encryption configuration is missing",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

func checkSecurityGroups(ctx context.Context, client *ec2.Client) []Finding {
	findings := []Finding{}
	
	// Get all security groups
	sgOutput, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		log.Printf("Error listing security groups: %v", err)
		return findings
	}

	fmt.Printf("🔒 Checking %d security groups...\n", len(sgOutput.SecurityGroups))

	for _, sg := range sgOutput.SecurityGroups {
		sgName := *sg.GroupName
		sgID := *sg.GroupId

		// Check inbound rules
		for _, rule := range sg.IpPermissions {
			// Check for 0.0.0.0/0 (open to the internet)
			for _, ipRange := range rule.IpRanges {
				if *ipRange.CidrIp == "0.0.0.0/0" {
					var port string
					if rule.FromPort != nil {
						port = fmt.Sprintf("port %d", *rule.FromPort)
					} else {
						port = "all ports"
					}

					severity := "MEDIUM"
					// SSH (22) and RDP (3389) open to internet = CRITICAL
					if rule.FromPort != nil && (*rule.FromPort == 22 || *rule.FromPort == 3389) {
						severity = "CRITICAL"
					}

					findings = append(findings, Finding{
						CheckName:   "Security Group Open to Internet",
						Severity:    severity,
						Resource:    fmt.Sprintf("%s (%s)", sgName, sgID),
						Description: fmt.Sprintf("Security group allows inbound traffic from 0.0.0.0/0 on %s", port),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func checkIAMUsers(ctx context.Context, client *iam.Client) []Finding {
	findings := []Finding{}
	
	// List all IAM users
	usersOutput, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		log.Printf("Error listing IAM users: %v", err)
		return findings
	}

	fmt.Printf("👥 Checking %d IAM users...\n", len(usersOutput.Users))

	for _, user := range usersOutput.Users {
		userName := *user.UserName

		// Check if user has MFA enabled
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: &userName,
		})

		if err != nil || len(mfaDevices.MFADevices) == 0 {
			findings = append(findings, Finding{
				CheckName:   "IAM User Without MFA",
				Severity:    "HIGH",
				Resource:    userName,
				Description: "IAM user does not have MFA (multi-factor authentication) enabled",
				Timestamp:   time.Now(),
			})
		}

		// Check for access keys
		accessKeys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: &userName,
		})

		if err == nil {
			for _, key := range accessKeys.AccessKeyMetadata {
				// Check if access key is old (>90 days)
				keyAge := time.Since(*key.CreateDate)
				if keyAge > 90*24*time.Hour {
					findings = append(findings, Finding{
						CheckName:   "Old IAM Access Key",
						Severity:    "MEDIUM",
						Resource:    fmt.Sprintf("%s (%s)", userName, *key.AccessKeyId),
						Description: fmt.Sprintf("IAM access key is %d days old (recommend rotation every 90 days)", int(keyAge.Hours()/24)),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return findings
}