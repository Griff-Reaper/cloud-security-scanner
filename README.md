# 🔐 Cloud Security Scanner

Automated AWS security auditing tool written in Go. Scans your AWS infrastructure for common security misconfigurations and generates detailed reports.

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![AWS SDK](https://img.shields.io/badge/AWS_SDK-Go_v2-FF9900?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Features

- **S3 Security Checks**
  - Public access block configuration
  - Default encryption settings
  - Bucket permissions

- **EC2 Security Group Auditing**
  - Detects security groups open to 0.0.0.0/0
  - Flags critical ports (SSH, RDP) exposed to internet
  - Reviews inbound rule configurations

- **IAM User Analysis**
  - MFA (Multi-Factor Authentication) enforcement check
  - Access key age monitoring (>90 days)
  - User security posture assessment

- **Automated Reporting**
  - Color-coded severity levels (Critical, High, Medium, Low)
  - JSON report generation with timestamps
  - Summary statistics and findings count

## 📊 Sample Output
```
🔐 Cloud Security Scanner - Starting...
✅ Connected to AWS
🔍 Running security checks...

📦 Checking 0 S3 buckets...
🔒 Checking 1 security groups...
👥 Checking 1 IAM users...

============================================================
📊 SCAN SUMMARY
============================================================
🔴 Critical: 0
🟠 High:     1
🟡 Medium:   0
🟢 Low:      0
📝 Total:    1

✅ Report saved to: security-report-2026-02-08-21-38-47.json
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or higher
- AWS account with appropriate permissions
- AWS credentials configured

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Griff-Reaper/cloud-security-scanner.git
cd cloud-security-scanner
```

2. **Install dependencies**
```bash
go mod download
```

3. **Configure AWS credentials**

Create a `.env` file:
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
```

**⚠️ Security Note:** Never commit your `.env` file! It's already in `.gitignore`.

4. **Run the scanner**
```bash
go run main.go
```

## 🔧 AWS Permissions Required

The scanner requires read-only access. Recommended IAM policies:
- `SecurityAudit` (AWS managed policy)
- `ViewOnlyAccess` (AWS managed policy)

### Creating an Audit User
```bash
# In AWS Console:
1. IAM → Users → Create user
2. Attach policies: SecurityAudit + ViewOnlyAccess
3. Create access key for CLI access
4. Use credentials in .env file
```

## 📁 Project Structure
```
cloud-security-scanner/
├── main.go              # Main application and security checks
├── .env                 # AWS credentials (not committed)
├── .gitignore          # Git ignore rules
├── go.mod              # Go module dependencies
├── go.sum              # Dependency checksums
└── README.md           # This file
```

## 🛡️ Security Checks Explained

### S3 Bucket Checks

**Public Access Block (HIGH)**
- Ensures buckets aren't accidentally exposed to the internet
- Validates all four public access block settings
- Critical for preventing data leaks

**Encryption at Rest (MEDIUM)**
- Verifies default encryption is enabled
- Protects data stored in S3 buckets
- Compliance requirement for many frameworks

### Security Group Checks

**Open to Internet (CRITICAL/MEDIUM)**
- Detects 0.0.0.0/0 rules allowing global access
- SSH (port 22) and RDP (port 3389) = CRITICAL severity
- Other ports = MEDIUM severity
- Prevents unauthorized access to resources

### IAM User Checks

**MFA Not Enabled (HIGH)**
- Multi-factor authentication protects against credential theft
- Critical security control for privileged accounts
- AWS best practice for all users

**Old Access Keys (MEDIUM)**
- Access keys older than 90 days should be rotated
- Reduces impact of potential key compromise
- Compliance requirement for many standards

## 🎨 Output Format

The scanner generates a JSON report with the following structure:
```json
{
  "scan_time": "2026-02-08T21:38:47Z",
  "region": "us-east-1",
  "findings": [
    {
      "check_name": "IAM User Without MFA",
      "severity": "HIGH",
      "resource": "cspm-audit-user",
      "description": "IAM user does not have MFA enabled",
      "timestamp": "2026-02-08T21:38:47Z"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "total": 1
  }
}
```

## 🔮 Roadmap

- [ ] RDS security checks (encryption, public access)
- [ ] Lambda function security analysis
- [ ] CloudTrail logging verification
- [ ] KMS key rotation policies
- [ ] SNS/SQS encryption checks
- [ ] HTML report generation
- [ ] Multi-region scanning
- [ ] Azure and GCP support
- [ ] CI/CD integration (GitHub Actions)
- [ ] Compliance framework mapping (CIS, NIST, PCI-DSS)

## 📚 Learn More

- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Go AWS SDK v2 Documentation](https://aws.github.io/aws-sdk-go-v2/)

## 🤝 Contributing

Contributions are welcome! This is a portfolio project demonstrating cloud security automation and Go programming.

## 📝 License

MIT License - See LICENSE file for details

## 👤 Author

**Jace** - System Administrator & Security Engineer  
- Active Secret Clearance
- CrowdStrike Falcon Administrator
- Pursuing AI Security & MLOps specialization

## 🎯 Why This Project?

Built to demonstrate:
- Go programming proficiency
- AWS security expertise
- Cloud security automation
- Infrastructure security auditing
- Real-world security tooling development

Perfect for roles requiring cloud security, infrastructure security, and security automation expertise.

---

**⭐ If this project helped you, consider starring it on GitHub!**
```

---

## Step 2: Create LICENSE File

**Create `LICENSE` file:**
```
MIT License

Copyright (c) 2026 Jace

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Step 3: Update .gitignore

**Make sure your `.gitignore` has:**
```
# Environment variables
.env

# Go build artifacts
*.exe
*.exe~
*.dll
*.so
*.dylib

# Go test coverage
*.out

# IDE
.vscode/
.idea/

# Reports
security-report-*.json

# Go vendor
vendor/