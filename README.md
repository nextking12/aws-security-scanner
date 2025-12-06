# AWS Security Scanner

A simple tool that checks your Amazon Web Services (AWS) account for common security issues.

## What Does This Do?

This scanner looks at your AWS resources and finds potential security problems. It checks:

- **S3 Buckets** - Your file storage (are they publicly accessible when they shouldn't be?)
- **EC2 Instances** - Your virtual servers (are they configured safely?)
- **IAM Permissions** - Who has access to what (are permissions too broad?)

The tool will give you a report showing any issues it finds, ranked by how serious they are.

## Before You Start

You'll need:

1. **An AWS Account** - The account you want to scan
2. **AWS Credentials** - Permission to read your AWS resources
3. **Go Installed** - The programming language this tool uses (version 1.19 or newer)

### Setting Up AWS Credentials

The scanner needs permission to look at your AWS resources. Set this up by creating a file at `~/.aws/credentials` with:

```
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

Or set environment variables:

```bash
export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
```

**Note:** The scanner only reads information - it never makes changes to your AWS account.

## How to Use

### 1. Install Dependencies

First, download the required components:

```bash
go mod download
```

### 2. Run a Basic Scan

Scan your AWS account in the default region (us-east-1):

```bash
go run main.go
```

### 3. Scan a Specific Region

To scan a different AWS region:

```bash
go run main.go -region us-west-2
```

### 4. Choose How to View Results

**Simple list (default):**
```bash
go run main.go -output console
```

**Formatted table:**
```bash
go run main.go -output table
```

**Save as JSON file:**
```bash
go run main.go -output json -file report.json
```

### 5. Run Faster with Concurrent Scanning

To check multiple things at once (faster):

```bash
go run main.go -concurrent
```

## Understanding the Results

The scanner will show you findings in these categories:

- 🔴 **CRITICAL** - Fix these immediately! (publicly exposed resources, overly permissive access)
- 🟡 **HIGH** - Important security issues that should be fixed soon
- 🟠 **MEDIUM** - Worth addressing but not urgent
- 🔵 **LOW** - Minor issues or best practice recommendations
- ⚪ **INFO** - Just information, not necessarily a problem

## Building the Program

To create a standalone program you can run anywhere:

```bash
go build -o aws-scanner
```

Then run it with:

```bash
./aws-scanner -region us-east-1
```

## Common Options Summary

| Option | What It Does | Example |
|--------|--------------|---------|
| `-region` | Which AWS region to scan | `-region us-west-2` |
| `-output` | How to show results (console, table, json) | `-output table` |
| `-file` | Where to save JSON report | `-file report.json` |
| `-concurrent` | Scan faster by checking multiple things at once | `-concurrent` |

## License

MIT License - See LICENSE file for details.

## Questions?

This tool helps you find security issues, but fixing them requires understanding AWS. If you're not sure what a finding means or how to fix it, consult the AWS documentation or a cloud security professional.
