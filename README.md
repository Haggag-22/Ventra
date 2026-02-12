# Ventra

**Ventra** is a Cloud DFIR (Digital Forensics and Incident Response) and Detection Engineering toolkit. It collects AWS logs and resource metadata, normalizes them into a standard schema, correlates events and resources, and can generate analysis reports—optionally enriched with AI.

## Features

- **Collection**: Pull activity logs (CloudTrail, GuardDuty, Security Hub, VPC Flow Logs, CloudWatch, ELB/S3/Route53/WAF/CloudFront/Detective) and resource snapshots (EC2, IAM, Lambda, KMS, DynamoDB, SNS, SQS, API Gateway, EKS, VPC, S3, ELB, Route53, EventBridge, CloudWatch).
- **Normalization**: Convert raw collected data into a unified schema for analysis.
- **Correlation**: Link events to events, events to resources, and resources to resources; build timelines and detect patterns.
- **Analysis**: Generate DFIR reports (text or JSON), with optional AI-based finding enrichment (OpenAI).
- **Case management**: Organize work by case; each case has its own directory under a central output folder.

## Requirements

- **Python** 3.10 or newer  
- **AWS** account and credentials (access key + secret) with permissions for the services you collect from

## Installation

### From source (recommended for development)

1. Clone the repository and enter the project directory:

   ```bash
   git clone <your-repo-url>
   cd Ventra
   ```

2. Create and activate a virtual environment (optional but recommended):

   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # macOS/Linux
   source .venv/bin/activate
   ```

3. Install the package in editable mode:

   ```bash
   pip install -e .
   ```

   This installs dependencies from `pyproject.toml` (boto3, rich, click, pyyaml, requests, paramiko) and registers the `ventra` CLI.

### Verify installation

```bash
ventra --help
```

You should see the main help and subcommands (`auth`, `whoami`, `case`, `status`, `collect`, `normalize`, `correlate`, `analyze`).

## Configuration

### 1. Configure AWS credentials (Ventra profile)

Ventra uses its own profile store (not the AWS CLI config). Save a profile once; it will be used by default for collect/normalize/analyze unless you pass `--profile`.

```bash
ventra auth --profile default --access-key AKIA... --secret-key ... --region us-east-1
```

Credentials are stored under `~/.ventra/credentials.json`. Use `ventra whoami` to confirm the active identity:

```bash
ventra whoami
ventra whoami --profile default
```

### 2. (Optional) AI enrichment for analysis

To use OpenAI for enriching findings during `ventra analyze`:

- Set environment variables (or use CLI flags):
  - `VENTRA_AI_PROVIDER=openai` (or `ventra analyze --ai-provider openai`)
  - `VENTRA_AI_MODEL=gpt-4o-mini` (or `--ai-model ...`)
  - `VENTRA_AI_MAX_FINDINGS=25` (or `--ai-max-findings N`)
- Ensure your OpenAI API key is set (e.g. `OPENAI_API_KEY` in the environment) as expected by the analysis/AI client in the codebase.

If you do not set the provider (or set it to `off`), analysis runs without AI enrichment.

## How to use

Workflow: **Auth → (optional) create case → Collect → Normalize → Correlate → Analyze**.

### 1. Auth and identity

```bash
ventra auth --profile myprofile --access-key KEY --secret-key SECRET --region us-east-1
ventra whoami
```

### 2. Cases

Cases are stored under a central output directory (e.g. `~/Desktop/Ventra/output` on Windows, or as configured in the case store). You can create a case explicitly or pass a case name to `collect` and Ventra will create it if it doesn’t exist.

```bash
# Create a case
ventra case new --name ec2-compromise

# List cases
ventra case list
```

### 3. Collect logs and resources

Always specify `--case <name>`. Use `--profile` and `--region` if you don’t want the default from your saved profile.

**Logs (events):**

```bash
# CloudTrail (API history, S3 bucket, or Lake query)
ventra collect logs cloudtrail history --case ec2-compromise [--hours 24]
ventra collect logs cloudtrail s3 --case ec2-compromise --bucket my-cloudtrail-bucket [--prefix ...]
ventra collect logs cloudtrail lake --case ec2-compromise --sql "SELECT * FROM ..."

# GuardDuty, Security Hub, CloudWatch Logs, VPC Flow Logs, etc.
ventra collect logs guardduty --case ec2-compromise
ventra collect logs securityhub --case ec2-compromise
ventra collect logs cloudwatch --case ec2-compromise --group /aws/lambda/my-fn [--hours 24]
ventra collect logs vpc flowlogs --case ec2-compromise [--vpc-id vpc-xxx] [--hours 48]
ventra collect logs elb alb --case ec2-compromise
ventra collect logs s3 access --case ec2-compromise --bucket my-bucket
ventra collect logs route53 query-logs --case ec2-compromise
ventra collect logs waf --case ec2-compromise
ventra collect logs cloudfront --case ec2-compromise
ventra collect logs detective --case ec2-compromise
```

**Resources:**

```bash
# EC2 (metadata, volumes, snapshots)
ventra collect resources ec2 metadata-passive --case ec2-compromise --instance i-xxx,i-yyy
ventra collect resources ec2 volumes --case ec2-compromise [--instance i-xxx | --volume vol-xxx]
ventra collect resources ec2 snapshots --case ec2-compromise [--instance i-xxx | --snapshot snap-xxx]
ventra collect resources ec2 all --case ec2-compromise [--instance i-xxx]

# IAM, Lambda, KMS, DynamoDB, SNS, SQS, API Gateway, EKS, VPC, S3, ELB, Route53, EventBridge, CloudWatch
ventra collect resources iam all --case ec2-compromise
ventra collect resources iam user --case ec2-compromise --name alice
ventra collect resources lambda all --case ec2-compromise --name my-function
ventra collect resources kms --case ec2-compromise
ventra collect resources dynamodb all --case ec2-compromise --table my-table [--limit 1000]
ventra collect resources sns all --case ec2-compromise
ventra collect resources sqs all --case ec2-compromise
ventra collect resources apigw all --case ec2-compromise
ventra collect resources eks all --case ec2-compromise --cluster my-cluster [--hours 24]
ventra collect resources vpc all --case ec2-compromise [--vpc-id vpc-xxx]
ventra collect resources s3 all --case ec2-compromise --bucket my-bucket [--prefix optional/]
ventra collect resources elb all --case ec2-compromise
ventra collect resources route53 all --case ec2-compromise --zone Z123...
ventra collect resources eventbridge all --case ec2-compromise
ventra collect resources cloudwatch alarms --case ec2-compromise
ventra collect resources cloudwatch dashboards --case ec2-compromise
```

### 4. Check collector status

See what has been collected for one or more cases:

```bash
ventra status collectors [--case ec2-compromise]
ventra status collectors --cases case1 case2
```

### 5. Normalize

Convert raw collected data for a case into the normalized schema:

```bash
ventra normalize --case ec2-compromise
# Only specific normalizers
ventra normalize --case ec2-compromise --normalizers cloudtrail guardduty ec2
# Optional: override output subdir, account-id, region
ventra normalize --case ec2-compromise --output-subdir normalized --account-id 123456789012 --region us-east-1
```

### 6. Correlate

Build relationships between normalized events and resources:

```bash
ventra correlate --case ec2-compromise
```

Output is written under the case directory (e.g. `.../correlated/`).

### 7. Analyze

Generate a DFIR report (and optionally run AI enrichment):

```bash
ventra analyze --case ec2-compromise
ventra analyze --case ec2-compromise --format json --output ./report.json
ventra analyze --case ec2-compromise --ai-provider openai --ai-model gpt-4o-mini --ai-max-findings 25
```

Reports are produced under the case (e.g. `reports/dfir_report.txt` or the path given by `--output`).

## Project layout

- **`ventra/`** – Main package  
  - **`cli.py`** – CLI entrypoint and routing  
  - **`auth/`** – Profile and credential storage (`~/.ventra/`)  
  - **`case/`** – Case directory resolution and listing  
  - **`collector/`** – Log and resource collectors (CloudTrail, GuardDuty, EC2, IAM, etc.)  
  - **`normalization/`** – Normalizers and pipeline  
  - **`correlation/`** – Correlators and pipeline  
  - **`analysis/`** – Reporting and optional AI enrichment  
  - **`status/`** – Collector status checks  

- **`pyproject.toml`** – Project metadata, dependencies, and CLI script `ventra`

Collected data, normalized output, correlated output, and reports are stored under the case directory in the central output base (e.g. `~/Desktop/Ventra/output/<case-name>/`).

## License

MIT.
