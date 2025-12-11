# CloudSecArchPP UI - Real AWS Integration

This app keeps the same UI/UX while switching to real AWS integration using the AWS Default Credential Provider Chain. No AWS secrets are stored by the app.

## Prerequisites
- Python 3.10+
- AWS credentials available via one of:
  - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`
  - AWS shared config/credentials files: `~/.aws/credentials`, `~/.aws/config`
  - AWS SSO/CLI v2 session (`aws sso login`)
  - Instance profile/role (EC2, ECS, Lambda)

## Setup
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optionally set region (defaults to `us-east-1`):
```bash
set AWS_REGION=us-east-1  # PowerShell: $env:AWS_REGION = "us-east-1"
```

## Run
```bash
python app.py
```
Visit http://localhost:5000

## Notes
- Settings no longer accept/store AWS secrets. Only region is kept in-memory.
- Connection test uses provided keys (if both key+secret are sent) or your default AWS profile/role.
- Scans run with your active AWS identity; ensure it has permissions for S3, EC2, IAM, and RDS read operations.

