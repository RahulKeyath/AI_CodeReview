import re
import json
import boto3
from transformers import pipeline

# Load AI model for vulnerability detection
ai_model = pipeline("text-classification", model="microsoft/codebert-base")
# Define vulnerability patterns
VULNERABILITY_PATTERNS = {
    "Hardcoded Password": r"(?i)(password\s*=\s*['\"].+['\"])",
    "SQL Injection": r"(?i)(SELECT\s+\*\s+FROM\s+.+\s+WHERE\s+.+\s*=.*)",
    "Command Injection": r"(?i)(os\.system|subprocess\.(call|Popen))",
    "Insecure Imports": r"(?i)(import\s+pickle|import\s+eval)"
}

# Function to scan code
def scan_code(code):
    findings = []
    
    # Check for vulnerabilities using regex
    for issue, pattern in VULNERABILITY_PATTERNS.items():
        if re.search(pattern, code):
            findings.append(f"⚠️ {issue} detected!")

    # Use AI model for further review
    ai_results = ai_model(code)
    ai_findings = [res["label"] for res in ai_results if res["score"] > 0.8]

    return findings + ai_findings

# AWS S3 Setup
s3 = boto3.client("s3")
BUCKET_NAME = "code-review-files"

# AWS Lambda Handler Function
def lambda_handler(event, context):
    # Get the file name from the event
    file_name = event["file_name"]

    # Download code file from S3
    s3.download_file(BUCKET_NAME, file_name, "/tmp/code.py")

    # Read the code file
    with open("/tmp/code.py", "r") as f:
        code_content = f.read()

    # Scan for vulnerabilities
    results = scan_code(code_content)

    return {"file": file_name, "vulnerabilities": results}

# Local Testing
if __name__ == "__main__":
    # Read test code file
    with open("test_code.py", "r") as f:
        code_content = f.read()
    
    # Scan for vulnerabilities
    results = scan_code(code_content)

    # Print results
    print("\n🔍 Vulnerabilities Found:")
    for issue in results:
        print(issue)