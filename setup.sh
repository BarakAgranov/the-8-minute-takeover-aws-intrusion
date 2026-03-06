#!/bin/bash
# =============================================================================
# setup.sh -- One-Command Setup for "The 8-Minute Takeover"
# =============================================================================
# This script checks prerequisites, creates a Python virtual environment,
# installs dependencies, and deploys the lab infrastructure.
#
# Usage: ./setup.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"
ATTACK_DIR="${SCRIPT_DIR}/attack"

echo -e "${CYAN}"
echo "============================================="
echo "  The 8-Minute Takeover -- Lab Setup"
echo "============================================="
echo -e "${NC}"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

echo -e "${CYAN}[1/8] Pre-flight checks...${NC}"

# Check Terraform
if ! command -v terraform &> /dev/null; then
    echo -e "${RED}ERROR: Terraform not found. Install Terraform >= 1.10.0${NC}"
    echo "  https://developer.hashicorp.com/terraform/install"
    exit 1
fi
TF_VERSION=$(terraform version -json | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1 | grep -oP 'v\K[0-9.]+')
echo -e "  Terraform: ${GREEN}${TF_VERSION}${NC}"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}ERROR: AWS CLI not found. Install AWS CLI v2${NC}"
    echo "  https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
    exit 1
fi
AWS_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
echo -e "  AWS CLI: ${GREEN}${AWS_VERSION}${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 not found. Install Python >= 3.10${NC}"
    exit 1
fi
PY_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "  Python: ${GREEN}${PY_VERSION}${NC}"

# Check AWS credentials
echo -e "\n${CYAN}[2/8] Verifying AWS credentials...${NC}"
CALLER_IDENTITY=$(aws sts get-caller-identity 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: AWS credentials not configured or invalid${NC}"
    echo "  Run: aws configure"
    exit 1
fi
ACCOUNT_ID=$(echo "${CALLER_IDENTITY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
IDENTITY_ARN=$(echo "${CALLER_IDENTITY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
echo -e "  Account: ${GREEN}${ACCOUNT_ID}${NC}"
echo -e "  Identity: ${GREEN}${IDENTITY_ARN}${NC}"
echo -e "${YELLOW}  WARNING: Verify this is a LAB account, not production!${NC}"

# =============================================================================
# CHECK S3 BLOCK PUBLIC ACCESS
# =============================================================================

echo -e "\n${CYAN}[3/8] Checking account-level S3 Block Public Access...${NC}"
BPA_OUTPUT=$(aws s3control get-public-access-block --account-id "${ACCOUNT_ID}" 2>/dev/null || echo "NOT_SET")

if echo "${BPA_OUTPUT}" | grep -q '"true"' 2>/dev/null || echo "${BPA_OUTPUT}" | grep -q 'true' 2>/dev/null; then
    echo -e "${YELLOW}  S3 Block Public Access is ENABLED (one or more settings are true).${NC}"
    echo -e "${YELLOW}  This scenario requires a public S3 bucket.${NC}"
    echo ""
    echo -e "  To disable BPA for this lab, run:"
    echo -e "  ${CYAN}aws s3control put-public-access-block \\${NC}"
    echo -e "  ${CYAN}  --account-id ${ACCOUNT_ID} \\${NC}"
    echo -e "  ${CYAN}  --public-access-block-configuration \\${NC}"
    echo -e "  ${CYAN}    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false${NC}"
    echo ""
    read -p "  Have you disabled BPA, or do you want to continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}  Setup paused. Disable BPA and re-run this script.${NC}"
        echo -e "${YELLOW}  (You can also proceed without BPA -- the fallback method will use Terraform outputs)${NC}"
        exit 0
    fi
else
    echo -e "  ${GREEN}BPA is disabled or not set. Public bucket will work.${NC}"
fi

# =============================================================================
# PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

echo -e "\n${CYAN}[4/8] Creating Python virtual environment...${NC}"
VENV_DIR="${SCRIPT_DIR}/.venv"
if [ -d "${VENV_DIR}" ]; then
    echo -e "  Virtual environment already exists at ${VENV_DIR}"
else
    python3 -m venv "${VENV_DIR}"
    echo -e "  ${GREEN}Created: ${VENV_DIR}${NC}"
fi

# Activate
source "${VENV_DIR}/bin/activate"
echo -e "  ${GREEN}Activated virtual environment${NC}"

# =============================================================================
# INSTALL PYTHON DEPENDENCIES
# =============================================================================

echo -e "\n${CYAN}[5/8] Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r "${ATTACK_DIR}/requirements.txt"
echo -e "  ${GREEN}Dependencies installed${NC}"

# =============================================================================
# TERRAFORM CONFIGURATION
# =============================================================================

echo -e "\n${CYAN}[6/8] Configuring Terraform...${NC}"
if [ ! -f "${TERRAFORM_DIR}/terraform.tfvars" ]; then
    if [ -f "${TERRAFORM_DIR}/terraform.tfvars.example" ]; then
        cp "${TERRAFORM_DIR}/terraform.tfvars.example" "${TERRAFORM_DIR}/terraform.tfvars"
        echo -e "  ${GREEN}Copied terraform.tfvars.example to terraform.tfvars${NC}"
        echo -e "  ${YELLOW}Review and edit terraform/terraform.tfvars if needed${NC}"
    else
        echo -e "${RED}ERROR: No terraform.tfvars.example found${NC}"
        exit 1
    fi
else
    echo -e "  terraform.tfvars already exists"
fi

# =============================================================================
# TERRAFORM INIT + APPLY
# =============================================================================

echo -e "\n${CYAN}[7/8] Running terraform init...${NC}"
cd "${TERRAFORM_DIR}"
terraform init -input=false
echo -e "  ${GREEN}Terraform initialized${NC}"

echo -e "\n${CYAN}[8/8] Deploying infrastructure (terraform apply)...${NC}"
terraform apply -auto-approve -input=false
echo -e "  ${GREEN}Infrastructure deployed!${NC}"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
BUCKET_NAME=$(terraform output -raw rag_bucket_name 2>/dev/null)
LAMBDA_NAME=$(terraform output -raw lambda_function_name 2>/dev/null)
echo -e "  S3 Bucket:       ${CYAN}${BUCKET_NAME}${NC}"
echo -e "  Lambda Function: ${CYAN}${LAMBDA_NAME}${NC}"
echo -e "  Region:          ${CYAN}$(terraform output -raw aws_region 2>/dev/null)${NC}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo -e "  ${CYAN}cd attack${NC}"
echo -e "  ${CYAN}python main.py --auto       ${NC}# Full automated attack"
echo -e "  ${CYAN}python main.py --manual     ${NC}# Manual step-by-step"
echo -e "  ${CYAN}python main.py              ${NC}# Interactive menu"
echo ""
echo -e "  ${YELLOW}When done, clean up with:${NC} ${CYAN}./cleanup.sh${NC}"
