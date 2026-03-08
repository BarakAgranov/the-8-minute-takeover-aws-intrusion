#!/bin/bash
# =============================================================================
# setup.sh -- One-Command Setup for "The 8-Minute Takeover"
# =============================================================================
# Checks prerequisites, configures the environment, and deploys infrastructure.
# Handles errors gracefully and offers to fix problems automatically.
#
# Usage: ./setup.sh
# Safe to re-run: detects partial state and picks up where it left off.
# =============================================================================

# No set -e. Every error is caught explicitly with helpful messages.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"
ATTACK_DIR="${SCRIPT_DIR}/attack"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo -e "${CYAN}"
echo "============================================="
echo "  The 8-Minute Takeover -- Lab Setup"
echo "============================================="
echo -e "${NC}"

# =============================================================================
# [1/8] PRE-FLIGHT CHECKS
# =============================================================================

echo -e "${CYAN}[1/8] Pre-flight checks...${NC}"

# Check Terraform
if ! command -v terraform &> /dev/null; then
    echo -e "${RED}ERROR: Terraform not found. Install Terraform >= 1.10.0${NC}"
    echo "  https://developer.hashicorp.com/terraform/install"
    exit 1
fi
TF_VERSION=$(terraform version | head -1 | sed 's/[^0-9.]//g')
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
    echo -e "${RED}ERROR: Python 3 not found. Install Python >= 3.8${NC}"
    exit 1
fi
PY_VERSION=$(python3 --version | cut -d' ' -f2)
PY_MINOR=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  Python: ${GREEN}${PY_VERSION}${NC}"

# =============================================================================
# [2/8] VERIFY AWS CREDENTIALS
# =============================================================================

echo -e "\n${CYAN}[2/8] Verifying AWS credentials...${NC}"

CALLER_IDENTITY=$(aws sts get-caller-identity 2>&1) || true

if echo "${CALLER_IDENTITY}" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    ACCOUNT_ID=$(echo "${CALLER_IDENTITY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
    IDENTITY_ARN=$(echo "${CALLER_IDENTITY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
    echo -e "  Account: ${GREEN}${ACCOUNT_ID}${NC}"
    echo -e "  Identity: ${GREEN}${IDENTITY_ARN}${NC}"
    echo -e "${YELLOW}  WARNING: Verify this is a LAB account, not production!${NC}"
else
    echo -e "${RED}ERROR: AWS credentials not configured or invalid${NC}"
    echo -e "${RED}  ${CALLER_IDENTITY}${NC}"
    echo ""
    echo "  Fix: run 'aws configure' or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
    exit 1
fi

# =============================================================================
# [3/8] CHECK S3 BLOCK PUBLIC ACCESS
# =============================================================================

echo -e "\n${CYAN}[3/8] Checking account-level S3 Block Public Access...${NC}"
BPA_OUTPUT=$(aws s3control get-public-access-block --account-id "${ACCOUNT_ID}" 2>/dev/null || echo "NOT_SET")

if echo "${BPA_OUTPUT}" | grep -q 'true' 2>/dev/null; then
    echo -e "${YELLOW}  S3 Block Public Access is ENABLED.${NC}"
    echo -e "${YELLOW}  This scenario requires a public S3 bucket.${NC}"
    echo ""
    read -p "  Disable BPA for this lab account? (cleanup.sh will re-enable it) [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if aws s3control put-public-access-block \
            --account-id "${ACCOUNT_ID}" \
            --public-access-block-configuration \
            BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false 2>&1; then
            echo -e "  ${GREEN}BPA disabled successfully${NC}"
        else
            echo -e "${RED}  Failed to disable BPA. Check your IAM permissions.${NC}"
            echo ""
            echo "  You can continue anyway -- the attack scripts have a fallback that"
            echo "  reads credentials from Terraform outputs instead of the public bucket."
            echo ""
            read -p "  Continue without public bucket access? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        echo ""
        echo -e "${RED}  Cannot continue. Terraform needs BPA disabled to create the public bucket policy.${NC}"
        echo -e "${YELLOW}  Re-run ./setup.sh and choose 'y' when prompted.${NC}"
        exit 1
    fi
else
    echo -e "  ${GREEN}BPA is already disabled. Public bucket will work.${NC}"
fi

# =============================================================================
# [4/8] PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

echo -e "\n${CYAN}[4/8] Creating Python virtual environment...${NC}"

# Auto-fix: broken venv from a previous failed run
if [ -d "${VENV_DIR}" ] && [ ! -f "${VENV_DIR}/bin/activate" ]; then
    echo -e "${YELLOW}  Broken .venv detected. Cleaning up and recreating...${NC}"
    rm -rf "${VENV_DIR}"
fi

if [ -d "${VENV_DIR}" ] && [ -f "${VENV_DIR}/bin/activate" ]; then
    echo -e "  Virtual environment already exists and looks healthy"
else
    VENV_OUTPUT=$(python3 -m venv "${VENV_DIR}" 2>&1) || true

    if [ ! -f "${VENV_DIR}/bin/activate" ]; then
        # Check if it is the ensurepip problem
        if echo "${VENV_OUTPUT}" | grep -qi "ensurepip"; then
            echo -e "${YELLOW}  python${PY_MINOR}-venv package is missing (needed to create virtual environments).${NC}"
            echo ""
            read -p "  Install it now? (requires sudo) [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if sudo apt install -y "python${PY_MINOR}-venv"; then
                    echo -e "  ${GREEN}Installed python${PY_MINOR}-venv${NC}"
                    # Retry venv creation
                    rm -rf "${VENV_DIR}"
                    if python3 -m venv "${VENV_DIR}"; then
                        echo -e "  ${GREEN}Created: ${VENV_DIR}${NC}"
                    else
                        echo -e "${RED}ERROR: venv creation still failing after installing python${PY_MINOR}-venv${NC}"
                        exit 1
                    fi
                else
                    echo -e "${RED}ERROR: Failed to install python${PY_MINOR}-venv${NC}"
                    echo "  Try manually: sudo apt install python${PY_MINOR}-venv"
                    exit 1
                fi
            else
                echo -e "${RED}Cannot continue without a virtual environment.${NC}"
                echo "  Install manually: sudo apt install python${PY_MINOR}-venv"
                echo "  Then re-run: ./setup.sh"
                exit 1
            fi
        else
            echo -e "${RED}ERROR: Failed to create virtual environment${NC}"
            echo -e "${RED}  ${VENV_OUTPUT}${NC}"
            exit 1
        fi
    else
        echo -e "  ${GREEN}Created: ${VENV_DIR}${NC}"
    fi
fi

source "${VENV_DIR}/bin/activate"
echo -e "  ${GREEN}Activated virtual environment${NC}"

# =============================================================================
# [5/8] INSTALL PYTHON DEPENDENCIES
# =============================================================================

echo -e "\n${CYAN}[5/8] Installing Python dependencies...${NC}"

pip install --quiet --upgrade pip 2>/dev/null || true

if ! pip install -r "${SCRIPT_DIR}/requirements.txt" 2>&1; then
    echo ""
    echo -e "${RED}ERROR: Failed to install Python dependencies${NC}"
    echo ""
    echo -e "${YELLOW}  This usually means a package version is not available for Python ${PY_VERSION}.${NC}"
    echo -e "${YELLOW}  Trying fallback: installing without version constraints...${NC}"
    echo ""
    if pip install boto3 rich; then
        echo -e "  ${GREEN}Fallback install succeeded${NC}"
    else
        echo -e "${RED}ERROR: Could not install boto3 and rich.${NC}"
        echo "  Check your internet connection and Python version."
        exit 1
    fi
fi
echo -e "  ${GREEN}Dependencies installed${NC}"

# =============================================================================
# [6/8] TERRAFORM CONFIGURATION
# =============================================================================

echo -e "\n${CYAN}[6/8] Configuring Terraform...${NC}"
if [ ! -f "${TERRAFORM_DIR}/terraform.tfvars" ]; then
    if [ -f "${TERRAFORM_DIR}/terraform.tfvars.example" ]; then
        cp "${TERRAFORM_DIR}/terraform.tfvars.example" "${TERRAFORM_DIR}/terraform.tfvars"
        echo -e "  ${GREEN}Copied terraform.tfvars.example to terraform.tfvars${NC}"
        echo -e "  ${YELLOW}Review and edit terraform/terraform.tfvars if needed${NC}"
    else
        echo -e "${RED}ERROR: No terraform.tfvars.example found in ${TERRAFORM_DIR}${NC}"
        exit 1
    fi
else
    echo -e "  terraform.tfvars already exists"
fi

# =============================================================================
# [7/8] TERRAFORM INIT
# =============================================================================

echo -e "\n${CYAN}[7/8] Running terraform init...${NC}"
cd "${TERRAFORM_DIR}"

if ! terraform init -input=false; then
    echo ""
    echo -e "${RED}ERROR: terraform init failed${NC}"
    echo ""
    echo "  Common causes:"
    echo "    - No internet (Terraform downloads providers on first init)"
    echo "    - Corrupt state (fix: rm -rf .terraform .terraform.lock.hcl)"
    exit 1
fi
echo -e "  ${GREEN}Terraform initialized${NC}"

# =============================================================================
# [8/8] TERRAFORM APPLY
# =============================================================================

echo -e "\n${CYAN}[8/8] Deploying infrastructure (terraform apply)...${NC}"

if ! terraform apply -auto-approve -input=false; then
    echo ""
    echo -e "${RED}ERROR: terraform apply failed${NC}"
    echo ""
    echo -e "${YELLOW}  Common causes:${NC}"
    echo "    - S3 bucket name collision (change project_prefix in terraform.tfvars)"
    echo "    - S3 Block Public Access still enabled at account level"
    echo "    - Insufficient IAM permissions"
    echo "    - Resources from a previous run still exist (run ./cleanup.sh first)"
    echo ""
    echo "  Check the Terraform error output above for details."
    exit 1
fi
echo -e "  ${GREEN}Infrastructure deployed!${NC}"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
BUCKET_NAME=$(terraform output -raw rag_bucket_name 2>/dev/null || echo "<unknown>")
LAMBDA_NAME=$(terraform output -raw lambda_function_name 2>/dev/null || echo "<unknown>")
REGION=$(terraform output -raw aws_region 2>/dev/null || echo "<unknown>")
echo -e "  S3 Bucket:       ${CYAN}${BUCKET_NAME}${NC}"
echo -e "  Lambda Function: ${CYAN}${LAMBDA_NAME}${NC}"
echo -e "  Region:          ${CYAN}${REGION}${NC}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo -e "  ${CYAN}cd attack${NC}"
echo -e "  ${CYAN}python main.py --auto       ${NC}# Full automated attack"
echo -e "  ${CYAN}python main.py --manual     ${NC}# Manual step-by-step"
echo -e "  ${CYAN}python main.py              ${NC}# Interactive menu"
echo ""
echo -e "  ${YELLOW}When done, clean up with:${NC} ${CYAN}./cleanup.sh${NC}"
