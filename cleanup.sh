#!/bin/bash
# =============================================================================
# cleanup.sh -- Complete Cleanup for "The 8-Minute Takeover"
# =============================================================================
# This script removes all resources created during the attack and the lab.
# It handles attacker-created resources (not managed by Terraform) FIRST,
# then runs terraform destroy, and finally re-enables S3 Block Public Access.
#
# Usage: ./cleanup.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"

echo -e "${CYAN}"
echo "============================================="
echo "  The 8-Minute Takeover -- Cleanup"
echo "============================================="
echo -e "${NC}"

# =============================================================================
# STEP 1: DELETE ATTACKER-CREATED RESOURCES (not managed by Terraform)
# =============================================================================

echo -e "${CYAN}[1/6] Deleting attacker-created resources...${NC}"

# Delete backdoor-admin user (created in Phase 4)
echo -e "  Cleaning up user: backdoor-admin"
for KEY_ID in $(aws iam list-access-keys --user-name backdoor-admin --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
    aws iam delete-access-key --user-name backdoor-admin --access-key-id "${KEY_ID}" 2>/dev/null && \
        echo -e "    ${GREEN}Deleted access key: ${KEY_ID}${NC}" || true
done
aws iam detach-user-policy --user-name backdoor-admin \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null && \
    echo -e "    ${GREEN}Detached AdministratorAccess${NC}" || true
aws iam delete-user --user-name backdoor-admin 2>/dev/null && \
    echo -e "    ${GREEN}Deleted user: backdoor-admin${NC}" || \
    echo -e "    ${YELLOW}User backdoor-admin not found (already cleaned up?)${NC}"

# Delete extra access keys for frick (created by Lambda during escalation)
echo -e "  Cleaning up extra keys for admin user (frick)..."
FRICK_KEYS=$(aws iam list-access-keys --user-name frick --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null || echo "")
if [ -n "${FRICK_KEYS}" ]; then
    # Get the Terraform-managed key from outputs (if available)
    TF_KEY=""
    if [ -f "${TERRAFORM_DIR}/terraform.tfstate" ]; then
        TF_KEY=$(cd "${TERRAFORM_DIR}" && terraform output -json compromised_access_key_id 2>/dev/null | tr -d '"' || echo "")
    fi

    KEY_COUNT=0
    for KEY_ID in ${FRICK_KEYS}; do
        KEY_COUNT=$((KEY_COUNT + 1))
    done

    if [ ${KEY_COUNT} -gt 1 ]; then
        echo -e "    ${YELLOW}Found ${KEY_COUNT} access keys for frick (1 expected from Terraform)${NC}"
        echo -e "    Deleting attacker-created keys..."
        SKIP_FIRST=true
        for KEY_ID in ${FRICK_KEYS}; do
            if [ "${SKIP_FIRST}" = true ]; then
                SKIP_FIRST=false
                echo -e "    ${CYAN}Keeping first key: ${KEY_ID} (likely Terraform-managed)${NC}"
                continue
            fi
            aws iam delete-access-key --user-name frick --access-key-id "${KEY_ID}" 2>/dev/null && \
                echo -e "    ${GREEN}Deleted attacker key: ${KEY_ID}${NC}" || true
        done
    else
        echo -e "    ${GREEN}Only 1 key found for frick (no attacker keys to clean)${NC}"
    fi
else
    echo -e "    ${YELLOW}User frick not found (already destroyed?)${NC}"
fi

# =============================================================================
# STEP 2: TERRAFORM DESTROY
# =============================================================================

echo -e "\n${CYAN}[2/6] Running terraform destroy...${NC}"
if [ -f "${TERRAFORM_DIR}/terraform.tfstate" ]; then
    cd "${TERRAFORM_DIR}"
    terraform destroy -auto-approve -input=false
    echo -e "  ${GREEN}Terraform resources destroyed${NC}"
else
    echo -e "  ${YELLOW}No terraform.tfstate found. Skipping terraform destroy.${NC}"
fi

# =============================================================================
# STEP 3: RE-ENABLE S3 BLOCK PUBLIC ACCESS
# =============================================================================

echo -e "\n${CYAN}[3/6] Re-enabling account-level S3 Block Public Access...${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -n "${ACCOUNT_ID}" ]; then
    aws s3control put-public-access-block \
        --account-id "${ACCOUNT_ID}" \
        --public-access-block-configuration \
            BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
        2>/dev/null && \
        echo -e "  ${GREEN}S3 Block Public Access re-enabled (all four settings = true)${NC}" || \
        echo -e "  ${YELLOW}Could not re-enable BPA (may require different permissions)${NC}"
else
    echo -e "  ${YELLOW}Could not determine account ID. Re-enable BPA manually.${NC}"
fi

# =============================================================================
# STEP 4: CLEAN UP LOCAL ARTIFACTS
# =============================================================================

echo -e "\n${CYAN}[4/6] Cleaning up local artifacts...${NC}"

# Terraform artifacts
rm -rf "${TERRAFORM_DIR}/.terraform" 2>/dev/null && echo -e "  ${GREEN}Removed .terraform/${NC}" || true
rm -f "${TERRAFORM_DIR}/terraform.tfstate" 2>/dev/null && echo -e "  ${GREEN}Removed terraform.tfstate${NC}" || true
rm -f "${TERRAFORM_DIR}/terraform.tfstate.backup" 2>/dev/null && echo -e "  ${GREEN}Removed terraform.tfstate.backup${NC}" || true
rm -f "${TERRAFORM_DIR}/.terraform.lock.hcl" 2>/dev/null && echo -e "  ${GREEN}Removed .terraform.lock.hcl${NC}" || true
rm -f "${TERRAFORM_DIR}/lambda/ec2_init.zip" 2>/dev/null && echo -e "  ${GREEN}Removed lambda zip${NC}" || true

# Python cache
find "${SCRIPT_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null && \
    echo -e "  ${GREEN}Removed __pycache__ directories${NC}" || true

# Temp files from attack
rm -f /tmp/lambda_output.json 2>/dev/null || true
rm -f /tmp/ec2_init.py 2>/dev/null || true
rm -f /tmp/ec2_init.zip 2>/dev/null || true

# Virtual environment (optional -- keep if user wants to re-run)
# rm -rf "${SCRIPT_DIR}/.venv" 2>/dev/null

echo -e "  ${GREEN}Local artifacts cleaned${NC}"

# =============================================================================
# STEP 5: CLEAN UP AWS CLI ATTACKER PROFILES
# =============================================================================

echo -e "\n${CYAN}[5/6] Cleaning up AWS CLI attacker profiles...${NC}"
for PROFILE in attacker attacker-admin; do
    aws configure set aws_access_key_id "" --profile "${PROFILE}" 2>/dev/null || true
    aws configure set aws_secret_access_key "" --profile "${PROFILE}" 2>/dev/null || true
    echo -e "  ${GREEN}Cleared profile: ${PROFILE}${NC}"
done

# =============================================================================
# STEP 6: MANUAL VERIFICATION CHECKLIST
# =============================================================================

echo -e "\n${CYAN}[6/6] Manual verification checklist${NC}"
echo -e "${YELLOW}"
echo "  Log into the AWS Console and verify:"
echo ""
echo "  [ ] IAM > Users: No backdoor-admin, rag-pipeline-user, frick, or rocker"
echo "  [ ] Lambda > Functions: No EC2-init function"
echo "  [ ] S3 > Buckets: No acme-ai-rag-data-* or acme-ai-cloudtrail-* buckets"
echo "  [ ] Secrets Manager: No prod/database/* or prod/api/* secrets"
echo "  [ ] SSM Parameters: No /prod/database/* or /prod/app/* parameters"
echo "  [ ] CloudTrail: No acme-ai-attack-lab-trail trail"
echo "  [ ] EC2: No running instances (especially GPU types)"
echo "  [ ] S3 Block Public Access: Account-level BPA re-enabled"
echo -e "${NC}"

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
