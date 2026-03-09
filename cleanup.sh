#!/bin/bash
# =============================================================================
# cleanup.sh -- Complete Cleanup for "The 8-Minute Takeover"
# =============================================================================
# Removes all resources created during the attack and the lab.
# Handles attacker-created resources (not managed by Terraform) FIRST,
# then runs terraform destroy, and finally re-enables S3 Block Public Access.
#
# IMPORTANT: No set -e. Cleanup is best-effort -- if one step fails,
# we continue with the rest. A half-cleanup is worse than a full attempt.
#
# Usage: ./cleanup.sh
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"

ERRORS=0

echo -e "${CYAN}"
echo "============================================="
echo "  The 8-Minute Takeover -- Cleanup"
echo "============================================="
echo -e "${NC}"

# =============================================================================
# STEP 1: DELETE ATTACKER-CREATED RESOURCES (not managed by Terraform)
# =============================================================================

echo -e "${CYAN}[1/6] Deleting attacker-created resources...${NC}"

# --- Delete backdoor-admin user (created in Phase 4) ---
echo -e "  Cleaning up user: backdoor-admin"
if aws iam get-user --user-name backdoor-admin &>/dev/null; then
    # Delete all access keys first
    for KEY_ID in $(aws iam list-access-keys --user-name backdoor-admin --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
        aws iam delete-access-key --user-name backdoor-admin --access-key-id "${KEY_ID}" 2>/dev/null && \
            echo -e "    ${GREEN}Deleted access key: ${KEY_ID}${NC}" || true
    done
    # Detach policies
    aws iam detach-user-policy --user-name backdoor-admin \
        --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null && \
        echo -e "    ${GREEN}Detached AdministratorAccess${NC}" || true
    # Delete user
    if aws iam delete-user --user-name backdoor-admin 2>/dev/null; then
        echo -e "    ${GREEN}Deleted user: backdoor-admin${NC}"
    else
        echo -e "    ${RED}Failed to delete backdoor-admin (may have inline policies or other attachments)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "    ${YELLOW}User backdoor-admin does not exist (already cleaned or attack Phase 4 was not run)${NC}"
fi

# --- Delete extra access keys for frick (created by Lambda during escalation) ---
echo -e "  Cleaning up extra keys for admin user (frick)..."
if aws iam get-user --user-name frick &>/dev/null; then
    FRICK_KEYS=$(aws iam list-access-keys --user-name frick --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    KEY_COUNT=$(echo "${FRICK_KEYS}" | wc -w)

# Delete ALL keys for frick. Terraform is about to delete the user
    # anyway, and we can't reliably tell which key is Terraform's vs
    # the attacker's (AWS doesn't guarantee listing order).
    for KEY_ID in ${FRICK_KEYS}; do
        aws iam delete-access-key --user-name frick --access-key-id "${KEY_ID}" 2>/dev/null && \
            echo -e "    ${GREEN}Deleted key: ${KEY_ID}${NC}" || {
                echo -e "    ${RED}Failed to delete key: ${KEY_ID}${NC}"
                ERRORS=$((ERRORS + 1))
            }
    done
else
    echo -e "    ${YELLOW}User frick does not exist (already destroyed or not yet created)${NC}"
fi

# =============================================================================
# STEP 2: TERRAFORM DESTROY
# =============================================================================

TF_DESTROY_SUCCESS=false

echo -e "\n${CYAN}[2/6] Running terraform destroy...${NC}"
if [ -f "${TERRAFORM_DIR}/terraform.tfstate" ]; then
    cd "${TERRAFORM_DIR}"
    if terraform destroy -auto-approve -input=false; then
        echo -e "  ${GREEN}Terraform resources destroyed${NC}"
        TF_DESTROY_SUCCESS=true
    else
        echo -e "  ${RED}terraform destroy failed (see errors above)${NC}"
        echo -e "  ${YELLOW}Some resources may still exist. Check the AWS Console.${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${YELLOW}No terraform.tfstate found. Skipping terraform destroy.${NC}"
fi

# =============================================================================
# STEP 3: RE-ENABLE S3 BLOCK PUBLIC ACCESS
# =============================================================================

echo -e "\n${CYAN}[3/6] Re-enabling account-level S3 Block Public Access...${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -n "${ACCOUNT_ID}" ]; then
    if aws s3control put-public-access-block \
        --account-id "${ACCOUNT_ID}" \
        --public-access-block-configuration \
            BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true 2>/dev/null; then
        echo -e "  ${GREEN}S3 Block Public Access re-enabled (all four settings = true)${NC}"
    else
        echo -e "  ${YELLOW}Could not re-enable BPA (check IAM permissions)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${YELLOW}Could not determine account ID. Re-enable BPA manually in the S3 Console.${NC}"
    ERRORS=$((ERRORS + 1))
fi

# =============================================================================
# STEP 4: CLEAN UP LOCAL ARTIFACTS
# =============================================================================

echo -e "\n${CYAN}[4/6] Cleaning up local artifacts...${NC}"

rm -f "${SCRIPT_DIR}/logs/.attack-progress.json" 2>/dev/null || true
rm -rf "${TERRAFORM_DIR}/.terraform" 2>/dev/null && echo -e "  ${GREEN}Removed .terraform/${NC}" || true
# Only delete state files if terraform destroy succeeded
if [ "${TF_DESTROY_SUCCESS}" = true ]; then
    rm -f "${TERRAFORM_DIR}/terraform.tfstate" 2>/dev/null && echo -e "  ${GREEN}Removed terraform.tfstate${NC}" || true
    rm -f "${TERRAFORM_DIR}/terraform.tfstate.backup" 2>/dev/null && echo -e "  ${GREEN}Removed terraform.tfstate.backup${NC}" || true
else
    echo -e "  ${YELLOW}Keeping terraform.tfstate (destroy had errors -- you may need to re-run)${NC}"
fi
rm -f "${TERRAFORM_DIR}/.terraform.lock.hcl" 2>/dev/null && echo -e "  ${GREEN}Removed .terraform.lock.hcl${NC}" || true
rm -f "${TERRAFORM_DIR}/lambda/ec2_init.zip" 2>/dev/null && echo -e "  ${GREEN}Removed lambda zip${NC}" || true
find "${SCRIPT_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
rm -f /tmp/lambda_output.json /tmp/ec2_init.py /tmp/ec2_init.zip 2>/dev/null || true
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
# STEP 6: VERIFICATION CHECKLIST
# =============================================================================

echo -e "\n${CYAN}[6/6] Verification checklist${NC}"
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

if [ ${ERRORS} -gt 0 ]; then
    echo -e "${YELLOW}=============================================${NC}"
    echo -e "${YELLOW}  Cleanup finished with ${ERRORS} warning(s).${NC}"
    echo -e "${YELLOW}  Check the output above and verify manually.${NC}"
    echo -e "${YELLOW}=============================================${NC}"
else
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}  Cleanup Complete!${NC}"
    echo -e "${GREEN}=============================================${NC}"
fi
