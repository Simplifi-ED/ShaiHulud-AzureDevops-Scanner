#!/bin/bash
# Dependency-Track Shai-Hulud Policy Creator (Shell version)
#
# Creates a Dependency-Track policy with PURL conditions based on the packages
# listed in list_shai.txt. Handles both exact versions and .x version ranges.
#
# Usage:
#     ./dt_create_shai_policy.sh
#
# Environment variables:
#     DT_BASE_URL: Dependency-Track base URL (default: http://localhost:8080)
#     DT_API_KEY: Dependency-Track API key (required)
#     LIST_FILE: Path to the package list file (default: list_shai.txt)
#     POLICY_NAME: Name of the policy to create (default: "Shai-Hulud Blocklist")
#     DRY_RUN: If true, only show what would be done (default: false)

set -euo pipefail

# Configuration
DT_BASE_URL="${DT_URL:-${DT_BASE_URL:-http://localhost:8080}}"
DT_API_KEY="${DT_API_KEY:-}"
LIST_FILE="${LIST_FILE:-list_shai.txt}"
POLICY_NAME="${POLICY_NAME:-Shai-Hulud Blocklist}"
DRY_RUN="${DRY_RUN:-false}"

# Colors
BLUE='\033[94m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
END='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${END}"; }
log_ok() { echo -e "${GREEN}✅ $1${END}"; }
log_warn() { echo -e "${YELLOW}⚠️  $1${END}"; }
log_error() { echo -e "${RED}❌ $1${END}"; }
log_skip() { echo -e "${YELLOW}⏭️  $1${END}"; }

# Check requirements
if [[ -z "$DT_API_KEY" ]]; then
    log_error "DT_API_KEY environment variable is required"
    exit 1
fi

if [[ ! -f "$LIST_FILE" ]]; then
    log_error "Package list file not found: $LIST_FILE"
    exit 1
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY RUN MODE - No actual changes will be made"
fi

log_info "Dependency-Track URL: $DT_BASE_URL"
log_info "Policy name: $POLICY_NAME"
log_info "Package list file: $LIST_FILE"

# Parse packages and filter out .x versions
TEMP_PACKAGES=$(mktemp)
TEMP_PURLS=$(mktemp)

log_info "Parsing packages from $LIST_FILE..."

while IFS= read -r line; do
    # Skip empty lines and comments
    line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ -z "$line" || "$line" =~ ^# ]]; then
        continue
    fi
    
    # Remove quotes
    line=$(echo "$line" | sed 's/^"//;s/"$//')
    
    # Check if line contains @
    if [[ "$line" =~ @ ]]; then
        # Extract name and version
        name=$(echo "$line" | sed 's/@.*$//')
        version=$(echo "$line" | sed 's/^[^@]*@//')
        
        # Skip .x versions
        if [[ "$version" =~ \.x$ ]]; then
            log_skip "Skipping .x version: $line"
            continue
        fi
        
        # Determine PURL format
        if [[ "$name" =~ ^@ ]]; then
            # NPM scoped package
            purl="pkg:npm/$name@$version"
        elif [[ "$name" =~ / ]]; then
            # GitHub-style package
            purl="pkg:github/$name@$version"
        else
            # Regular NPM package
            purl="pkg:npm/$name@$version"
        fi
        
        echo "$name@$version" >> "$TEMP_PACKAGES"
        echo "$purl" >> "$TEMP_PURLS"
    fi
done < "$LIST_FILE"

PACKAGE_COUNT=$(wc -l < "$TEMP_PACKAGES")
log_info "Found $PACKAGE_COUNT concrete packages"

if [[ $PACKAGE_COUNT -eq 0 ]]; then
    log_error "No valid packages found in the list file"
    rm -f "$TEMP_PACKAGES" "$TEMP_PURLS"
    exit 1
fi

# Show sample packages
log_info "Sample packages:"
head -5 "$TEMP_PACKAGES" | nl -nln
if [[ $PACKAGE_COUNT -gt 5 ]]; then
    echo "  ... and $((PACKAGE_COUNT - 5)) more"
fi

# Find or create policy
log_info "Looking for existing policy: $POLICY_NAME"

if [[ "$DRY_RUN" == "true" ]]; then
    log_info "DRY RUN: Would check for existing policy"
    POLICY_UUID="mock-uuid"
else
    # Check if policy already exists
    EXISTING_POLICIES=$(curl -s -H "X-Api-Key: $DT_API_KEY" "$DT_BASE_URL/api/v1/policy")
    POLICY_UUID=$(echo "$EXISTING_POLICIES" | jq -r ".[] | select(.name == \"$POLICY_NAME\") | .uuid // empty")
    
    if [[ -n "$POLICY_UUID" && "$POLICY_UUID" != "null" ]]; then
        log_info "Policy '$POLICY_NAME' already exists with UUID: $POLICY_UUID"
    else
        log_info "Creating policy: $POLICY_NAME"
        
        POLICY_DATA=$(cat <<EOF
{
    "name": "$POLICY_NAME",
    "violationState": "FAIL",
    "operator": "ANY"
}
EOF
)
        
        POLICY_RESPONSE=$(curl -s -X POST "$DT_BASE_URL/api/v1/policy" \
            -H "X-Api-Key: $DT_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$POLICY_DATA")
        
        POLICY_UUID=$(echo "$POLICY_RESPONSE" | jq -r '.uuid // empty')
        
        if [[ -z "$POLICY_UUID" || "$POLICY_UUID" == "null" ]]; then
            log_error "Failed to create policy: $POLICY_RESPONSE"
            log_info "Trying to find existing policy with similar name..."
            
            # Try to find a policy with similar name
            POLICY_UUID=$(echo "$EXISTING_POLICIES" | jq -r ".[] | select(.name | ascii_downcase | contains(\"shai\") or contains(\"hulud\")) | .uuid // empty" | head -1)
            
            if [[ -n "$POLICY_UUID" && "$POLICY_UUID" != "null" ]]; then
                POLICY_NAME_FOUND=$(echo "$EXISTING_POLICIES" | jq -r ".[] | select(.uuid == \"$POLICY_UUID\") | .name")
                log_info "Found similar policy: $POLICY_NAME_FOUND (UUID: $POLICY_UUID)"
            else
                log_error "No suitable policy found"
                rm -f "$TEMP_PACKAGES" "$TEMP_PURLS"
                exit 1
            fi
        else
            log_ok "Policy created with UUID: $POLICY_UUID"
        fi
    fi
fi

# Add PURL conditions
log_info "Adding $PACKAGE_COUNT PURL conditions..."

SUCCESS_COUNT=0
FAILED_COUNT=0
CURRENT=0

while IFS= read -r purl; do
    CURRENT=$((CURRENT + 1))
    
    CONDITION_DATA=$(cat <<EOF
{
    "subject": "PACKAGE_URL",
    "operator": "IS",
    "value": "$purl"
}
EOF
)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would add condition $CURRENT/$PACKAGE_COUNT: $purl"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        CONDITION_RESPONSE=$(curl -s -X PUT "$DT_BASE_URL/api/v1/policy/$POLICY_UUID/condition" \
            -H "X-Api-Key: $DT_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$CONDITION_DATA")
        
        if [[ "$CONDITION_RESPONSE" =~ "uuid" ]]; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            if [[ $CURRENT -le 10 ]] || [[ $((CURRENT % 100)) -eq 0 ]]; then
                log_ok "Added condition $CURRENT/$PACKAGE_COUNT: $purl"
            fi
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
            log_error "Failed to add condition for $purl: $CONDITION_RESPONSE"
        fi
    fi
done < "$TEMP_PURLS"

# Summary
log_info "Summary:"
log_ok "Policy created: $POLICY_NAME (UUID: $POLICY_UUID)"
log_ok "Conditions added: $SUCCESS_COUNT"
if [[ $FAILED_COUNT -gt 0 ]]; then
    log_error "Failed conditions: $FAILED_COUNT"
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "This was a dry run - no actual changes were made"
    log_info "Run without DRY_RUN=true to create the actual policy"
else
    log_ok "Policy creation completed successfully!"
fi

# Cleanup
rm -f "$TEMP_PACKAGES" "$TEMP_PURLS"
