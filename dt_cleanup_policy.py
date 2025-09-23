#!/usr/bin/env python3
"""
Dependency-Track Policy Cleanup Script

Cleans up the Shai-Hulud policy by:
1. Removing duplicate conditions
2. Ensuring consistent operators (IS for exact matches)
3. Fixing URL encoding issues

Usage:
    python dt_cleanup_policy.py
"""

import os
import sys
import json
import requests
from typing import List, Dict, Set
from urllib.parse import urljoin

# Configuration
DT_BASE_URL = os.environ.get("DT_URL", os.environ.get("DT_BASE_URL", "http://localhost:8080"))
DT_API_KEY = os.environ.get("DT_API_KEY")
POLICY_NAME = os.environ.get("POLICY_NAME", "Shai-Hulud Blocklist")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() in ("true", "1", "yes")

# Colors for output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_info(msg: str):
    print(f"{Colors.BLUE}ℹ️  {msg}{Colors.END}")

def log_ok(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")

def log_warn(msg: str):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.END}")

def log_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.END}")

def make_dt_request(method: str, endpoint: str, data: Dict = None) -> requests.Response:
    """Make a request to Dependency-Track API."""
    url = urljoin(DT_BASE_URL, endpoint)
    headers = {
        "X-Api-Key": DT_API_KEY,
        "Content-Type": "application/json"
    }
    
    if DRY_RUN:
        log_info(f"DRY RUN: {method} {url}")
        if data:
            log_info(f"DRY RUN: Data: {json.dumps(data, indent=2)}")
        # Return a mock response
        class MockResponse:
            def __init__(self):
                self.status_code = 200
                self.text = '{"success": true}'
            def json(self):
                if endpoint == "/api/v1/policy":
                    return [{"name": "Block Shai-Hulud IOCs", "uuid": "mock-uuid", "policyConditions": []}]
                return {"success": True}
        return MockResponse()
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=30)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=30)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=30)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response
    except requests.exceptions.RequestException as e:
        log_error(f"Request failed: {e}")
        raise

def find_policy() -> Dict:
    """Find the policy by name."""
    response = make_dt_request("GET", "/api/v1/policy")
    
    if response.status_code == 200:
        policies = response.json()
        for policy in policies:
            if policy.get("name") == POLICY_NAME:
                return policy
        
        # Try to find similar policy
        for policy in policies:
            if "shai" in policy.get("name", "").lower() or "hulud" in policy.get("name", "").lower():
                log_info(f"Found similar policy: {policy.get('name')}")
                return policy
    
    return None

def cleanup_conditions(policy: Dict) -> List[Dict]:
    """Clean up policy conditions by removing duplicates and fixing issues."""
    conditions = policy.get("policyConditions", [])
    seen_purls: Set[str] = set()
    cleaned_conditions = []
    
    log_info(f"Processing {len(conditions)} conditions...")
    
    for condition in conditions:
        purl = condition.get("value", "")
        operator = condition.get("operator", "")
        
        # Fix URL encoding issues
        if "%40" in purl:
            purl = purl.replace("%40", "@")
            log_warn(f"Fixed URL encoding: {condition.get('value')} → {purl}")
        
        # Skip duplicates
        if purl in seen_purls:
            log_warn(f"Skipping duplicate: {purl}")
            continue
        
        # Ensure consistent operator (IS for exact matches)
        if operator == "MATCHES" and not any(char in purl for char in ["*", ".", "^", "$", "+", "?", "[", "]", "(", ")", "{", "}", "|", "\\"]):
            operator = "IS"
            log_warn(f"Changed operator from MATCHES to IS for: {purl}")
        
        seen_purls.add(purl)
        cleaned_conditions.append({
            "subject": "PACKAGE_URL",
            "operator": operator,
            "value": purl
        })
    
    log_info(f"Cleaned up to {len(cleaned_conditions)} unique conditions")
    return cleaned_conditions

def delete_condition(policy_uuid: str, condition_uuid: str) -> bool:
    """Delete a specific condition."""
    response = make_dt_request("DELETE", f"/api/v1/policy/{policy_uuid}/condition/{condition_uuid}")
    return response.status_code in (200, 204)

def add_condition(policy_uuid: str, condition: Dict) -> bool:
    """Add a new condition."""
    response = make_dt_request("PUT", f"/api/v1/policy/{policy_uuid}/condition", condition)
    return response.status_code in (200, 201)

def main():
    """Main function."""
    if not DT_API_KEY:
        log_error("DT_API_KEY environment variable is required")
        sys.exit(1)
    
    if DRY_RUN:
        log_warn("DRY RUN MODE - No actual changes will be made")
    
    log_info(f"Dependency-Track URL: {DT_BASE_URL}")
    log_info(f"Policy name: {POLICY_NAME}")
    
    # Find the policy
    policy = find_policy()
    if not policy:
        log_error(f"Policy '{POLICY_NAME}' not found")
        sys.exit(1)
    
    policy_uuid = policy.get("uuid")
    log_info(f"Found policy: {policy.get('name')} (UUID: {policy_uuid})")
    
    # Clean up conditions
    cleaned_conditions = cleanup_conditions(policy)
    
    if DRY_RUN:
        log_info("DRY RUN: Would clean up conditions")
        log_info(f"DRY RUN: Original: {len(policy.get('policyConditions', []))} conditions")
        log_info(f"DRY RUN: Cleaned: {len(cleaned_conditions)} conditions")
        return
    
    # Delete all existing conditions
    log_info("Deleting existing conditions...")
    existing_conditions = policy.get("policyConditions", [])
    deleted_count = 0
    
    for condition in existing_conditions:
        condition_uuid = condition.get("uuid")
        if condition_uuid and delete_condition(policy_uuid, condition_uuid):
            deleted_count += 1
    
    log_ok(f"Deleted {deleted_count} existing conditions")
    
    # Add cleaned conditions
    log_info("Adding cleaned conditions...")
    added_count = 0
    
    for i, condition in enumerate(cleaned_conditions, 1):
        if add_condition(policy_uuid, condition):
            added_count += 1
            if i <= 10 or i % 100 == 0:
                log_ok(f"Added condition {i}/{len(cleaned_conditions)}: {condition['value']}")
    
    # Summary
    log_info("Summary:")
    log_ok(f"Policy: {policy.get('name')} (UUID: {policy_uuid})")
    log_ok(f"Original conditions: {len(existing_conditions)}")
    log_ok(f"Cleaned conditions: {len(cleaned_conditions)}")
    log_ok(f"Conditions added: {added_count}")
    
    if added_count == len(cleaned_conditions):
        log_ok("Policy cleanup completed successfully!")
    else:
        log_error(f"Some conditions failed to add: {len(cleaned_conditions) - added_count}")

if __name__ == "__main__":
    main()
