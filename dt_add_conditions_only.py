#!/usr/bin/env python3
"""
Dependency-Track Add Conditions Script

Adds PURL conditions to an existing policy. Use this after creating a policy
manually through the Dependency-Track web interface.

Usage:
    python dt_add_conditions_only.py
"""

import os
import sys
import json
import requests
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin

# Configuration
DT_BASE_URL = os.environ.get("DT_URL", os.environ.get("DT_BASE_URL", "http://localhost:8080"))
DT_API_KEY = os.environ.get("DT_API_KEY")
LIST_FILE = os.environ.get("LIST_FILE", "list_shai.txt")
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

def parse_package_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Parse a package line from the list file."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # Remove quotes if present
    line = line.strip('"')
    
    # Handle different package formats
    if '@' not in line:
        return None
    
    # Split name and version
    parts = line.rsplit('@', 1)
    if len(parts) != 2:
        return None
    
    name, version = parts
    
    # Skip .x versions as they're not concrete
    if version.endswith('.x'):
        return None
    
    # Determine package type and construct PURL
    if '/' in name:
        # Scoped package (e.g., @scope/package or user/package)
        if name.startswith('@'):
            # NPM scoped package
            purl = f"pkg:npm/{name}@{version}"
        else:
            # GitHub-style package
            purl = f"pkg:github/{name}@{version}"
    else:
        # Regular NPM package
        purl = f"pkg:npm/{name}@{version}"
    
    return (name, version, purl)

def load_packages(file_path: str) -> List[Tuple[str, str, str]]:
    """Load packages from the list file."""
    packages = []
    skipped = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                parsed = parse_package_line(line)
                if parsed:
                    packages.append(parsed)
                else:
                    if line.strip() and not line.strip().startswith('#'):
                        skipped += 1
                        if skipped <= 5:  # Show first 5 skipped lines
                            log_warn(f"Line {line_num}: {line.strip()}")
                        elif skipped == 6:
                            log_warn("... (more skipped lines)")
    
    except FileNotFoundError:
        log_error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error reading file: {e}")
        sys.exit(1)
    
    log_info(f"Loaded {len(packages)} concrete packages (skipped {skipped} lines)")
    return packages

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

def find_policy() -> Optional[Dict]:
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

def add_purl_condition(policy_uuid: str, purl: str) -> bool:
    """Add a PURL condition to the policy."""
    condition_data = {
        "subject": "PACKAGE_URL",
        "operator": "MATCHES",
        "value": purl
    }
    
    response = make_dt_request("PUT", f"/api/v1/policy/{policy_uuid}/condition", condition_data)
    
    if response.status_code in (200, 201):
        return True
    else:
        log_error(f"Failed to add condition for {purl}: {response.status_code} - {response.text}")
        return False

def main():
    """Main function."""
    if not DT_API_KEY:
        log_error("DT_API_KEY environment variable is required")
        sys.exit(1)
    
    if DRY_RUN:
        log_warn("DRY RUN MODE - No actual changes will be made")
    
    log_info(f"Dependency-Track URL: {DT_BASE_URL}")
    log_info(f"Policy name: {POLICY_NAME}")
    log_info(f"Package list file: {LIST_FILE}")
    
    # Find the policy
    policy = find_policy()
    if not policy:
        log_error(f"Policy '{POLICY_NAME}' not found")
        log_info("Please create the policy manually through the Dependency-Track web interface first")
        log_info("Go to: Administration > Policies > Create Policy")
        log_info("Set Name: 'Shai-Hulud Blocklist'")
        log_info("Set Operator: 'Any'")
        log_info("Set Violation State: 'Fail'")
        sys.exit(1)
    
    policy_uuid = policy.get("uuid")
    log_info(f"Found policy: {policy.get('name')} (UUID: {policy_uuid})")
    
    # Load packages
    packages = load_packages(LIST_FILE)
    if not packages:
        log_error("No valid packages found in the list file")
        sys.exit(1)
    
    # Show sample packages
    log_info("Sample packages:")
    for i, (name, version, purl) in enumerate(packages[:5]):
        print(f"  {i+1}. {name}@{version} → {purl}")
    if len(packages) > 5:
        print(f"  ... and {len(packages) - 5} more")
    
    # Add conditions
    log_info(f"Adding {len(packages)} PURL conditions...")
    success_count = 0
    failed_count = 0
    
    for i, (name, version, purl) in enumerate(packages, 1):
        if add_purl_condition(policy_uuid, purl):
            success_count += 1
            if i <= 10 or i % 100 == 0:  # Show progress for first 10 and every 100
                log_ok(f"Added condition {i}/{len(packages)}: {purl}")
        else:
            failed_count += 1
    
    # Summary
    log_info("Summary:")
    log_ok(f"Policy: {policy.get('name')} (UUID: {policy_uuid})")
    log_ok(f"Conditions added: {success_count}")
    if failed_count > 0:
        log_error(f"Failed conditions: {failed_count}")
    
    if DRY_RUN:
        log_warn("This was a dry run - no actual changes were made")
        log_info("Run without DRY_RUN=true to add the actual conditions")
    else:
        log_ok("Conditions added successfully!")

if __name__ == "__main__":
    main()
