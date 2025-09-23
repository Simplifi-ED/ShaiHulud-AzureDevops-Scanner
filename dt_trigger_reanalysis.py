#!/usr/bin/env python3
"""
Dependency-Track Reanalysis Trigger

Triggers reanalysis of projects to apply new policy conditions.
This will force Dependency-Track to re-evaluate all components against
the updated Shai-Hulud policy.

Usage:
    python dt_trigger_reanalysis.py [project_name_pattern]

Examples:
    python dt_trigger_reanalysis.py                    # Reanalyze all projects
    python dt_trigger_reanalysis.py "Loop_"            # Reanalyze projects starting with "Loop_"
    python dt_trigger_reanalysis.py "specific-project" # Reanalyze specific project
"""

import os
import sys
import json
import requests
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin

# Configuration
DT_BASE_URL = os.environ.get("DT_URL", os.environ.get("DT_BASE_URL", "http://localhost:8080"))
DT_API_KEY = os.environ.get("DT_API_KEY")
PROJECT_PATTERN = sys.argv[1] if len(sys.argv) > 1 else None
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

def get_projects() -> List[Dict]:
    """Get all projects from Dependency-Track."""
    response = make_dt_request("GET", "/api/v1/project")
    
    if response.status_code == 200:
        projects = response.json()
        if PROJECT_PATTERN:
            filtered_projects = [p for p in projects if PROJECT_PATTERN in p.get("name", "")]
            log_info(f"Filtered to {len(filtered_projects)} projects matching pattern '{PROJECT_PATTERN}'")
            return filtered_projects
        return projects
    else:
        log_error(f"Failed to get projects: {response.status_code} - {response.text}")
        return []

def trigger_analysis(project_uuid: str, project_name: str) -> bool:
    """Trigger vulnerability analysis for a project."""
    response = make_dt_request("POST", f"/api/v1/finding/project/{project_uuid}/analyze")
    
    if response.status_code == 200:
        result = response.json()
        token = result.get("token", "unknown")
        log_ok(f"Analysis triggered for {project_name} (token: {token})")
        return True
    else:
        log_error(f"Failed to trigger analysis for {project_name}: {response.status_code} - {response.text}")
        return False

def refresh_metrics(project_uuid: str, project_name: str) -> bool:
    """Refresh metrics for a project."""
    response = make_dt_request("GET", f"/api/v1/metrics/project/{project_uuid}/refresh")
    
    if response.status_code == 200:
        log_ok(f"Metrics refresh requested for {project_name}")
        return True
    else:
        log_error(f"Failed to refresh metrics for {project_name}: {response.status_code} - {response.text}")
        return False

def check_analysis_progress(token: str) -> Dict:
    """Check the progress of an analysis."""
    response = make_dt_request("GET", f"/api/v1/bom/token/{token}")
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"processing": False, "status": "error"}

def main():
    """Main function."""
    if not DT_API_KEY:
        log_error("DT_API_KEY environment variable is required")
        sys.exit(1)
    
    if DRY_RUN:
        log_warn("DRY RUN MODE - No actual changes will be made")
    
    log_info(f"Dependency-Track URL: {DT_BASE_URL}")
    if PROJECT_PATTERN:
        log_info(f"Project pattern: {PROJECT_PATTERN}")
    else:
        log_info("Project pattern: All projects")
    
    # Get projects
    projects = get_projects()
    if not projects:
        log_error("No projects found")
        sys.exit(1)
    
    log_info(f"Found {len(projects)} projects to reanalyze")
    
    # Show sample projects
    log_info("Sample projects:")
    for i, project in enumerate(projects[:5]):
        print(f"  {i+1}. {project.get('name')} (v{project.get('version', 'unknown')})")
    if len(projects) > 5:
        print(f"  ... and {len(projects) - 5} more")
    
    # Trigger analysis for each project
    success_count = 0
    failed_count = 0
    analysis_tokens = []
    
    log_info("Triggering analysis for all projects...")
    
    for i, project in enumerate(projects, 1):
        project_name = project.get("name", "unknown")
        project_uuid = project.get("uuid")
        project_version = project.get("version", "unknown")
        
        if not project_uuid:
            log_error(f"Project {project_name} has no UUID, skipping")
            failed_count += 1
            continue
        
        log_info(f"Processing {i}/{len(projects)}: {project_name} (v{project_version})")
        
        # Trigger analysis
        if trigger_analysis(project_uuid, project_name):
            success_count += 1
            # Refresh metrics as well
            refresh_metrics(project_uuid, project_name)
        else:
            failed_count += 1
    
    # Summary
    log_info("Summary:")
    log_ok(f"Projects processed: {len(projects)}")
    log_ok(f"Analysis triggered: {success_count}")
    if failed_count > 0:
        log_error(f"Failed: {failed_count}")
    
    if DRY_RUN:
        log_warn("This was a dry run - no actual analysis was triggered")
        log_info("Run without DRY_RUN=true to trigger actual reanalysis")
    else:
        log_ok("Reanalysis triggered successfully!")
        log_info("Note: Analysis may take several minutes to complete")
        log_info("Check the Dependency-Track web interface for progress")

if __name__ == "__main__":
    main()
