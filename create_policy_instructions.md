# How to Create Shai-Hulud Policy in Dependency-Track

Since the Dependency-Track API doesn't support creating policies via POST requests, you need to create the policy manually through the web interface.

## Step 1: Create the Policy Manually

1. **Open Dependency-Track Web Interface**
   - Go to: `http://localhost:8081`
   - Login with your admin credentials

2. **Navigate to Policies**
   - Click on "Administration" in the top menu
   - Click on "Policies" in the left sidebar

3. **Create New Policy**
   - Click the "Create Policy" button (usually a "+" or "New" button)
   - Fill in the form with these exact values:
     - **Name**: `Shai-Hulud Blocklist`
     - **Operator**: `Any`
     - **Violation State**: `Fail`
     - **Policy Type**: `Operational` (if available)
     - **Global**: `Yes` (if available)
   - Click "Save" or "Create"

## Step 2: Add Conditions Automatically

Once the policy is created, run this command to add all 570 PURL conditions:

```bash
uv run --env-file .env.dt dt_add_conditions_only.py
```

This script will:
- ✅ Find your newly created policy
- ✅ Add all 570 PURL conditions with "MATCHES" operator
- ✅ Show progress and handle any errors

## Step 3: Verify the Policy

After running the script, you can verify the policy in the web interface:
- Go back to Administration → Policies
- Click on "Shai-Hulud Blocklist"
- You should see 570 conditions listed
- Each condition should have:
  - Subject: "Package URL (PURL)"
  - Operator: "matches"
  - Value: A PURL like `pkg:npm/package@version`

## Troubleshooting

If the script can't find your policy:
1. Make sure the policy name is exactly `Shai-Hulud Blocklist`
2. Check that the policy was saved successfully
3. Try running: `POLICY_NAME="your-exact-policy-name" uv run --env-file .env.dt dt_add_conditions_only.py`

## Alternative: Use Different Policy Name

If you want to use a different name, create the policy with your preferred name and run:
```bash
POLICY_NAME="Your Policy Name" uv run --env-file .env.dt dt_add_conditions_only.py
```
