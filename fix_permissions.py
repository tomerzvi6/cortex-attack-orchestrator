"""
Assign 'User Access Administrator' role to the existing Service Principal.

Uses interactive device-code auth (no Azure CLI required).
Run this once to fix the 403 errors on roleAssignments/write:

    python fix_permissions.py
"""
import json
import uuid
import urllib.request
import urllib.error
from pathlib import Path

from azure.identity import DeviceCodeCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters


def read_env():
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return {}
    result = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def main():
    env = read_env()
    tenant_id = env.get("AZURE_TENANT_ID", "").strip()
    subscription_id = env.get("AZURE_SUBSCRIPTION_ID", "").strip()
    client_id = env.get("AZURE_CLIENT_ID", "").strip()

    if not all([tenant_id, subscription_id, client_id]):
        print("ERROR: Missing AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID, or AZURE_CLIENT_ID in .env")
        return

    print("=" * 60)
    print("Fix SP Permissions — Assign User Access Administrator")
    print("=" * 60)
    print(f"  Tenant       : {tenant_id}")
    print(f"  Subscription : {subscription_id}")
    print(f"  SP Client ID : {client_id}")
    print()

    # Interactive login
    credential = DeviceCodeCredential(
        tenant_id=tenant_id,
        additionally_allowed_tenants=["*"],
    )

    # Look up the SP's object ID via Microsoft Graph
    print("Looking up Service Principal object ID via Graph API...")
    graph_token = credential.get_token("https://graph.microsoft.com/.default")
    encoded_filter = urllib.request.quote(f"appId eq '{client_id}'")
    req = urllib.request.Request(
        f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter={encoded_filter}",
        headers={"Authorization": f"Bearer {graph_token.token}"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"ERROR: Graph API call failed: {e.read().decode()}")
        return

    sps = data.get("value", [])
    if not sps:
        print(f"ERROR: No Service Principal found with appId={client_id}")
        return

    sp_object_id = sps[0]["id"]
    print(f"  SP Object ID : {sp_object_id}")

    # Assign User Access Administrator (18d7d88d-d35e-4fb5-a5c3-7773c20a72d9)
    print("\nAssigning 'User Access Administrator' role on subscription...")
    scope = f"/subscriptions/{subscription_id}"
    role_def_id = f"{scope}/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

    auth_client = AuthorizationManagementClient(credential, subscription_id)
    try:
        auth_client.role_assignments.create(
            scope=scope,
            role_assignment_name=str(uuid.uuid4()),
            parameters=RoleAssignmentCreateParameters(
                role_definition_id=role_def_id,
                principal_id=sp_object_id,
                principal_type="ServicePrincipal",
            ),
        )
        print("  User Access Administrator role ASSIGNED successfully!")
    except Exception as e:
        err_str = str(e)
        if "RoleAssignmentExists" in err_str:
            print("  Role assignment already exists — nothing to do.")
        else:
            print(f"  ERROR: {e}")
            print("\n  You may need Owner or User Access Administrator on the subscription.")
            print("  Alternative: Azure Portal → Subscriptions → IAM → Add role assignment")
            return

    # Verify
    print("\nVerifying role assignments for the SP...")
    assignments = auth_client.role_assignments.list_for_scope(
        scope=scope,
        filter=f"principalId eq '{sp_object_id}'",
    )
    for a in assignments:
        role_id = a.role_definition_id.split("/")[-1]
        role_names = {
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
        }
        name = role_names.get(role_id, role_id)
        print(f"  - {name}")

    print("\n" + "=" * 60)
    print("Done! Now restart the dashboard and retry your deployment.")
    print("=" * 60)


if __name__ == "__main__":
    main()
