"""
Helper script to create a new Azure Service Principal and update .env credentials.
Uses DeviceCodeCredential for interactive authentication (no Azure CLI required).

Run once whenever you need to (re)create credentials:
    python create_service_principal.py

Prerequisites: pip install -r requirements.txt
"""
import os
import sys
import json
import uuid
import datetime
from pathlib import Path

from azure.identity import DeviceCodeCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters


def get_env_path():
    return Path(__file__).parent / ".env"


def read_env():
    env_path = get_env_path()
    if not env_path.exists():
        return {}
    lines = env_path.read_text(encoding="utf-8").splitlines()
    result = {}
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def update_env(updates: dict):
    env_path = get_env_path()
    lines = env_path.read_text(encoding="utf-8").splitlines()
    updated_keys = set()
    new_lines = []
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k = line.partition("=")[0].strip()
            if k in updates:
                new_lines.append(f"{k}={updates[k]}")
                updated_keys.add(k)
                continue
        new_lines.append(line)
    # Add any keys not already present
    for k, v in updates.items():
        if k not in updated_keys:
            new_lines.append(f"{k}={v}")
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    print(f"✅ Updated {env_path}")


def main():
    print("=" * 60)
    print("Azure Service Principal Creator")
    print("=" * 60)
    print()
    print("This will open a browser/device-code flow to authenticate you")
    print("interactively, then create a new service principal.\n")

    # Step 1: Interactive login with device code
    print("Step 1: Interactive authentication...")
    print("(A device code will be displayed — open the URL and enter the code)\n")

    # Read current tenant from .env to target the right directory
    current_env = read_env()
    current_tenant = current_env.get("AZURE_TENANT_ID", "").strip() or "organizations"
    print(f"   Targeting tenant: {current_tenant}")

    # Use a well-known management scope
    credential = DeviceCodeCredential(
        tenant_id=current_tenant,
        additionally_allowed_tenants=["*"]
    )

    # Get subscriptions to determine the tenant
    sub_client = SubscriptionClient(credential)

    # Show logged-in user info
    try:
        import urllib.request as _ur
        tok = credential.get_token("https://management.azure.com/.default")
        me_req = _ur.Request(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            headers={"Authorization": f"Bearer {tok.token}"},
        )
        with _ur.urlopen(me_req) as r:
            subs_raw = json.loads(r.read())
        print(f"   Raw subscription count from REST: {len(subs_raw.get('value', []))}")
        for s in subs_raw.get("value", []):
            print(f"   - {s.get('displayName')} ({s.get('subscriptionId')}) tenantId={s.get('tenantId')}")
    except Exception as e:
        print(f"   (REST subscription check failed: {e})")

    subscriptions = list(sub_client.subscriptions.list())
    if not subscriptions:
        print("\n❌ No subscriptions found for this account.")
        print("   Make sure you signed in with the account that owns the Azure subscription.")
        print("   If you have multiple Microsoft accounts, try signing in to the correct one.")
        print()
        print("   Alternatively, update your .env manually with the correct values from:")
        print("   https://portal.azure.com > Azure Active Directory > App Registrations")
        sys.exit(1)

    print("\nAvailable subscriptions:")
    for i, sub in enumerate(subscriptions):
        print(f"  [{i}] {sub.display_name} ({sub.subscription_id})")

    if len(subscriptions) == 1:
        chosen = subscriptions[0]
    else:
        idx = int(input("\nEnter the number of the subscription to use: ").strip())
        chosen = subscriptions[idx]

    subscription_id = chosen.subscription_id
    tenant_id = current_tenant  # from .env / login target
    print(f"\n✅ Selected subscription: {chosen.display_name}")
    print(f"   Subscription ID : {subscription_id}")
    print(f"   Tenant ID       : {tenant_id}")

    # Step 2: Create app registration via Microsoft Graph
    print("\nStep 2: Creating app registration via Microsoft Graph...")

    graph_token = credential.get_token("https://graph.microsoft.com/.default")
    import urllib.request, urllib.error

    app_name = f"cortex-sim-sp-{uuid.uuid4().hex[:8]}"
    app_payload = json.dumps({"displayName": app_name}).encode()

    req = urllib.request.Request(
        "https://graph.microsoft.com/v1.0/applications",
        data=app_payload,
        headers={
            "Authorization": f"Bearer {graph_token.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            app_data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"❌ Failed to create app registration: {e.read().decode()}")
        sys.exit(1)

    app_id = app_data["appId"]
    app_object_id = app_data["id"]
    print(f"   App registration created: {app_name}")
    print(f"   Client ID: {app_id}")

    # Step 3: Create a client secret
    print("\nStep 3: Creating client secret...")
    secret_payload = json.dumps({
        "passwordCredential": {
            "displayName": "cortex-sim-secret",
            "endDateTime": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    }).encode()

    req = urllib.request.Request(
        f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/addPassword",
        data=secret_payload,
        headers={
            "Authorization": f"Bearer {graph_token.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            secret_data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"❌ Failed to create client secret: {e.read().decode()}")
        sys.exit(1)

    client_secret = secret_data["secretText"]
    print("   Client secret created.")

    # Step 4: Create service principal for the app
    print("\nStep 4: Creating service principal...")
    sp_payload = json.dumps({"appId": app_id}).encode()
    req = urllib.request.Request(
        "https://graph.microsoft.com/v1.0/servicePrincipals",
        data=sp_payload,
        headers={
            "Authorization": f"Bearer {graph_token.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            sp_data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        # May already exist
        if "AlreadyExists" not in body:
            print(f"❌ Failed to create service principal: {body}")
            sys.exit(1)
        print("   Service principal already exists (continuing).")
        sp_data = {"id": None}

    sp_object_id = sp_data.get("id")

    # Step 5: Assign Contributor + User Access Administrator roles on the subscription
    # Contributor alone lacks Microsoft.Authorization/roleDefinitions/write, which is
    # required to create custom role definitions in simulation scenarios.
    # User Access Administrator grants Microsoft.Authorization/* including roleDefinitions/write.
    print("\nStep 5: Assigning Contributor + User Access Administrator roles on subscription...")
    import time
    time.sleep(10)  # Wait for SP to propagate

    auth_client = AuthorizationManagementClient(credential, subscription_id)
    scope = f"/subscriptions/{subscription_id}"

    roles_to_assign = {
        "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
        "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    }

    for role_name, role_id in roles_to_assign.items():
        role_def_id = f"{scope}/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
        assignment_id = str(uuid.uuid4())
        try:
            auth_client.role_assignments.create(
                scope=scope,
                role_assignment_name=assignment_id,
                parameters=RoleAssignmentCreateParameters(
                    role_definition_id=role_def_id,
                    principal_id=sp_object_id,
                    principal_type="ServicePrincipal",
                ),
            )
            print(f"   {role_name} role assigned.")
        except Exception as e:
            print(f"⚠️  {role_name} role assignment failed (may need to assign manually): {e}")

    # Step 6: Update .env
    print("\nStep 6: Updating .env file...")
    update_env({
        "AZURE_CLIENT_ID": app_id,
        "AZURE_CLIENT_SECRET": client_secret,
        "AZURE_TENANT_ID": tenant_id,
        "AZURE_SUBSCRIPTION_ID": subscription_id,
    })

    print("\n" + "=" * 60)
    print("✅ Done! New service principal created:")
    print(f"   AZURE_CLIENT_ID       = {app_id}")
    print(f"   AZURE_TENANT_ID       = {tenant_id}")
    print(f"   AZURE_SUBSCRIPTION_ID = {subscription_id}")
    print(f"   AZURE_CLIENT_SECRET   = (saved to .env)")
    print("=" * 60)
    print("\nRun 'python verify_azure_creds.py' to confirm the new credentials work.")


if __name__ == "__main__":
    main()
