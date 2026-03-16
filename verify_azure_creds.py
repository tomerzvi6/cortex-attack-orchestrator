import os
import sys
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from dotenv import load_dotenv

# Load environment variables from .env file, OVERRIDING system env vars to ensure we get the latest file content
load_dotenv(override=True)

def check_azure_credentials():
    print(f"CWD: {os.getcwd()}")
    print("Checking Azure credentials...")
    
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    print(f"Loaded Client ID: '{client_id}'")
    print(f"Loaded Tenant ID: '{tenant_id}'")
    print(f"Loaded Subscription ID: '{subscription_id}'")
    
    # Check for whitespace
    if any(x and x.strip() != x for x in [tenant_id, client_id, client_secret, subscription_id]):
         print("\n⚠️  WARNING: Detected leading/trailing whitespace in your .env values! Please remove spaces.")


    missing = []
    if not tenant_id: missing.append("AZURE_TENANT_ID")
    if not client_id: missing.append("AZURE_CLIENT_ID")
    if not client_secret: missing.append("AZURE_CLIENT_SECRET")
    if not subscription_id: missing.append("AZURE_SUBSCRIPTION_ID")

    if missing:
        print(f"❌ Missing environment variables: {', '.join(missing)}")
        return False

    try:
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )

        subscription_client = ResourceManagementClient(credential, subscription_id)

        # Attempt to list resource groups (limit to 1 to be fast)
        rgs = list(subscription_client.resource_groups.list(top=1))
        
        print(f"✅ Successfully authenticated with Azure!")
        print(f"   Subscription ID: {subscription_id}")
        if rgs:
            print(f"   Found resource group: {rgs[0].name}")
        else:
            print(f"   (No resource groups found, but connection works)")
            
        return True

    except Exception as e:
        print(f"❌ Failed to authenticate with Azure:")
        print(f"   {str(e)}")
        # Check for specific error hints
        if "AADSTS7000215" in str(e):
            print("\n   ⚠️  Hint: Invalid client secret format. Make sure you are using the Secret VALUE, not the Secret ID.")
        return False

if __name__ == "__main__":
    if check_azure_credentials():
        sys.exit(0)
    else:
        sys.exit(1)
