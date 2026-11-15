#!/usr/bin/env bash
set -euo pipefail

: "${AZ_RESOURCE_GROUP:?Set AZ_RESOURCE_GROUP}"
: "${FUNCTION_REGION:?Set FUNCTION_REGION to a Flex Consumption supported region}"
: "${FUNCTION_STORAGE:?Set globally unique lowercase FUNCTION_STORAGE (3-24 chars)}"
: "${FUNCTION_APP_NAME:?Set globally unique FUNCTION_APP_NAME}"
: "${ENTRA_TENANT_ID:?Set ENTRA_TENANT_ID}"
: "${GRAPH_CLIENT_ID:?Set GRAPH_CLIENT_ID}"
: "${GRAPH_CLIENT_SECRET:?Set GRAPH_CLIENT_SECRET}"
: "${EDGE_APP_SP_OBJECT_ID:?Set EDGE_APP_SP_OBJECT_ID}"
: "${EDGE_DEVICE_ID:=WSL-POC-001}"
: "${RBAC_CACHE_VALID_HOURS:=168}"

az storage account create \
  --name "$FUNCTION_STORAGE" \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --location "$FUNCTION_REGION" \
  --sku Standard_LRS \
  --allow-blob-public-access false >/dev/null

if ! az functionapp show -g "$AZ_RESOURCE_GROUP" -n "$FUNCTION_APP_NAME" >/dev/null 2>&1; then
  az functionapp create \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --name "$FUNCTION_APP_NAME" \
    --storage-account "$FUNCTION_STORAGE" \
    --flexconsumption-location "$FUNCTION_REGION" \
    --runtime python \
    --runtime-version 3.11 >/dev/null
fi

az functionapp config appsettings set \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --name "$FUNCTION_APP_NAME" \
  --settings \
    ENTRA_TENANT_ID="$ENTRA_TENANT_ID" \
    GRAPH_CLIENT_ID="$GRAPH_CLIENT_ID" \
    GRAPH_CLIENT_SECRET="$GRAPH_CLIENT_SECRET" \
    EDGE_APP_SP_OBJECT_ID="$EDGE_APP_SP_OBJECT_ID" \
    ALLOWED_DEVICE_IDS="$EDGE_DEVICE_ID" \
    RBAC_CACHE_VALID_HOURS="$RBAC_CACHE_VALID_HOURS" >/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUNCTION_PROJECT="$(cd "$SCRIPT_DIR/../rbac_function" && pwd)"
pushd "$FUNCTION_PROJECT" >/dev/null
func azure functionapp publish "$FUNCTION_APP_NAME"
popd >/dev/null

echo
echo "RBAC API deployed."
echo "Base URL: https://${FUNCTION_APP_NAME}.azurewebsites.net/api"
echo "HOST KEY (secret):"
az functionapp keys list \
  --resource-group "$AZ_RESOURCE_GROUP" \
  --name "$FUNCTION_APP_NAME" \
  --query functionKeys.default -o tsv
