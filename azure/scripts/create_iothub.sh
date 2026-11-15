#!/usr/bin/env bash
set -euo pipefail

: "${AZ_RESOURCE_GROUP:?Set AZ_RESOURCE_GROUP}"
: "${AZ_REGION:?Set AZ_REGION, e.g. centralindia}"
: "${IOTHUB_NAME:?Set globally unique IOTHUB_NAME}"
: "${EDGE_DEVICE_ID:=WSL-POC-001}"

az extension add --upgrade --name azure-iot >/dev/null
az group create --name "$AZ_RESOURCE_GROUP" --location "$AZ_REGION" >/dev/null

if ! az iot hub show -g "$AZ_RESOURCE_GROUP" -n "$IOTHUB_NAME" >/dev/null 2>&1; then
  az iot hub create \
    --resource-group "$AZ_RESOURCE_GROUP" \
    --name "$IOTHUB_NAME" \
    --sku F1 \
    --partition-count 2 >/dev/null
fi

if ! az iot hub device-identity show --hub-name "$IOTHUB_NAME" --device-id "$EDGE_DEVICE_ID" >/dev/null 2>&1; then
  az iot hub device-identity create --hub-name "$IOTHUB_NAME" --device-id "$EDGE_DEVICE_ID" >/dev/null
fi

if ! az iot hub consumer-group show --hub-name "$IOTHUB_NAME" --name adx-edge-poc >/dev/null 2>&1; then
  az iot hub consumer-group create --hub-name "$IOTHUB_NAME" --name adx-edge-poc >/dev/null
fi

echo "IoT Hub ready: $IOTHUB_NAME"
echo "Device: $EDGE_DEVICE_ID"
echo "Consumer group: adx-edge-poc"
echo
echo "DEVICE CONNECTION STRING (secret):"
az iot hub device-identity connection-string show \
  --hub-name "$IOTHUB_NAME" \
  --device-id "$EDGE_DEVICE_ID" \
  --query connectionString -o tsv
