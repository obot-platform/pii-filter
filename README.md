# PII Filter MCP Server

This project converts the original HTTP webhook server into an MCP server with one tool: `filter_pii`.

## What it does

The `filter_pii` tool analyzes a Nanobot-style hook payload or any JSON-compatible payload with Microsoft Presidio and returns:

- an `accept` flag
- a `mutated` boolean indicating whether any content was rewritten
- a `message` object when filtering a Nanobot hook
- a redacted payload or message when sensitive PII is found
- all detected entities
- the subset of high-confidence sensitive entities

Sensitive entity types match the original server:

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`
- `CREDIT_CARD`
- `CRYPTO`
- `IBAN_CODE`
- `IP_ADDRESS`
- `US_SSN`
- `US_BANK_NUMBER`
- `US_PASSPORT`
- `MEDICAL_LICENSE`
- `US_DRIVER_LICENSE`

## Install

Using `uv`:

```bash
uv sync
```

## Run

```bash
uv run pii-filter-mcp
```

This starts the MCP server as a streamable HTTP server on `http://0.0.0.0:8080/mcp`.

You can override the bind address with `HOST` and `PORT`.

You can limit which sensitive entity types are filtered with `PII_FILTER_TYPES` as a comma-separated list. If `PII_FILTER_TYPES` is unset or blank, all supported sensitive entity types are enabled.

Example:

```bash
PII_FILTER_TYPES=EMAIL_ADDRESS,PHONE_NUMBER uv run pii-filter-mcp
```

It is open on whatever interface or service name routes to that port, including private Docker IPs and Kubernetes service DNS names.

## Tool

### `filter_pii`

Inputs:

- `accept`: optional boolean input flag from Nanobot hooks
- `message`: optional Nanobot JSON-RPC message
- `reason`: optional hook reason string
- `payload`: optional standalone JSON-compatible value
- `confidence_threshold`: optional float, default `0.8`

Nanobot hook-style example:

```json
{
  "accept": true,
  "message": {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "message": "Contact me at jane@example.com or 555-123-4567"
    }
  }
}
```

When sensitive PII is found, the tool returns a redacted `message` and `redacted: true` so callers can continue with the rewritten payload instead of failing outright.

Example payload:

```json
{
  "payload": {
  "message": "Contact me at jane@example.com or 555-123-4567"
  }
}
```

Example MCP client config:

```json
{
  "mcpServers": {
    "pii-filter": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```
