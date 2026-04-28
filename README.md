# PII Filter MCP Server

This project converts the original HTTP webhook server into an MCP server with one tool: `filter_pii`.

## What it does

The `filter_pii` tool analyzes a Nanobot-style hook payload or any JSON-compatible payload with Microsoft Presidio and returns:

- an `accept` flag
- a `mutated` boolean indicating whether any content was rewritten
- a `message` object when filtering a Nanobot hook
- a redacted payload or message when redactable PII is found and no blocked PII is found
- a human-friendly `reason`

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

You can configure blocked and redacted entity types separately:

- `PII_BLOCK_TYPES`: comma-separated entity types that should be treated as blocking
- `PII_REDACT_TYPES`: comma-separated entity types that should be redacted

`main.py` constructs the `PIIFilter` from those environment variables at startup.

Each configured type can optionally include a confidence threshold override using `TYPE=THRESHOLD`.

- `EMAIL_ADDRESS` means `{"EMAIL_ADDRESS": null}` and uses the default `0.8` threshold for email addresses
- `PHONE_NUMBER=0.4` means `{"PHONE_NUMBER": 0.4}`

If either value is unset or blank, no entity types are enabled for that behavior.

Example:

```bash
PII_BLOCK_TYPES=US_SSN,CREDIT_CARD PII_REDACT_TYPES=EMAIL_ADDRESS,PHONE_NUMBER uv run pii-filter-mcp
```

Per-type thresholds example:

```bash
PII_REDACT_TYPES=EMAIL_ADDRESS=0.8,PHONE_NUMBER=0.4 uv run pii-filter-mcp
```

It is open on whatever interface or service name routes to that port, including private Docker IPs and Kubernetes service DNS names.

## Tool

### `filter_pii`

Inputs:

- `message`: Nanobot JSON-RPC message to inspect and optionally redact

Thresholds are configured through `PII_BLOCK_TYPES` and `PII_REDACT_TYPES`. If a type has no explicit threshold, its per-type default is used. `EMAIL_ADDRESS` defaults to `0.8`, `PHONE_NUMBER` defaults to `0.4`, and any type without a specific default uses `0.6`.

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

When blocked PII is found, the tool returns only `accept: false` and a human-friendly `reason` describing which blocked entity types were detected.

When only redactable PII is found, the tool returns a redacted `message`, `mutated: true`, and a human-friendly `reason` describing which entity types were redacted.

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
