import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import AliasChoices, BaseModel, Field

from filters import pii_filter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

server = FastMCP(
    "pii-filter",
    host=HOST,
    port=PORT,
)


class MCPMessage(BaseModel):
    jsonrpc: str = "2.0"
    id: Any | None = None
    method: str | None = None
    params: Any | None = None
    result: Any | None = None
    error: Any | None = None


class FilterHookInput(BaseModel):
    accept: bool = Field(
        default=True, validation_alias=AliasChoices("accept", "accepted")
    )
    message: MCPMessage | None = None
    reason: str = ""
    payload: Any | None = None
    confidence_threshold: float = 0.8


def _filter_message(message: MCPMessage, confidence_threshold: float) -> dict[str, Any]:
    redacted_message = message.model_dump()
    params_result = pii_filter.redact_payload(message.params, confidence_threshold)
    result_result = pii_filter.redact_payload(message.result, confidence_threshold)

    redacted_message["params"] = params_result["redacted_payload"]
    redacted_message["result"] = result_result["redacted_payload"]

    entities = params_result["entities"] + result_result["entities"]
    sensitive_entities = (
        params_result["sensitive_entities"] + result_result["sensitive_entities"]
    )
    modified = params_result["modified"] or result_result["modified"]

    if modified:
        reason = "Sensitive PII was detected and redacted from the message payload."
    elif sensitive_entities:
        reason = "Sensitive PII was detected in the message payload."
    else:
        reason = ""

    return {
        "accept": True,
        "accepted": True,
        "message": redacted_message,
        "reason": reason,
        "entities": entities,
        "sensitive_entities": sensitive_entities,
        "entity_count": len(entities),
        "sensitive_entity_count": len(sensitive_entities),
        "confidence_threshold": confidence_threshold,
    }


def _coerce_message(message: MCPMessage | dict[str, Any] | None) -> MCPMessage:
    if isinstance(message, MCPMessage):
        return message
    return MCPMessage.model_validate(message)


@server.tool(
    name="filter_pii",
    description="Nanobot-compatible MCP hook that detects PII and can return a redacted message when content is not accepted as-is.",
)
def filter_pii(
    message: MCPMessage | dict[str, Any] | None = None,
    confidence_threshold: float = 0.8,
) -> dict[str, Any]:
    print("Filtering message with confidence threshold:", confidence_threshold)
    return _filter_message(_coerce_message(message), confidence_threshold)


def main() -> None:
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
