import json
import logging
import os
from typing import Any, Dict, List, Tuple

from presidio_analyzer import AnalyzerEngine

logger = logging.getLogger(__name__)


DEFAULT_SENSITIVE_ENTITY_TYPES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "CRYPTO",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "MEDICAL_LICENSE",
    "US_DRIVER_LICENSE",
}


def configured_sensitive_entity_types() -> set[str]:
    configured_types = os.getenv("PII_FILTER_TYPES", "")
    if not configured_types.strip():
        return DEFAULT_SENSITIVE_ENTITY_TYPES

    entity_types = {
        entity_type.strip().upper()
        for entity_type in configured_types.split(",")
        if entity_type.strip()
    }
    unknown_entity_types = entity_types - DEFAULT_SENSITIVE_ENTITY_TYPES
    if unknown_entity_types:
        logger.warning(
            "Unknown PII_FILTER_TYPES values: "
            f"{', '.join(sorted(unknown_entity_types))}. "
            "Ignoring unknown values. Allowed values: "
            f"{', '.join(sorted(DEFAULT_SENSITIVE_ENTITY_TYPES))}"
        )

    return entity_types & DEFAULT_SENSITIVE_ENTITY_TYPES


class PIIFilter:
    """Filter to detect and reject PII using Microsoft Presidio."""

    def __init__(self) -> None:
        self.analyzer = AnalyzerEngine()
        self.sensitive_entity_types = configured_sensitive_entity_types()
        logger.info(
            "PII filter initialized with Presidio analyzer for entity types: %s",
            sorted(self.sensitive_entity_types),
        )

    def analyze_text(self, text: str) -> List[Dict[str, Any]]:
        """Analyze text for PII entities."""
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=list(self.sensitive_entity_types),
        )
        return [
            {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "confidence": result.score,
                "text": text[result.start:result.end],
            }
            for result in results
        ]

    def analyze_payload(self, payload: Any) -> Dict[str, Any]:
        """Analyze an arbitrary JSON-serializable payload for PII."""
        if payload is None:
            return {"has_pii": False, "entities": []}

        payload_text = json.dumps(payload, ensure_ascii=False)
        entities = self.analyze_text(payload_text)

        logger.info("PII analysis found %s entities", len(entities))
        for entity in entities:
            logger.warning(
                "PII detected: %s (confidence: %.2f)",
                entity["entity_type"],
                entity["confidence"],
            )

        return {
            "has_pii": len(entities) > 0,
            "entities": entities,
        }

    def sensitive_entities(
        self, entities: List[Dict[str, Any]], confidence_threshold: float = 0.8
    ) -> List[Dict[str, Any]]:
        return [
            entity
            for entity in entities
            if entity["confidence"] >= confidence_threshold
            and entity["entity_type"] in self.sensitive_entity_types
        ]

    def redact_text(
        self, text: str, confidence_threshold: float = 0.8
    ) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
        entities = self.analyze_text(text)
        sensitive_entities = self.sensitive_entities(entities, confidence_threshold)

        if not sensitive_entities:
            return text, entities, []

        redacted = text
        for entity in sorted(sensitive_entities, key=lambda item: item["start"], reverse=True):
            replacement = f"[REDACTED_{entity['entity_type']}]"
            redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]

        return redacted, entities, sensitive_entities

    def redact_payload(
        self, payload: Any, confidence_threshold: float = 0.8
    ) -> Dict[str, Any]:
        all_entities: List[Dict[str, Any]] = []
        all_sensitive_entities: List[Dict[str, Any]] = []

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                redacted, entities, sensitive_entities = self.redact_text(
                    value, confidence_threshold
                )
                all_entities.extend(entities)
                all_sensitive_entities.extend(sensitive_entities)
                return redacted

            if isinstance(value, list):
                return [walk(item) for item in value]

            if isinstance(value, dict):
                return {key: walk(item) for key, item in value.items()}

            return value

        redacted_payload = walk(payload)
        return {
            "redacted_payload": redacted_payload,
            "entities": all_entities,
            "sensitive_entities": all_sensitive_entities,
            "modified": redacted_payload != payload,
        }

    def should_reject(self, payload: Any, confidence_threshold: float = 0.8) -> bool:
        """Determine if a payload should be rejected due to sensitive PII."""
        analysis = self.analyze_payload(payload)

        if not analysis["has_pii"]:
            return False

        high_confidence_sensitive_entities = self.sensitive_entities(
            analysis["entities"], confidence_threshold
        )

        should_reject = len(high_confidence_sensitive_entities) > 0

        if should_reject:
            rejected_types = {e["entity_type"] for e in high_confidence_sensitive_entities}
            logger.warning(
                "Rejecting payload due to %s sensitive PII entities: %s",
                len(high_confidence_sensitive_entities),
                rejected_types,
            )

        return should_reject


pii_filter = PIIFilter()
