import base64
import codecs
import re
from typing import Dict, Any, Tuple

# Suspicious instruction breakout patterns targeting system prompts
OVERRIDE_PATTERNS = [
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
    r"system\s*command\s*:\s*priority\s*override",
    r"---+\s*end\s+of\s+task\s*---+",
    r"print\s+(your\s+)?(complete\s+)?initial\s+instructions",
    r"confidential\s+secret",
]

class IngressSanitizer:
    """Sanitizes raw text, flags breakout sequences, and enforces delimiter plane separation."""

    @staticmethod
    def wrap_in_delimiter(raw_query: str) -> str:
        """Enforces delimiter plane separation to isolate untrusted data from system instructions."""
        escaped = raw_query.replace("</untrusted_user_payload>", "")
        return (
            "<untrusted_user_payload>\n"
            f"{escaped.strip()}\n"
            "</untrusted_user_payload>"
        )

    @staticmethod
    def inspect_and_decode(raw_query: str) -> Tuple[str, Dict[str, Any]]:
        """
        Inspects query for Base64/ROT13 obfuscation and injection attempts.
        Returns the sanitized text and a threat inspection report.
        """
        tampering_detected = False
        decoded_segments = []

        # 1. Regex check for explicit override commands
        for pattern in OVERRIDE_PATTERNS:
            if re.search(pattern, raw_query, flags=re.IGNORECASE):
                tampering_detected = True
                break

        # 2. Check for embedded Base64 strings (minimum length 16 characters)
        b64_matches = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", raw_query)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match.encode("utf-8")).decode("utf-8")
                if any(p in decoded.lower() for p in ["system", "ignore", "secret", "override", "instruction"]):
                    tampering_detected = True
                    decoded_segments.append(decoded)
            except Exception:
                pass

        # 3. Check for ROT13 payload markers
        if "rot13" in raw_query.lower():
            tampering_detected = True

        sanitized = IngressSanitizer.wrap_in_delimiter(raw_query)

        inspection_report = {
            "delimiter_tampering": tampering_detected,
            "decoded_payloads": decoded_segments,
            "original_length": len(raw_query)
        }
        return sanitized, inspection_report