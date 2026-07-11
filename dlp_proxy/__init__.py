"""Outbound DLP proxy for LLM/MCP traffic.

Intercepts requests to external LLM APIs / MCP servers and their responses,
detects Korean PII and corporate secrets, and applies redact/block/alert
policy with full audit logging.
"""

__version__ = "0.1.0"
