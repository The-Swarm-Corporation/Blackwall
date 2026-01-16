"""
Blackwall - AI-Powered API Security Middleware

Blackwall is a FastAPI middleware that provides intelligent security monitoring
and threat detection for API endpoints. It uses AI agents to analyze incoming
requests, detect malicious patterns, and take protective actions.

Key Features:
    - Real-time threat detection (SQL injection, XSS, command injection, etc.)
    - IP blocking and rate limiting
    - AI-powered security analysis via Swarms API
    - Automatic function call execution for security actions
    - Comprehensive threat analytics and reporting

Main Components:
    - BlackwallMiddleware: FastAPI middleware for request interception
    - SecurityStateManager: Manages security state (blocked IPs, threats, etc.)
    - SwarmsAgent: AI agent wrapper for security analysis
    - Security Tools: Functions for blocking, unblocking, and analyzing threats

Example Usage:
    >>> from fastapi import FastAPI
    >>> from blackwall.main import BlackwallMiddleware
    >>>
    >>> app = FastAPI()
    >>> app.add_middleware(
    ...     BlackwallMiddleware,
    ...     model_name="gpt-4.1",
    ...     run_agent_on_all_requests=True
    ... )

For more information, see the README.md file.
"""

from blackwall.main import BlackwallMiddleware, create_blackwall_agent
from blackwall.swarms_api_client import SwarmsAPIClient, SwarmsAgent


__all__ = [
    "BlackwallMiddleware",
    "create_blackwall_agent",
    "SwarmsAPIClient",
    "SwarmsAgent",
]
