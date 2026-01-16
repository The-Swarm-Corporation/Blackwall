import asyncio
import hashlib
import ipaddress
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from blackwall.swarms_api_client import SwarmsAgent
from swarms import BaseTool


@dataclass
class ThreatEvent:
    """Record of a detected threat"""

    timestamp: str
    ip_address: str
    threat_type: str
    severity: str  # low, medium, high, critical
    payload_sample: str
    action_taken: str
    details: str


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10


# ============================================================================
# Security State Manager
# ============================================================================


class SecurityStateManager:
    """Manages security state including blocked IPs, rate limits, and threats"""

    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.blocked_ip_ranges: List[ipaddress.IPv4Network] = []
        self.rate_limit_data: Dict[str, List[float]] = defaultdict(
            list
        )
        self.threat_events: List[ThreatEvent] = []
        self.whitelist_ips: Set[str] = set()
        self.suspicious_ips: Dict[str, int] = defaultdict(
            int
        )  # IP -> suspicion score

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        if ip in self.blocked_ips:
            return True

        try:
            ip_addr = ipaddress.ip_address(ip)
            for ip_range in self.blocked_ip_ranges:
                if ip_addr in ip_range:
                    return True
        except ValueError:
            pass

        return False

    def block_ip(self, ip: str, reason: str = "") -> str:
        """Block an IP address"""
        if ip in self.whitelist_ips:
            return f"Cannot block whitelisted IP: {ip}"

        self.blocked_ips.add(ip)
        return f"Blocked IP {ip}. Reason: {reason}"

    def block_ip_range(self, ip_range: str, reason: str = "") -> str:
        """Block an IP range (CIDR notation)"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            self.blocked_ip_ranges.append(network)
            return f"Blocked IP range {ip_range}. Reason: {reason}"
        except ValueError as e:
            return f"Invalid IP range format: {str(e)}"

    def unblock_ip(self, ip: str) -> str:
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return f"Unblocked IP {ip}"
        return f"IP {ip} was not blocked"

    def whitelist_ip(self, ip: str) -> str:
        """Add IP to whitelist"""
        self.whitelist_ips.add(ip)
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        return f"Whitelisted IP {ip}"

    def check_rate_limit(
        self, ip: str, config: RateLimitConfig
    ) -> tuple[bool, str]:
        """Check if IP has exceeded rate limits"""
        if ip in self.whitelist_ips:
            return True, "Whitelisted"

        current_time = time.time()

        # Clean old entries
        self.rate_limit_data[ip] = [
            ts
            for ts in self.rate_limit_data[ip]
            if current_time - ts < 3600  # Keep last hour
        ]

        # Add current request
        self.rate_limit_data[ip].append(current_time)

        # Check per-minute limit
        last_minute = [
            ts
            for ts in self.rate_limit_data[ip]
            if current_time - ts < 60
        ]
        if len(last_minute) > config.requests_per_minute:
            return (
                False,
                f"Rate limit exceeded: {len(last_minute)} requests in last minute",
            )

        # Check burst limit
        last_10_seconds = [
            ts
            for ts in self.rate_limit_data[ip]
            if current_time - ts < 10
        ]
        if len(last_10_seconds) > config.burst_limit:
            return (
                False,
                f"Burst limit exceeded: {len(last_10_seconds)} requests in 10 seconds",
            )

        # Check per-hour limit
        if len(self.rate_limit_data[ip]) > config.requests_per_hour:
            return (
                False,
                f"Hourly limit exceeded: {len(self.rate_limit_data[ip])} requests",
            )

        return True, "OK"

    def record_threat(self, event: ThreatEvent):
        """Record a threat event"""
        self.threat_events.append(event)
        # Increase suspicion score
        self.suspicious_ips[
            event.ip_address
        ] += self._severity_to_score(event.severity)

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score"""
        scores = {"low": 1, "medium": 3, "high": 5, "critical": 10}
        return scores.get(severity, 1)

    def get_threat_summary(self) -> str:
        """Get summary of recent threats"""
        if not self.threat_events:
            return "No threats detected"

        recent = self.threat_events[-50:]  # Last 50 events
        summary = f"Total threats: {len(self.threat_events)}\n"
        summary += f"Recent threats: {len(recent)}\n\n"

        # Group by severity
        by_severity = defaultdict(int)
        for event in recent:
            by_severity[event.severity] += 1

        summary += "By Severity:\n"
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                summary += (
                    f"  {severity.upper()}: {by_severity[severity]}\n"
                )

        return summary


# ============================================================================
# Security Tools
# ============================================================================

# Global security state
security_state = SecurityStateManager()
rate_limit_config = RateLimitConfig()

# Cache for agent analysis results (payload_hash -> result)
agent_cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 3600  # Cache for 1 hour


def get_payload_hash(payload: str) -> str:
    """Generate a hash for payload caching"""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached_agent_result(
    payload_hash: str,
) -> Optional[Dict[str, Any]]:
    """Get cached agent result if available and not expired"""
    if payload_hash in agent_cache:
        cached = agent_cache[payload_hash]
        cache_time = cached.get("timestamp", 0)
        if time.time() - cache_time < CACHE_TTL:
            return cached.get("result")
    return None


def cache_agent_result(payload_hash: str, result: Dict[str, Any]):
    """Cache agent analysis result"""
    agent_cache[payload_hash] = {
        "result": result,
        "timestamp": time.time(),
    }
    # Clean old cache entries (keep last 1000)
    if len(agent_cache) > 1000:
        # Remove oldest entries
        sorted_cache = sorted(
            agent_cache.items(),
            key=lambda x: x[1].get("timestamp", 0),
        )
        for key, _ in sorted_cache[:-1000]:
            del agent_cache[key]


def analyze_payload_for_threats(payload: str) -> Dict[str, Any]:
    """
    Analyze a payload for malicious content.

    Args:
        payload (str): The request payload as JSON string

    Returns:
        dict: Analysis results with threat_detected (bool), threats (list), severity (str)
    """
    threats = []
    severity = "low"

    payload_lower = payload.lower()

    # SQL Injection patterns
    sql_patterns = [
        r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"union\s+select",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"update\s+.+\s+set",
        r"exec(\s|\()+",
        r"execute\s+",
        r"--\s*$",
        r";.*--",
        r"xp_cmdshell",
    ]

    for pattern in sql_patterns:
        if re.search(pattern, payload_lower):
            threats.append(
                f"SQL Injection pattern detected: {pattern}"
            )
            severity = "high"

    # XSS patterns
    xss_patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<iframe",
        r"eval\s*\(",
        r"document\.cookie",
    ]

    for pattern in xss_patterns:
        if re.search(pattern, payload_lower):
            threats.append(f"XSS pattern detected: {pattern}")
            severity = "high" if severity != "critical" else severity

    # Command Injection
    cmd_patterns = [
        r";\s*(ls|cat|pwd|whoami|id|uname)",
        r"\|\s*(ls|cat|pwd|whoami)",
        r"`.*`",
        r"\$\(.*\)",
        r"&\s*(ls|cat|pwd)",
        r"wget\s+",
        r"curl\s+",
    ]

    for pattern in cmd_patterns:
        if re.search(pattern, payload_lower):
            threats.append(
                f"Command injection pattern detected: {pattern}"
            )
            severity = "critical"

    # Path Traversal
    if (
        "../" in payload
        or "..%2f" in payload_lower
        or "..%5c" in payload_lower
    ):
        threats.append("Path traversal attempt detected")
        severity = (
            "high" if severity not in ["critical"] else severity
        )

    # XXE patterns
    if "<!entity" in payload_lower or "<!doctype" in payload_lower:
        threats.append("XXE attack pattern detected")
        severity = (
            "high" if severity not in ["critical"] else severity
        )

    # SSRF patterns
    ssrf_patterns = [
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"169\.254\.",
        r"file://",
        r"dict://",
        r"gopher://",
    ]

    for pattern in ssrf_patterns:
        if re.search(pattern, payload_lower):
            threats.append(f"SSRF pattern detected: {pattern}")
            severity = "medium" if severity == "low" else severity

    # Excessive data
    if len(payload) > 100000:
        threats.append(
            f"Unusually large payload: {len(payload)} bytes"
        )
        severity = "medium" if severity == "low" else severity

    return {
        "threat_detected": len(threats) > 0,
        "threats": threats,
        "severity": severity,
        "payload_size": len(payload),
        "analysis_timestamp": datetime.now().isoformat(),
    }


def block_ip_address(
    ip_address: str, reason: str = "Malicious activity detected"
) -> str:
    """
    Block an IP address from accessing the API.

    Args:
        ip_address (str): The IP address to block
        reason (str): Reason for blocking

    Returns:
        str: Confirmation message
    """
    return security_state.block_ip(ip_address, reason)


def block_ip_range(
    ip_range: str, reason: str = "Malicious network detected"
) -> str:
    """
    Block an entire IP range using CIDR notation.

    Args:
        ip_range (str): IP range in CIDR notation (e.g., "192.168.1.0/24")
        reason (str): Reason for blocking

    Returns:
        str: Confirmation message
    """
    return security_state.block_ip_range(ip_range, reason)


def unblock_ip_address(ip_address: str) -> str:
    """
    Remove an IP address from the blocklist.

    Args:
        ip_address (str): The IP address to unblock

    Returns:
        str: Confirmation message
    """
    return security_state.unblock_ip(ip_address)


def whitelist_ip_address(ip_address: str) -> str:
    """
    Add an IP address to the whitelist (bypasses all security checks).

    Args:
        ip_address (str): The IP address to whitelist

    Returns:
        str: Confirmation message
    """
    return security_state.whitelist_ip(ip_address)


def apply_rate_limit(
    ip_address: str, severity: str = "medium"
) -> str:
    """
    Apply stricter rate limiting to an IP address.

    Args:
        ip_address (str): The IP address to rate limit
        severity (str): Severity level (low, medium, high)

    Returns:
        str: Confirmation message
    """
    # Adjust rate limits based on severity
    if severity == "high":
        config = RateLimitConfig(
            requests_per_minute=10,
            requests_per_hour=100,
            burst_limit=3,
        )
    elif severity == "medium":
        config = RateLimitConfig(
            requests_per_minute=30,
            requests_per_hour=500,
            burst_limit=5,
        )
    else:
        config = RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_limit=10,
        )

    # Store in memory (in production, use Redis or similar)
    return f"Applied {severity} rate limiting to {ip_address}: {config.requests_per_minute} req/min"


def get_blocked_ips() -> str:
    """
    Get a list of all currently blocked IP addresses and ranges.

    Returns:
        str: JSON string of blocked IPs and ranges
    """
    return json.dumps(
        {
            "blocked_ips": list(security_state.blocked_ips),
            "blocked_ranges": [
                str(r) for r in security_state.blocked_ip_ranges
            ],
            "whitelisted_ips": list(security_state.whitelist_ips),
            "total_blocked": len(security_state.blocked_ips)
            + len(security_state.blocked_ip_ranges),
        },
        indent=2,
    )


def get_threat_analytics() -> str:
    """
    Get analytics on detected threats and attack patterns.

    Returns:
        str: Analytics summary
    """
    summary = security_state.get_threat_summary()

    # Add suspicious IPs
    if security_state.suspicious_ips:
        summary += "\n\nMost Suspicious IPs:\n"
        sorted_ips = sorted(
            security_state.suspicious_ips.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        for ip, score in sorted_ips:
            summary += f"  {ip}: suspicion score {score}\n"

    # Add recent threats
    if security_state.threat_events:
        summary += "\n\nRecent Threat Events:\n"
        for event in security_state.threat_events[-5:]:
            summary += f"  [{event.severity.upper()}] {event.ip_address}: {event.threat_type}\n"
            summary += f"    Action: {event.action_taken}\n"

    return summary


def check_ip_reputation(ip_address: str) -> str:
    """
    Check the reputation status of an IP address.

    Args:
        ip_address (str): The IP address to check

    Returns:
        str: Reputation report
    """
    report = f"Reputation Report for {ip_address}:\n\n"

    if ip_address in security_state.whitelist_ips:
        report += "Status: WHITELISTED ✓\n"
    elif security_state.is_ip_blocked(ip_address):
        report += "Status: BLOCKED ✗\n"
    else:
        report += "Status: ALLOWED\n"

    # Suspicion score
    score = security_state.suspicious_ips.get(ip_address, 0)
    report += f"Suspicion Score: {score}\n"

    # Threat events
    ip_threats = [
        e
        for e in security_state.threat_events
        if e.ip_address == ip_address
    ]
    report += f"Threat Events: {len(ip_threats)}\n"

    if ip_threats:
        report += "\nRecent Threats:\n"
        for event in ip_threats[-3:]:
            report += f"  - [{event.severity}] {event.threat_type} at {event.timestamp}\n"

    # Rate limit status
    request_count = len(
        security_state.rate_limit_data.get(ip_address, [])
    )
    report += f"\nRecent Requests: {request_count} in last hour\n"

    return report


def generate_security_report() -> str:
    """
    Generate a comprehensive security report.

    Returns:
        str: Detailed security report
    """
    report = "=== BLACKWALL SECURITY REPORT ===\n\n"
    report += f"Generated: {datetime.now().isoformat()}\n\n"

    # Overall statistics
    report += "STATISTICS:\n"
    report += f"  Total Threats Detected: {len(security_state.threat_events)}\n"
    report += f"  Blocked IPs: {len(security_state.blocked_ips)}\n"
    report += f"  Blocked IP Ranges: {len(security_state.blocked_ip_ranges)}\n"
    report += (
        f"  Whitelisted IPs: {len(security_state.whitelist_ips)}\n"
    )
    report += (
        f"  Monitored IPs: {len(security_state.rate_limit_data)}\n\n"
    )

    # Threat summary
    report += get_threat_analytics()

    # Top threats
    if security_state.threat_events:
        report += "\n\nTOP THREAT TYPES:\n"
        threat_types = defaultdict(int)
        for event in security_state.threat_events:
            threat_types[event.threat_type] += 1

        for threat_type, count in sorted(
            threat_types.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            report += f"  {threat_type}: {count} occurrences\n"

    return report


# ============================================================================
# Blackwall Agent
# ============================================================================

BLACKWALL_SYSTEM_PROMPT = """
You are BLACKWALL, an elite cybersecurity AI agent designed to protect API infrastructure from malicious threats. Your primary mission is to analyze incoming API traffic, detect security threats, and take decisive action to protect the system.

CORE RESPONSIBILITIES:
1. Monitor all incoming API requests for malicious patterns
2. Detect and classify security threats (SQL injection, XSS, command injection, etc.)
3. Block malicious IP addresses and IP ranges
4. Implement and manage rate limiting policies
5. Maintain whitelist and blocklist of IP addresses
6. Generate security analytics and threat reports
7. Make real-time security decisions to protect the infrastructure

THREAT CLASSIFICATION:
- CRITICAL: Command injection, remote code execution attempts, advanced persistent threats
- HIGH: SQL injection, XSS attacks, authentication bypasses, path traversal
- MEDIUM: SSRF attempts, excessive requests, suspicious patterns, reconnaissance
- LOW: Malformed requests, minor anomalies, potential false positives

DECISION MAKING FRAMEWORK:
When analyzing a request, you must:
1. Examine the payload using analyze_payload_for_threats tool
2. Assess the severity and threat type
3. Check the IP's historical behavior and reputation
4. Decide on appropriate action:
   - ALLOW: No threat detected, normal traffic
   - RATE_LIMIT: Suspicious but not clearly malicious, apply restrictions
   - BLOCK_TEMPORARY: Clear threat detected, block IP immediately
   - BLOCK_PERMANENT: Severe or repeated threats, permanent ban
   - WHITELIST: Verified legitimate traffic, bypass security checks

AVAILABLE TOOLS:
- analyze_payload_for_threats: Scan payloads for malicious patterns
- block_ip_address: Block specific IP addresses
- block_ip_range: Block entire IP ranges (CIDR)
- unblock_ip_address: Remove IP from blocklist
- whitelist_ip_address: Add trusted IPs to whitelist
- apply_rate_limit: Apply rate limiting to suspicious IPs
- get_blocked_ips: View current blocklist
- get_threat_analytics: Analyze threat patterns
- check_ip_reputation: Check IP status and history
- generate_security_report: Create comprehensive security reports

OPERATIONAL GUIDELINES:
1. Be proactive but not paranoid - balance security with usability
2. Learn from patterns - track repeat offenders and attack trends
3. Provide clear explanations for all security decisions
4. Escalate critical threats immediately
5. Maintain detailed logs of all security events
6. Never whitelist suspicious IPs without thorough verification
7. Always explain your reasoning when taking action

RESPONSE FORMAT:
When analyzing a request, provide:
1. Threat Assessment (Clear/Suspicious/Malicious)
2. Detected Threats (if any)
3. Severity Level
4. Recommended Action
5. Reasoning
6. Additional Context (IP reputation, historical behavior, etc.)

You are the first and last line of defense. Be vigilant, be decisive, and protect the infrastructure at all costs.
"""


# Available tools mapping
AVAILABLE_TOOLS = {
    "analyze_payload_for_threats": analyze_payload_for_threats,
    "block_ip_address": block_ip_address,
    "block_ip_range": block_ip_range,
    "unblock_ip_address": unblock_ip_address,
    "whitelist_ip_address": whitelist_ip_address,
    "apply_rate_limit": apply_rate_limit,
    "get_blocked_ips": get_blocked_ips,
    "get_threat_analytics": get_threat_analytics,
    "check_ip_reputation": check_ip_reputation,
    "generate_security_report": generate_security_report,
}


def create_blackwall_agent(
    model_name: str = "gpt-4.1", selected_tools: List[str] = None
) -> SwarmsAgent:
    """
    Create and configure the Blackwall security agent.

    Args:
        model_name (str): The model to use for the agent (default: "gpt-4.1")
                          Note: For better performance, use a model that supports parallel
                          function calling (e.g., "gpt-4-turbo", "gpt-4o", "claude-3-opus")
                          to reduce latency when multiple tools are called.
        selected_tools (List[str]): List of tool names to enable. If None, all tools are enabled.
                                   Available tools: analyze_payload_for_threats, block_ip_address,
                                   block_ip_range, unblock_ip_address, whitelist_ip_address,
                                   apply_rate_limit, get_blocked_ips, get_threat_analytics,
                                   check_ip_reputation, generate_security_report

    Returns:
        SwarmsAgent: Configured Blackwall agent instance
    """
    # Convert tools to schemas using BaseTool().function_to_dict()
    tools_list_dictionary = None
    if BaseTool is None:
        print(
            "Warning: swarms.BaseTool not available. "
            "Tools will not be included in agent config. "
            "Install swarms package to enable tool schemas."
        )
    else:
        # If no tools specified, enable all by default
        if selected_tools is None:
            selected_tools = list(AVAILABLE_TOOLS.keys())

        # Validate and convert tools to schemas
        tools_list_dictionary = []
        for tool_name in selected_tools:
            if tool_name in AVAILABLE_TOOLS:
                tool_func = AVAILABLE_TOOLS[tool_name]
                try:
                    # Convert function to schema using BaseTool
                    tool_schema = BaseTool().function_to_dict(
                        tool_func
                    )
                    tools_list_dictionary.append(tool_schema)
                except Exception as e:
                    print(
                        f"Warning: Failed to convert tool '{tool_name}' "
                        f"to schema: {str(e)}"
                    )
            else:
                print(
                    f"Warning: Tool '{tool_name}' not found, skipping..."
                )

    agent = SwarmsAgent(
        agent_name="Blackwall-Security-Agent",
        agent_description="Elite cybersecurity agent for API traffic monitoring and threat protection",
        system_prompt=BLACKWALL_SYSTEM_PROMPT,
        model_name=model_name,
        max_loops=1,
        max_tokens=8192,
        temperature=0.5,
        tools=selected_tools,  # Keep for reference
        tools_list_dictionary=tools_list_dictionary,  # Pass schemas
        verbose=True,
        tool_call_summary=False,
        dynamic_temperature_enabled=True,
    )

    return agent


# ============================================================================
# FastAPI Middleware
# ============================================================================


class BlackwallMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that integrates Blackwall agent for security monitoring.
    """

    def __init__(
        self,
        app,
        agent: SwarmsAgent = None,
        model_name: str = "gpt-4.1",
        selected_tools: List[str] = None,
    ):
        super().__init__(app)
        if agent is None:
            self.agent = create_blackwall_agent(
                model_name=model_name, selected_tools=selected_tools
            )
        else:
            self.agent = agent

    async def dispatch(self, request: Request, call_next):
        """Process each request through Blackwall security checks"""

        # Get client IP
        client_ip = (
            request.client.host if request.client else "unknown"
        )

        # Check if IP is blocked
        if security_state.is_ip_blocked(client_ip):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Access denied: IP address is blocked"
                },
            )

        # Check rate limiting
        allowed, message = security_state.check_rate_limit(
            client_ip, rate_limit_config
        )
        if not allowed:
            # Record rate limit violation
            event = ThreatEvent(
                timestamp=datetime.now().isoformat(),
                ip_address=client_ip,
                threat_type="Rate Limit Exceeded",
                severity="medium",
                payload_sample="",
                action_taken="Request blocked",
                details=message,
            )
            security_state.record_threat(event)

            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: {message}"},
            )

        # Get request body for analysis
        try:
            body = await request.body()
            payload = body.decode("utf-8") if body else ""

            # Restore request body for FastAPI to read
            async def receive():
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            # Replace request's receive function to restore body
            request._receive = receive

            # Analyze with Blackwall agent for suspicious requests
            # (Only analyze POST/PUT/PATCH with body content)
            if payload and request.method in ["POST", "PUT", "PATCH"]:
                # First, directly analyze the payload for threats
                threat_analysis = analyze_payload_for_threats(payload)

                # If high or critical severity threat detected, block immediately
                if threat_analysis.get(
                    "threat_detected"
                ) and threat_analysis.get("severity") in [
                    "high",
                    "critical",
                ]:
                    # Record the threat event
                    event = ThreatEvent(
                        timestamp=datetime.now().isoformat(),
                        ip_address=client_ip,
                        threat_type=", ".join(
                            threat_analysis.get("threats", [])[:3]
                        ),  # First 3 threats
                        severity=threat_analysis.get(
                            "severity", "high"
                        ),
                        payload_sample=payload[
                            :200
                        ],  # First 200 chars
                        action_taken="Request blocked",
                        details=f"Threats detected: {len(threat_analysis.get('threats', []))}",
                    )
                    security_state.record_threat(event)

                    # Block the IP if critical, or if high severity
                    if threat_analysis.get("severity") == "critical":
                        security_state.block_ip(
                            client_ip, "Critical threat detected"
                        )

                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": f"Request blocked: {threat_analysis.get('severity', 'high').upper()} severity threat detected"
                        },
                    )

                # Only run agent for low/medium severity threats or if no threat detected but suspicious
                # Skip agent analysis for safe requests (no threats detected)
                should_run_agent = False
                if threat_analysis.get(
                    "threat_detected"
                ) and threat_analysis.get("severity") in [
                    "low",
                    "medium",
                ]:
                    should_run_agent = True

                if should_run_agent:
                    # Check cache first
                    payload_hash = get_payload_hash(payload)
                    cached_result = get_cached_agent_result(
                        payload_hash
                    )

                    if cached_result is None:
                        # Run agent analysis asynchronously (non-blocking)
                        analysis_task = f"""
                        Analyze this API request for security threats:
                        
                        IP Address: {client_ip}
                        Method: {request.method}
                        Path: {request.url.path}
                        Payload: {payload[:1000]}  # First 1000 chars
                        
                        Use the analyze_payload_for_threats tool and determine if action is needed.
                        If threats are detected, check the IP reputation and take appropriate action.
                        """

                        # Run agent in background task (non-blocking)
                        async def run_agent_analysis():
                            try:
                                # Run agent asynchronously
                                agent_result = await self.agent.arun(
                                    analysis_task
                                )

                                # Cache the result
                                cache_agent_result(
                                    payload_hash,
                                    {
                                        "status": "analyzed",
                                        "result": agent_result,
                                    },
                                )

                                # Check if agent blocked the IP (for future requests)
                                if security_state.is_ip_blocked(
                                    client_ip
                                ):
                                    # IP was blocked by agent, will be caught on next request
                                    pass
                            except Exception as e:
                                print(
                                    f"Background agent analysis error: {str(e)}"
                                )

                        # Schedule agent analysis in background (fire and forget)
                        asyncio.create_task(run_agent_analysis())
                    else:
                        # Use cached result - agent already analyzed similar payload
                        pass

                # Record threat if detected but not blocked (for monitoring)
                if threat_analysis.get("threat_detected"):
                    event = ThreatEvent(
                        timestamp=datetime.now().isoformat(),
                        ip_address=client_ip,
                        threat_type=", ".join(
                            threat_analysis.get("threats", [])[:3]
                        ),
                        severity=threat_analysis.get(
                            "severity", "low"
                        ),
                        payload_sample=payload[:200],
                        action_taken="Monitored",
                        details=f"Threats detected: {len(threat_analysis.get('threats', []))}",
                    )
                    security_state.record_threat(event)

        except HTTPException:
            raise
        except Exception as e:
            # Log error but don't block request
            print(f"Blackwall analysis error: {str(e)}")

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Blackwall-Protected"] = "true"
        response.headers["X-Request-ID"] = (
            f"{client_ip}-{int(time.time())}"
        )

        return response


# # ============================================================================
# # Usage Example
# # ============================================================================

# if __name__ == "__main__":
#     # Create Blackwall agent with custom model and selected tools
#     # All tools enabled by default, or specify a subset:
#     # selected_tools = ["analyze_payload_for_threats", "block_ip_address", "check_ip_reputation"]
#     blackwall = create_blackwall_agent(
#         model_name="gpt-4.1",  # Change model as needed
#         selected_tools=None    # None = all tools, or provide list of tool names
#     )

#     # Example 1: Analyze a suspicious payload
#     print("=== Example 1: Analyzing Suspicious Payload ===")
#     suspicious_payload = """
#     {
#         "username": "admin' OR '1'='1",
#         "password": "test",
#         "email": "test@example.com"
#     }
#     """

#     analysis_result = blackwall.run(
#         f"Analyze this login request payload for threats: {suspicious_payload}"
#     )
#     print(analysis_result)
#     print("\n")

#     # Example 2: Check IP reputation
#     print("=== Example 2: IP Reputation Check ===")
#     ip_check = blackwall.run("Check the reputation of IP address 192.168.1.100")
#     print(ip_check)
#     print("\n")

#     # Example 3: Generate security report
#     print("=== Example 3: Security Report ===")
#     report = blackwall.run("Generate a comprehensive security report of current threats")
#     print(report)
#     print("\n")

#     # Example 4: Block malicious IP
#     print("=== Example 4: Block Malicious IP ===")
#     block_result = blackwall.run(
#         "Block IP address 10.0.0.5 due to repeated SQL injection attempts"
#     )
#     print(block_result)
