# Blackwall

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Blackwall** is an enterprise-grade API security middleware designed to protect FastAPI applications from malicious attacks and unauthorized access. Built on the Swarms AI platform, Blackwall combines rule-based pattern detection with intelligent AI-powered threat analysis to provide comprehensive, real-time security for your API infrastructure.

## Overview


```mermaid
flowchart TD
    A[Incoming Request] --> B{IP Blocked?}
    B -->|Yes| C[Block & Respond]
    B -->|No| D{Rate Limit Exceeded?}
    D -->|Yes| E[Block & Respond]
    D -->|No| F[Analyze Request]
    F --> G{Threat Detected?}
    G -->|Yes| H[Block or Rate Limit]
    G -->|No| I[Allow Request]
    H --> J[Respond]
    I --> J
    E --> J
    C --> J
```


Blackwall acts as a security layer that sits between incoming requests and your FastAPI application endpoints. It automatically analyzes all incoming traffic, detects a wide range of attack patterns including SQL injection, XSS, command injection, and more, then takes immediate protective action by blocking malicious IPs and rate-limiting suspicious activity.

Unlike traditional security solutions that rely solely on static rules, Blackwall leverages AI to make intelligent security decisions, reducing false positives while maintaining high detection accuracy. The middleware integrates seamlessly into existing FastAPI applications with minimal configuration, requiring only a single line of code to enable comprehensive protection.

Key capabilities include automated threat detection, intelligent IP blocking, configurable rate limiting, comprehensive threat analytics, and real-time security monitoring. Blackwall is designed for production environments, with features like request caching, asynchronous processing, and detailed logging to ensure minimal performance impact while providing maximum security coverage.

## Features

- **Real-time Threat Detection**: Detects SQL injection, XSS, command injection, path traversal, SSRF, and XXE attacks
- **AI-Powered Analysis**: Uses Swarms API for intelligent threat assessment and decision-making
- **Automated IP Blocking**: Automatically blocks malicious IP addresses and IP ranges
- **Rate Limiting**: Configurable rate limiting to prevent abuse and DDoS attacks
- **Threat Analytics**: Comprehensive threat reporting and IP reputation tracking
- **Zero Configuration**: Works out of the box with sensible defaults
- **Production Ready**: Built for high-performance production environments

## Installation

Install Blackwall using pip:

```bash
pip install blackwall-gateway
```

## Quick Start

### Basic Usage

Add Blackwall middleware to your FastAPI application:

```python
from fastapi import FastAPI
from blackwall.main import BlackwallMiddleware

app = FastAPI(title="My Protected API")

# Add Blackwall middleware with default settings
app.add_middleware(BlackwallMiddleware)

@app.get("/api/data")
async def get_data():
    return {"message": "This endpoint is protected by Blackwall"}
```

### Environment Setup

**Get your API key**: Obtain your Swarms API key from the [Swarms Dashboard](https://swarms.world/platform/api-keys).

Set your Swarms API key as an environment variable:

```bash
export SWARMS_API_KEY="your-api-key-here"
```

Or create a `.env` file:

```env
SWARMS_API_KEY=your-api-key-here
```

## Middleware Configuration

### Default Configuration

The simplest way to use Blackwall is with default settings:

```python
from fastapi import FastAPI
from blackwall.main import BlackwallMiddleware

app = FastAPI()
app.add_middleware(BlackwallMiddleware)
```

This enables:

- All security tools
- Default model (`gpt-4.1`)
- Automatic threat detection
- IP blocking and rate limiting

### Custom Model Configuration

Specify a different AI model:

```python
app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4o"  # or "gpt-4o-mini", "claude-sonnet-4-20250514", etc.
)
```

### Selective Tool Configuration

Enable only specific security tools:

```python
app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4.1",
    selected_tools=[
        "analyze_payload_for_threats",
        "block_ip_address",
        "check_ip_reputation"
    ]
)
```

Available tools:

- `analyze_payload_for_threats` - Scan payloads for malicious patterns
- `block_ip_address` - Block specific IP addresses
- `block_ip_range` - Block IP ranges (CIDR notation)
- `unblock_ip_address` - Remove IP from blocklist
- `whitelist_ip_address` - Add trusted IPs to whitelist
- `apply_rate_limit` - Apply rate limiting to suspicious IPs
- `get_blocked_ips` - View current blocklist
- `get_threat_analytics` - Analyze threat patterns
- `check_ip_reputation` - Check IP reputation and history
- `generate_security_report` - Generate comprehensive security reports

### Advanced Configuration

Create a custom agent and pass it to the middleware:

```python
from blackwall.main import create_blackwall_agent, BlackwallMiddleware
from fastapi import FastAPI

# Create custom agent with specific configuration
blackwall_agent = create_blackwall_agent(
    model_name="gpt-4.1",
    selected_tools=["analyze_payload_for_threats", "block_ip_address"]
)

app = FastAPI()
app.add_middleware(BlackwallMiddleware, agent=blackwall_agent)
```

## Complete Example

Here's a complete example of a protected FastAPI application:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from blackwall.main import BlackwallMiddleware

app = FastAPI(
    title="Protected API",
    description="API protected by Blackwall security middleware",
    version="1.0.0"
)

# Add Blackwall middleware
app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4.1",
    selected_tools=None  # None = all tools enabled
)

# Request models
class LoginRequest(BaseModel):
    username: str
    password: str

class UserData(BaseModel):
    name: str
    email: str
    bio: str

# Protected endpoints
@app.get("/")
async def root():
    return {
        "message": "Blackwall Protected API",
        "status": "active"
    }

@app.post("/login")
async def login(credentials: LoginRequest):
    """Login endpoint - automatically protected by Blackwall"""
    if credentials.username == "admin" and credentials.password == "password":
        return {"message": "Login successful", "token": "fake-token"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/users")
async def create_user(user: UserData):
    """Create user endpoint - protected against XSS and injection attacks"""
    return {
        "message": "User created",
        "user": {"name": user.name, "email": user.email}
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Request Flow

1. **Request Interception**: Blackwall middleware intercepts all incoming requests
2. **IP Validation**: Checks if the IP is blocked or whitelisted
3. **Rate Limiting**: Validates request rate against configured limits
4. **Threat Analysis**: Analyzes request payloads for malicious patterns
5. **AI Assessment**: Uses Swarms API for intelligent threat assessment (for suspicious requests)
6. **Action**: Blocks malicious requests, allows legitimate traffic
7. **Response**: Adds security headers to all responses

### Threat Detection

Blackwall detects the following attack patterns:

| Threat Type        | Detection Method                    | Response                    |
|--------------------|-------------------------------------|-----------------------------|
| SQL Injection      | Pattern matching + AI analysis      | Immediate block             |
| XSS                | Script tag detection + AI analysis  | Immediate block             |
| Command Injection  | Command pattern detection           | Immediate block (critical)  |
| Path Traversal     | Directory traversal patterns        | Block                       |
| SSRF               | Internal network request detection  | Rate limit or block         |
| XXE                | XML entity detection                | Block                       |

### Security Headers

Blackwall automatically adds security headers to all responses:

- `X-Blackwall-Protected: true` - Indicates Blackwall is active
- `X-Request-ID: {ip}-{timestamp}` - Unique request identifier

## Configuration Options

### Rate Limiting

Rate limiting is configured per IP address:

```python
from blackwall.main import rate_limit_config

# Adjust rate limits
rate_limit_config.requests_per_minute = 100
rate_limit_config.requests_per_hour = 2000
rate_limit_config.burst_limit = 20
```

### IP Management

Manage blocked and whitelisted IPs programmatically:

```python
from blackwall.main import (
    block_ip_address,
    unblock_ip_address,
    whitelist_ip_address,
    get_blocked_ips
)

# Block an IP
block_ip_address("192.168.1.100", reason="Repeated SQL injection attempts")

# Whitelist a trusted IP
whitelist_ip_address("10.0.0.1")

# Get current blocklist
blocked = get_blocked_ips()
print(blocked)
```

### Performance Considerations

- **Caching**: Blackwall caches agent analysis results to reduce API calls
- **Async Processing**: Agent analysis runs asynchronously to minimize latency
- **Selective Analysis**: Only suspicious requests trigger AI analysis
- **Direct Blocking**: High-severity threats are blocked immediately without AI analysis

### Monitoring

Blackwall uses `loguru` for logging. Configure log levels:

```python
from loguru import logger

# Set log level
logger.remove()
logger.add("blackwall.log", rotation="10 MB", level="INFO")
logger.add(lambda msg: print(msg, end=""), level="DEBUG")
```

## API Reference

### BlackwallMiddleware

FastAPI middleware class that provides security protection.

**Parameters:**

- `agent` (SwarmsAgent, optional): Pre-configured agent instance
- `model_name` (str, default: "gpt-4.1"): AI model to use
- `selected_tools` (List[str], optional): List of tool names to enable

### create_blackwall_agent

Factory function to create a Blackwall security agent.

**Parameters:**

- `model_name` (str, default: "gpt-4.1"): AI model to use
- `selected_tools` (List[str], optional): List of tool names to enable

**Returns:** `SwarmsAgent` instance

## Security Best Practices

1. **API Key Security**: Store `SWARMS_API_KEY` in environment variables, never in code
2. **Whitelist Management**: Carefully manage whitelisted IPs to avoid bypassing security
3. **Regular Monitoring**: Review threat analytics regularly to identify attack patterns
4. **Rate Limit Tuning**: Adjust rate limits based on your application's traffic patterns
5. **False Positive Handling**: Monitor for false positives and adjust detection rules
6. **Logging**: Enable comprehensive logging for security auditing
7. **Backup State**: Regularly backup security state (blocked IPs, etc.)

## Troubleshooting

### Common Issues

**Issue**: `ValueError: API key is required`

**Solution**: Set the `SWARMS_API_KEY` environment variable:

```bash
export SWARMS_API_KEY="your-key"
```

**Issue**: High latency on requests

**Solution**:

- Use a faster model (e.g., `gpt-4o-mini`)
- Reduce the number of enabled tools
- Check your network connection to `api.swarms.world`

**Issue**: Too many false positives

**Solution**:

- Whitelist trusted IPs
- Adjust rate limiting thresholds
- Review and tune detection patterns

## Contributing

Contributions are welcome! Please ensure that:

- All security features are thoroughly tested
- Documentation is updated for new features
- Code follows security best practices
- Tests pass before submitting PRs

## License

Apache-2.0 License - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [Full Documentation](https://github.com/The-Swarm-Corporation/Blackwall)
- **Issues**: [GitHub Issues](https://github.com/The-Swarm-Corporation/Blackwall/issues)
- **Discussions**: [GitHub Discussions](https://github.com/The-Swarm-Corporation/Blackwall/discussions)

## Acknowledgments

Built with [Swarms](https://swarms.world) and [FastAPI](https://fastapi.tiangolo.com/).

---

**Security Notice**: Blackwall provides application-layer protection. For comprehensive security, use it alongside network-level security measures, proper authentication, and regular security audits.
