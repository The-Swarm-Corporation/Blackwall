# Blackwall Security Agent

Blackwall is a comprehensive API security agent designed to protect web applications from malicious threats. Built on the Swarms framework, it provides real-time monitoring, threat detection, and automated response capabilities for API infrastructure.

## Overview

Blackwall implements an intelligent security layer that analyzes incoming API traffic, detects various types of attacks, and takes appropriate protective measures. The system combines machine learning-powered threat detection with rule-based security policies to provide robust protection against common web application vulnerabilities.

## Key Features

### Threat Detection

| Feature                          | Description                                                                                     |
|-----------------------------------|-------------------------------------------------------------------------------------------------|
| **SQL Injection**                 | Detects and blocks SQL injection attempts using pattern matching and behavioral analysis         |
| **Cross-Site Scripting (XSS)**    | Identifies malicious scripts and prevents XSS attacks                                           |
| **Command Injection**             | Blocks attempts to execute system commands through API endpoints                                |
| **Path Traversal**                | Prevents directory traversal and file system access attacks                                     |
| **Server-Side Request Forgery (SSRF)** | Detects and blocks internal network requests                                            |
| **XML External Entity (XXE)**     | Protects against XML-based attacks                                                              |
| **IP Blocking**                   | Automatically blocks malicious IP addresses and ranges                                          |
| **Rate Limiting**                 | Implements configurable rate limiting to prevent abuse                                          |
| **IP Whitelisting**               | Allows trusted IP addresses to bypass security checks                                           |
| **Suspicion Scoring**             | Tracks and scores IP addresses based on suspicious behavior                                     |

## Architecture

### Core Components

#### Security Agent (`blackwall_agent_new.py`)
The main security agent powered by the Swarms framework. It includes:
- AI-driven threat analysis and decision making
- Comprehensive tool set for security operations
- Automated response capabilities

#### Middleware (`BlackwallMiddleware`)
FastAPI middleware that intercepts all incoming requests and applies security checks before they reach the application endpoints.

#### Security State Manager
Centralized state management for:
- Blocked and whitelisted IP addresses
- Rate limiting data
- Threat event logs
- Security configuration

#### Demo API Server (`api.py`)
A sample FastAPI application demonstrating how to integrate Blackwall protection into existing applications.

## Installation

```bash
# Install required dependencies
pip install swarms fastapi uvicorn pydantic loguru

# Clone or navigate to the project directory
cd blackwall/
```

## Quick Start

### 1. Running the Demo Server

```bash
# Start the protected API server
python api.py
```

The server will start on `http://localhost:8000` with Blackwall protection enabled.

### 2. Basic Usage

```python
from blackwall_agent_new import create_blackwall_agent, BlackwallMiddleware
from fastapi import FastAPI

# Create the security agent
agent = create_blackwall_agent()

# Create your FastAPI application
app = FastAPI(title="My Protected API")

# Add Blackwall middleware
app.add_middleware(BlackwallMiddleware)

# Your API endpoints will now be protected
@app.get("/api/data")
def get_data():
    return {"message": "This endpoint is protected by Blackwall"}
```

### 3. Testing the Protection

```bash
# Run the test suite
python test.py
```

The test suite includes various attack scenarios to demonstrate Blackwall's detection capabilities.

## Configuration

### Rate Limiting

Configure rate limiting parameters:

```python
from blackwall_agent_new import rate_limit_config

# Adjust rate limits
rate_limit_config.requests_per_minute = 100
rate_limit_config.requests_per_hour = 2000
rate_limit_config.burst_limit = 20
```

### Security Policies

Customize threat detection sensitivity and response actions through the agent's system prompt and configuration.

## API Endpoints

The demo server provides the following protected endpoints:

- `GET /` - Health check
- `POST /auth/login` - User authentication
- `GET /api/products` - Product listing
- `POST /api/products` - Create product
- `POST /api/search` - Search functionality
- `GET /admin/security/status` - Security status (requires authentication)
- `POST /admin/security/block-ip` - Block IP address (admin only)

## Security Agent Tools

The Blackwall agent provides the following tools for security operations:

- `analyze_payload_for_threats` - Scan request payloads for malicious content
- `block_ip_address` - Block specific IP addresses
- `block_ip_range` - Block IP ranges using CIDR notation
- `unblock_ip_address` - Remove IP addresses from blocklist
- `whitelist_ip_address` - Add trusted IPs to whitelist
- `apply_rate_limit` - Apply rate limiting to suspicious IPs
- `get_blocked_ips` - View current blocklist
- `get_threat_analytics` - Analyze threat patterns and statistics
- `check_ip_reputation` - Check IP address reputation and history
- `generate_security_report` - Create comprehensive security reports

## Threat Response Framework

Blackwall implements a graduated response system:

1. **Allow**: Normal traffic with no threats detected
2. **Monitor**: Suspicious but not clearly malicious activity
3. **Rate Limit**: Apply restrictions to suspicious IPs
4. **Block Temporary**: Immediate blocking for clear threats
5. **Block Permanent**: Permanent banning for severe or repeated offenses

## Monitoring and Analytics

### Real-time Monitoring
- Continuous traffic analysis
- Threat pattern recognition
- Automated incident response

### Reporting
- Comprehensive security reports
- Threat trend analysis
- IP reputation tracking
- Performance metrics

## Best Practices

1. **Deployment**: Deploy Blackwall in front of your API endpoints for maximum protection
2. **Configuration**: Tune detection sensitivity based on your application's needs
3. **Monitoring**: Regularly review security reports and threat analytics
4. **Updates**: Keep threat detection patterns updated with emerging attack vectors
5. **Testing**: Regularly test your protected endpoints with the provided test suite

## Security Considerations

- Blackwall provides application-layer protection but should be used with network-level security measures
- Regularly backup security state and configuration
- Monitor for false positives and adjust detection rules accordingly
- Implement proper logging and alerting for security events

## License

This project is part of the Swarms framework. Please refer to the main project license for usage terms.

## Contributing

Contributions to Blackwall are welcome. Please ensure that:
- All security features are thoroughly tested
- Documentation is updated for any new features
- Code follows established patterns and security best practices

## Support

For issues, questions, or contributions:
- Review the main Swarms documentation
- Check the test suite for usage examples
- Examine the demo API server for integration patterns