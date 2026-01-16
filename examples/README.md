# Blackwall Examples

This directory contains example applications demonstrating Blackwall security middleware integration.

## Example Applications

### 🛡️ Security Test Suite
**Location:** `security_test_suite/`

A comprehensive test suite for validating Blackwall security middleware functionality with multiple attack scenarios.

- **`test_server.py`** - FastAPI server with multiple endpoints to test Blackwall middleware
- **`test_client.py`** - Comprehensive test client that runs various security test scenarios

### 🛒 E-Commerce API
**Location:** `ecommerce_api/`

A full-featured e-commerce API protected by Blackwall, featuring user management, product catalog, search functionality, and admin operations.

- **`api.py`** - Complete e-commerce API with Blackwall protection

### 👤 User Management API
**Location:** `user_management_api/`

A simple user management API demonstrating basic Blackwall middleware integration with authentication and user creation endpoints.

- **`example.py`** - FastAPI app with login and user creation endpoints
- **`client_example.py`** - Client code to test the protected API

### 🔍 Security Testing Client
**Location:** `security_testing_client/`

A comprehensive security testing client that demonstrates various attack patterns to test Blackwall's detection capabilities.

- **`test.py`** - Security testing client with various attack patterns
- **`schema_test.py`** - Schema validation examples

## Prerequisites

1. Install Blackwall and its dependencies:
   ```bash
   pip install -e .
   ```

2. Set your Swarms API key:
   ```bash
   export SWARMS_API_KEY="your-api-key-here"
   ```

## Quick Start

### Security Test Suite

1. **Start the test server:**
   ```bash
   uvicorn examples.security_test_suite.test_server:app --reload --port 8001
   ```

2. **In another terminal, run the test client:**
   ```bash
   python examples/security_test_suite/test_client.py
   ```

### E-Commerce API

```bash
cd examples/ecommerce_api
uvicorn api:app --reload --port 8000
```

### User Management API

```bash
cd examples/user_management_api
uvicorn example:app --reload --port 8000
```

See each example's README.md for detailed instructions.

## Security Test Suite Endpoints

The security test suite server provides the following endpoints:

### Public Endpoints
- `GET /` - API information and endpoint list
- `GET /health` - Health check endpoint
- `GET /api/info` - API details and security features

### Authentication
- `POST /api/auth/login` - User login (tests SQL/command injection)

### User Management
- `POST /api/users` - Create user (tests XSS)
- `GET /api/users/{user_id}` - Get user by ID

### Product Management
- `POST /api/products` - Create product (tests injection)
- `GET /api/products` - List products with filtering

### Comments
- `POST /api/comments` - Create comment (tests XSS)

### Search
- `POST /api/search` - Search endpoint (tests SQL injection, SSRF)

### Data
- `GET /api/data/{resource}` - Get data resource (tests path traversal)

## Security Test Suite Test Cases

The security test suite client runs the following test cases:

### 1. Health Check
- Basic connectivity test

### 2. Legitimate Requests
- Tests that normal, safe requests are allowed through
- Includes legitimate login, user creation, product creation, and search

### 3. SQL Injection Detection
- Tests various SQL injection patterns:
  - `admin' OR '1'='1`
  - `admin' UNION SELECT * FROM users--`
  - `admin'; DROP TABLE users;--`

### 4. XSS Attack Detection
- Tests various XSS payloads:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `javascript:alert('XSS')`

### 5. Command Injection Detection
- Tests command injection attempts:
  - `admin; rm -rf /`
  - `test || cat /etc/passwd`
  - `test; ls -la`
  - `test `whoami``

### 6. Path Traversal Detection
- Tests path traversal attacks:
  - `../../../etc/passwd`
  - `..\\..\\..\\windows\\system32`
  - URL-encoded variants

### 7. SSRF Detection
- Tests Server-Side Request Forgery attempts:
  - `http://localhost:8080`
  - `http://127.0.0.1/admin`
  - `file:///etc/passwd`

### 8. Large Payload Detection
- Tests detection of unusually large payloads (>100KB)

### 9. Rate Limiting
- Tests rate limiting by sending rapid requests

### 10. Mixed Threat Types
- Tests requests containing multiple threat types simultaneously

## Expected Behavior

### Legitimate Requests
- **Status Code:** `200 OK`
- **Response:** Normal API response with data

### Malicious Requests
- **Status Code:** `403 Forbidden`
- **Response:** 
  ```json
  {
    "detail": "Request blocked: HIGH severity threat detected"
  }
  ```
  or
  ```json
  {
    "detail": "Request blocked: CRITICAL severity threat detected"
  }
  ```

## Security Test Suite Configuration

The security test suite server is configured with:
- **Model:** `gpt-4.1`
- **Tools:** All security tools enabled
- **Agent Mode:** `run_agent_on_all_requests=True` (agent analyzes every request)

You can modify these settings in `security_test_suite/test_server.py`:

```python
app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4.1",  # Change model here
    selected_tools=None,  # Or specify tools: ["analyze_payload_for_threats", "block_ip_address"]
    run_agent_on_all_requests=True,  # Set to False for standard mode
)
```

## Viewing Results

### Server Logs
The server logs will show:
- Agent analysis for each request
- Function calls executed by the agent
- IP blocking/unblocking actions
- Threat detection details

### Client Output
The test client prints:
- Test name and description
- HTTP status code
- Full response body
- Formatted output for easy reading

## API Documentation

Once the server is running, you can view interactive API documentation at:
- **Swagger UI:** http://localhost:8001/docs
- **ReDoc:** http://localhost:8001/redoc

## Troubleshooting

### Server Won't Start
- Check that port 8001 is not already in use
- Verify Blackwall is installed: `pip install -e .`
- Check that `SWARMS_API_KEY` is set

### Tests Failing
- Ensure the server is running before running tests
- Check server logs for error messages
- Verify your API key is valid

### Agent Not Running
- Check that `SWARMS_API_KEY` environment variable is set
- Verify the API key is valid
- Check server logs for agent initialization messages

## Customization

You can customize the security test suite by:
1. Modifying test cases in `security_test_suite/test_client.py`
2. Adding new endpoints in `security_test_suite/test_server.py`
3. Adjusting middleware configuration
4. Changing threat detection patterns

## Notes

- The server runs on port **8001** to avoid conflicts with other examples
- All requests are analyzed by the Blackwall agent when `run_agent_on_all_requests=True`
- IP addresses may be blocked after multiple malicious requests
- The agent can unblock IPs if it determines a block was a false positive
