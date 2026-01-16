# Security Test Suite

This folder contains a complete test suite for validating Blackwall security middleware functionality.

## Files

- **`test_server.py`** - FastAPI server with multiple endpoints to test Blackwall middleware
- **`test_client.py`** - Comprehensive test client that runs various security test scenarios

## Quick Start

1. **Start the test server:**
   ```bash
   uvicorn examples.security_test_suite.test_server:app --reload --port 8001
   ```

2. **In another terminal, run the test client:**
   ```bash
   python examples/security_test_suite/test_client.py
   ```

## Test Coverage

- ✅ Legitimate requests (should pass)
- ✅ SQL Injection detection
- ✅ XSS attack detection
- ✅ Command injection detection
- ✅ Path traversal detection
- ✅ SSRF detection
- ✅ Rate limiting
- ✅ Large payload detection

See the main examples README.md for detailed documentation.
