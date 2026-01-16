import requests
import json
import time

BASE_URL = "http://localhost:8001"


def print_response(response: requests.Response, test_name: str):
    """Helper function to print response details"""
    print(f"\n{'='*60}")
    print(f"Test: {test_name}")
    print(f"{'='*60}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception:
        print(f"Response: {response.text}")
    print(f"{'='*60}\n")


def test_health_check():
    """Test basic health check endpoint"""
    print("Testing health check...")
    response = requests.get(f"{BASE_URL}/health")
    print_response(response, "Health Check")
    return response.status_code == 200


def test_legitimate_requests():
    """Test legitimate requests that should be allowed"""
    print("\n" + "=" * 60)
    print("TESTING LEGITIMATE REQUESTS (Should be allowed)")
    print("=" * 60)

    # Test legitimate login
    print("\n1. Legitimate Login")
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin", "password": "password123"},
    )
    print_response(response, "Legitimate Login")

    # Test legitimate user creation
    print("\n2. Legitimate User Creation")
    response = requests.post(
        f"{BASE_URL}/api/users",
        json={
            "name": "John Doe",
            "email": "john@example.com",
            "bio": "Regular user biography",
            "age": 30,
        },
    )
    print_response(response, "Legitimate User Creation")

    # Test legitimate product creation
    print("\n3. Legitimate Product Creation")
    response = requests.post(
        f"{BASE_URL}/api/products",
        json={
            "name": "Laptop",
            "description": "High-performance laptop",
            "price": 999.99,
            "category": "Electronics",
        },
    )
    print_response(response, "Legitimate Product Creation")

    # Test legitimate search
    print("\n4. Legitimate Search")
    response = requests.post(
        f"{BASE_URL}/api/search",
        json={
            "query": "laptop",
            "filters": {"category": "electronics"},
        },
    )
    print_response(response, "Legitimate Search")


def test_sql_injection():
    """Test SQL injection detection"""
    print("\n" + "=" * 60)
    print("TESTING SQL INJECTION DETECTION")
    print("=" * 60)

    test_cases = [
        (
            "Login SQL Injection",
            {"username": "admin' OR '1'='1", "password": "test"},
        ),
        (
            "Login SQL Injection (Union)",
            {
                "username": "admin' UNION SELECT * FROM users--",
                "password": "test",
            },
        ),
        (
            "Login SQL Injection (Drop Table)",
            {
                "username": "admin'; DROP TABLE users;--",
                "password": "test",
            },
        ),
    ]

    for name, payload in test_cases:
        print(f"\n{name}")
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json=payload,
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def test_xss_attacks():
    """Test XSS attack detection"""
    print("\n" + "=" * 60)
    print("TESTING XSS ATTACK DETECTION")
    print("=" * 60)

    test_cases = [
        (
            "XSS in User Name",
            {
                "name": "<script>alert('XSS')</script>",
                "email": "test@example.com",
                "bio": "test",
            },
        ),
        (
            "XSS in User Bio",
            {
                "name": "John Doe",
                "email": "john@example.com",
                "bio": "<img src=x onerror=alert('XSS')>",
            },
        ),
        (
            "XSS in Comment",
            {
                "post_id": 1,
                "content": "<script>document.cookie</script>",
                "author": "attacker",
            },
        ),
        (
            "XSS JavaScript Protocol",
            {
                "name": "Test User",
                "email": "test@example.com",
                "bio": "javascript:alert('XSS')",
            },
        ),
    ]

    for name, payload in test_cases:
        print(f"\n{name}")
        if "post_id" in payload:
            endpoint = "/api/comments"
        else:
            endpoint = "/api/users"

        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def test_command_injection():
    """Test command injection detection"""
    print("\n" + "=" * 60)
    print("TESTING COMMAND INJECTION DETECTION")
    print("=" * 60)

    test_cases = [
        (
            "Command Injection in Login",
            {
                "username": "admin; rm -rf /",
                "password": "test || cat /etc/passwd",
            },
        ),
        (
            "Command Injection in Search",
            {"query": "test; ls -la", "filters": {}},
        ),
        (
            "Command Injection with Pipe",
            {
                "username": "admin | cat /etc/passwd",
                "password": "test",
            },
        ),
        (
            "Command Injection with Backticks",
            {"query": "test `whoami`", "filters": {}},
        ),
    ]

    for name, payload in test_cases:
        print(f"\n{name}")
        if "username" in payload:
            endpoint = "/api/auth/login"
        else:
            endpoint = "/api/search"

        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def test_path_traversal():
    """Test path traversal detection"""
    print("\n" + "=" * 60)
    print("TESTING PATH TRAVERSAL DETECTION")
    print("=" * 60)

    test_cases = [
        ("Path Traversal - etc/passwd", "../../../etc/passwd"),
        ("Path Traversal - Windows", "..\\..\\..\\windows\\system32"),
        ("Path Traversal - Encoded", "..%2F..%2F..%2Fetc%2Fpasswd"),
        ("Path Traversal - Backslash", "..%5C..%5C..%5Cwindows"),
    ]

    for name, resource in test_cases:
        print(f"\n{name}")
        response = requests.get(
            f"{BASE_URL}/api/data/{resource}",
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def test_ssrf_attempts():
    """Test SSRF (Server-Side Request Forgery) detection"""
    print("\n" + "=" * 60)
    print("TESTING SSRF DETECTION")
    print("=" * 60)

    test_cases = [
        (
            "SSRF - localhost",
            {"query": "http://localhost:8080", "filters": {}},
        ),
        (
            "SSRF - 127.0.0.1",
            {"query": "http://127.0.0.1/admin", "filters": {}},
        ),
        (
            "SSRF - Internal IP",
            {
                "query": "http://169.254.169.254/latest/meta-data",
                "filters": {},
            },
        ),
        (
            "SSRF - File Protocol",
            {"query": "file:///etc/passwd", "filters": {}},
        ),
    ]

    for name, payload in test_cases:
        print(f"\n{name}")
        response = requests.post(
            f"{BASE_URL}/api/search",
            json=payload,
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def test_large_payload():
    """Test detection of unusually large payloads"""
    print("\n" + "=" * 60)
    print("TESTING LARGE PAYLOAD DETECTION")
    print("=" * 60)

    # Create a large payload (>100KB)
    large_content = "A" * 150000  # 150KB

    print("\nLarge Payload Test")
    response = requests.post(
        f"{BASE_URL}/api/comments",
        json={
            "post_id": 1,
            "content": large_content,
            "author": "test",
        },
    )
    print_response(response, "Large Payload")
    print(f"Payload size: {len(large_content)} bytes")


def test_rate_limiting():
    """Test rate limiting (if enabled)"""
    print("\n" + "=" * 60)
    print("TESTING RATE LIMITING")
    print("=" * 60)

    print("\nSending multiple rapid requests...")
    for i in range(15):
        response = requests.get(f"{BASE_URL}/health")
        print(
            f"Request {i+1}: Status {response.status_code}", end="\r"
        )
        time.sleep(0.1)
    print("\n")


def test_mixed_threats():
    """Test requests with multiple threat types"""
    print("\n" + "=" * 60)
    print("TESTING MIXED THREAT TYPES")
    print("=" * 60)

    test_cases = [
        (
            "SQL Injection + XSS",
            {
                "name": "<script>alert('XSS')</script>",
                "email": "admin' OR '1'='1@example.com",
                "bio": "test",
            },
        ),
        (
            "Command Injection + Path Traversal",
            {
                "query": "../../etc/passwd; cat /etc/passwd",
                "filters": {},
            },
        ),
    ]

    for name, payload in test_cases:
        print(f"\n{name}")
        if "name" in payload:
            endpoint = "/api/users"
        else:
            endpoint = "/api/search"

        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
        )
        print_response(response, name)
        time.sleep(1.0)  # Increased delay to avoid rate limiting


def run_all_tests():
    """Run all test suites"""
    print("\n" + "=" * 80)
    print("BLACKWALL MIDDLEWARE COMPREHENSIVE TEST SUITE")
    print("=" * 80)

    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=2)
        if response.status_code != 200:
            print("❌ Server is not responding correctly!")
            return
    except requests.exceptions.RequestException:
        print("❌ Server is not running!")
        print(
            "Please start the server with: uvicorn examples.security_test_suite.test_server:app --reload --port 8001"
        )
        print(
            "Or from this directory: uvicorn test_server:app --reload --port 8001"
        )
        return

    print("✅ Server is running!\n")

    # Run test suites
    test_health_check()
    test_legitimate_requests()
    test_sql_injection()
    test_xss_attacks()
    test_command_injection()
    # test_path_traversal()
    # test_ssrf_attempts()
    # test_large_payload()
    # test_rate_limiting()
    # test_mixed_threats()

    print("\n" + "=" * 80)
    print("TEST SUITE COMPLETE")
    print("=" * 80)
    print(
        "\nCheck the server logs to see Blackwall agent analysis results."
    )


if __name__ == "__main__":
    run_all_tests()
