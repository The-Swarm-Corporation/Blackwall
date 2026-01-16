import json
from typing import Any, Dict

import requests
from loguru import logger


def print_error(message: str):
    """Print error message using loguru"""
    logger.error(message)


def print_success(message: str):
    """Print success message using loguru"""
    logger.success(message)


def print_warning(message: str):
    """Print warning message using loguru"""
    logger.warning(message)


def print_section(title: str):
    """Print section header"""
    logger.info(f"\n{'='*50}")
    logger.info(f"🔍 {title}")
    logger.info(f"{'='*50}")


# API Base URL
BASE_URL = "http://localhost:8000"


def make_request(
    method: str,
    endpoint: str,
    data: Dict[str, Any] = None,
    params: Dict[str, Any] = None,
    description: str = "",
) -> tuple[bool, Any]:
    """
    Make an API request and handle the response

    Returns:
        tuple: (success: bool, response_data: Any)
    """
    url = f"{BASE_URL}{endpoint}"

    logger.info(f"\n📡 Request: {method} {endpoint}")
    if description:
        logger.info(f"🎯 Purpose: {description}")

    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params)
        elif method.upper() == "POST":
            response = requests.post(url, json=data)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data)
        elif method.upper() == "DELETE":
            response = requests.delete(url)
        else:
            print_error(f"Unsupported method: {method}")
            return False, None

        # Print status
        if response.status_code == 200:
            print_success(f"Status: {response.status_code} OK")
        elif response.status_code == 403:
            print_error(
                f"Status: {response.status_code} BLOCKED BY BLACKWALL"
            )
        elif response.status_code == 429:
            print_warning(
                f"Status: {response.status_code} RATE LIMITED"
            )
        else:
            print_warning(f"Status: {response.status_code}")

        # Print response
        try:
            response_data = response.json()
            logger.info(
                f"📥 Response: {json.dumps(response_data, indent=2)}"
            )
            return response.status_code == 200, response_data
        except json.JSONDecodeError:
            logger.info(f"📄 Response: {response.text}")
            return response.status_code == 200, response.text

    except requests.exceptions.ConnectionError:
        print_error("Connection Error: Is the API server running?")
        return False, None
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return False, None


def test_sql_injection_attacks():
    """Test SQL injection attack patterns"""
    print_section("TEST 2: SQL INJECTION ATTACKS")

    # Test 2.1: SQL injection in login
    make_request(
        "POST",
        "/login",
        data={"username": "admin' OR '1'='1", "password": "anything"},
        description="SQL injection attempt in username (classic OR attack)",
    )

    # Test 2.2: SQL injection with UNION
    make_request(
        "POST",
        "/register",
        data={
            "username": "user' UNION SELECT * FROM users--",
            "password": "test123",
            "email": "test@test.com",
        },
        description="SQL injection with UNION SELECT",
    )

    # Test 2.3: SQL injection with DROP TABLE
    make_request(
        "POST",
        "/login",
        data={
            "username": "admin'; DROP TABLE users;--",
            "password": "password",
        },
        description="SQL injection attempting to DROP TABLE",
    )

    # Test 2.4: Blind SQL injection
    make_request(
        "POST",
        "/search",
        data={"query": "laptop' AND 1=1--"},
        description="Blind SQL injection attempt",
    )

    print_warning(
        "\n⚠ SQL injection tests completed - Check if Blackwall blocked them"
    )


def test_xss_attacks():
    """Test Cross-Site Scripting (XSS) attack patterns"""
    print_section("TEST 3: XSS ATTACKS")

    # Test 3.1: Script tag injection
    make_request(
        "POST",
        "/register",
        data={
            "username": "<script>alert('XSS')</script>",
            "password": "test123",
            "email": "test@test.com",
        },
        description="XSS with script tag in username",
    )

    # Test 3.2: Event handler injection
    make_request(
        "POST",
        "/search",
        data={"query": "<img src=x onerror=alert('XSS')>"},
        description="XSS with onerror event handler",
    )

    # # Test 3.3: JavaScript protocol
    # make_request(
    #     "POST", "/register",
    #     data={
    #         "username": "user",
    #         "password": "test",
    #         "email": "javascript:alert('XSS')"
    #     },
    #     description="XSS with javascript: protocol"
    # )

    # # Test 3.4: Iframe injection
    # make_request(
    #     "POST", "/search",
    #     data={
    #         "query": "<iframe src='http://malicious.com'></iframe>"
    #     },
    #     description="XSS with iframe injection"
    # )

    # print_warning("\n⚠ XSS tests completed - Check if Blackwall detected them")


if __name__ == "__main__":
    test_sql_injection_attacks()
    test_xss_attacks()
