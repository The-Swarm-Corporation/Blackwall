"""
Simple client to test if Blackwall agent is working
Run this after starting the server with: uvicorn example:app --reload --port 8000
"""

import requests
import json

BASE_URL = "http://localhost:8000"

# Test if server is running
requests.get(f"{BASE_URL}/health")


def test_login():
    # Test if agent analyzes payload (this should trigger the agent)
    out = requests.post(
        f"{BASE_URL}/login",
        json={"username": "admin' OR '1'='1", "password": "test"},
    )

    print(f"Response: {out.json()}")
    print(json.dumps(out.json(), indent=4))
    print("status code: ", out.status_code)


def test_users():
    # Test if agent detects XSS attempts
    out = requests.post(
        f"{BASE_URL}/users",
        json={
            "name": "<script>alert('XSS')</script>",
            "email": "test@example.com",
            "bio": "test",
        },
    )

    print(f"Response: {out.json()}")
    print(json.dumps(out.json(), indent=4))
    print("status code: ", out.status_code)


def test_legitimate_login():
    # Test legitimate login request (should be allowed)
    out = requests.post(
        f"{BASE_URL}/login",
        json={"username": "admin", "password": "password"},
    )

    print(f"Response: {out.json()}")
    print(json.dumps(out.json(), indent=4))
    print("status code: ", out.status_code)


def test_legitimate_user():
    # Test legitimate user creation (should be allowed)
    out = requests.post(
        f"{BASE_URL}/users",
        json={
            "name": "John Doe",
            "email": "john@example.com",
            "bio": "Regular user bio",
        },
    )

    print(f"Response: {out.json()}")
    print(json.dumps(out.json(), indent=4))
    print("status code: ", out.status_code)


if __name__ == "__main__":
    test_login()
    test_users()
    test_legitimate_login()
    test_legitimate_user()
