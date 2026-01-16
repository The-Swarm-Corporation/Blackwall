# User Management API

A simple user management API demonstrating basic Blackwall middleware integration with authentication and user creation endpoints.

## Files

- **`example.py`** - FastAPI app with login and user creation endpoints
- **`client_example.py`** - Client code to test the protected API

## Purpose

Demonstrates the simplest way to add Blackwall security to a user management system with minimal configuration.

## Quick Start

```bash
# Start the server
uvicorn example:app --reload --port 8000

# Run the client (in another terminal)
python client_example.py
```

## Endpoints

- `POST /login` - User authentication
- `POST /users` - Create new user
- `GET /health` - Health check
