"""
Simple Example: Using Blackwall Middleware with FastAPI

This example demonstrates how to integrate Blackwall security middleware
into a FastAPI application with different configuration options.

Run with: uvicorn example:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from blackwall.main import BlackwallMiddleware

# ============================================================================
# Create FastAPI Application
# ============================================================================

app = FastAPI(
    title="Blackwall Example API",
    description="Simple example showing Blackwall middleware integration",
    version="1.0.0",
)

# ============================================================================
# Option 1: Use middleware with default settings (all tools, default model)
# ============================================================================
# app.add_middleware(BlackwallMiddleware)

# ============================================================================
# Option 2: Use middleware with custom model name
# ============================================================================
# app.add_middleware(BlackwallMiddleware, model_name="gpt-4")

# ============================================================================
# Option 3: Use middleware with custom model and selected tools
# ============================================================================
app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4.1",  # Change to your preferred model
    selected_tools=None,  # None = all tools enabled, or specify: ["analyze_payload_for_threats", "block_ip_address"]
    run_agent_on_all_requests=True,  # Agent will analyze every request
)

# ============================================================================
# Option 4: Create agent manually and pass it to middleware
# ============================================================================
# blackwall_agent = create_blackwall_agent(
#     model_name="gpt-4.1",
#     selected_tools=["analyze_payload_for_threats", "block_ip_address", "check_ip_reputation"]
# )
# app.add_middleware(BlackwallMiddleware, agent=blackwall_agent)

# ============================================================================
# Option 5: Run agent on all requests (not just low/medium severity threats)
# ============================================================================
# app.add_middleware(
#     BlackwallMiddleware,
#     model_name="gpt-4.1",
#     selected_tools=None,
#     run_agent_on_all_requests=True,  # Agent will analyze every request
# )

# ============================================================================
# Example Endpoints
# ============================================================================


class LoginRequest(BaseModel):
    username: str
    password: str


class UserData(BaseModel):
    name: str
    email: str
    bio: str


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Blackwall Protected API",
        "status": "active",
        "endpoints": {
            "GET /": "This endpoint",
            "POST /login": "Login endpoint (protected)",
            "POST /users": "Create user (protected)",
            "GET /health": "Health check",
        },
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "security": "active"}


@app.post("/login")
async def login(credentials: LoginRequest):
    """
    Login endpoint - Blackwall will analyze the payload for threats.
    Try sending malicious payloads like:
    {
        "username": "admin' OR '1'='1",
        "password": "test"
    }
    """
    # Simulate authentication
    if (
        credentials.username == "admin"
        and credentials.password == "password"
    ):
        return {"message": "Login successful", "token": "fake-token"}
    else:
        raise HTTPException(
            status_code=401, detail="Invalid credentials"
        )


@app.post("/users")
async def create_user(user: UserData):
    """
    Create user endpoint - Blackwall will monitor for XSS, injection, etc.
    Try sending malicious payloads like:
    {
        "name": "<script>alert('XSS')</script>",
        "email": "test@example.com",
        "bio": "test"
    }
    """
    return {
        "message": "User created",
        "user": {"name": user.name, "email": user.email},
    }


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    print("🛡️  Starting Blackwall Protected API Server...")
    print("📖 API Docs: http://localhost:8000/docs")
    print(
        "🔍 All requests are monitored by Blackwall security agent\n"
    )

    uvicorn.run("example:app", host="0.0.0.0", port=8000, reload=True)
