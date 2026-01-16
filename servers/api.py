"""
Blackwall Protected API Server

This is a sample FastAPI server protected by the Blackwall security agent.
It demonstrates how the security middleware monitors and protects endpoints.

Run with: uvicorn api_server:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn
from datetime import datetime

# Import Blackwall components
from blackwall.main import (
    create_blackwall_agent,
    BlackwallMiddleware,
    security_state,
)


# ============================================================================
# Pydantic Models
# ============================================================================


class User(BaseModel):
    """User model for authentication"""

    username: str
    password: str
    email: Optional[str] = None


class Product(BaseModel):
    """Product model"""

    id: Optional[int] = None
    name: str
    description: str
    price: float
    category: str


class SearchQuery(BaseModel):
    """Search query model"""

    query: str
    filters: Optional[Dict[str, Any]] = None


class AdminCommand(BaseModel):
    """Admin command model"""

    command: str
    parameters: Optional[Dict[str, Any]] = None


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Blackwall Protected API",
    description="Sample API protected by Blackwall security agent",
    version="1.0.0",
)

# Initialize Blackwall agent
print("🛡️  Initializing Blackwall Security Agent...")
blackwall_agent = create_blackwall_agent(
    model_name="gpt-4.1",
    selected_tools=[
        "analyze_payload_for_threats",
        "block_ip_address",
    ],
)

# Add Blackwall middleware
app.add_middleware(BlackwallMiddleware, agent=blackwall_agent)

# In-memory database (for demo purposes)
users_db = []
products_db = [
    {
        "id": 1,
        "name": "Laptop",
        "description": "High-performance laptop",
        "price": 1299.99,
        "category": "Electronics",
    },
    {
        "id": 2,
        "name": "Mouse",
        "description": "Wireless mouse",
        "price": 29.99,
        "category": "Electronics",
    },
    {
        "id": 3,
        "name": "Keyboard",
        "description": "Mechanical keyboard",
        "price": 89.99,
        "category": "Electronics",
    },
]


# ============================================================================
# Public Endpoints
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to Blackwall Protected API",
        "status": "protected",
        "version": "1.0.0",
        "endpoints": {
            "public": ["/", "/health", "/products"],
            "auth": ["/login", "/register"],
            "protected": ["/admin", "/users/me"],
            "security": ["/security/status", "/security/report"],
        },
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "security": "active",
        "blocked_ips": len(security_state.blocked_ips),
        "threat_events": len(security_state.threat_events),
    }


@app.get("/products")
async def get_products(
    category: Optional[str] = Query(
        None, description="Filter by category"
    ),
    min_price: Optional[float] = Query(
        None, description="Minimum price"
    ),
    max_price: Optional[float] = Query(
        None, description="Maximum price"
    ),
):
    """Get all products with optional filtering"""
    filtered_products = products_db

    if category:
        filtered_products = [
            p for p in filtered_products if p["category"] == category
        ]

    if min_price is not None:
        filtered_products = [
            p for p in filtered_products if p["price"] >= min_price
        ]

    if max_price is not None:
        filtered_products = [
            p for p in filtered_products if p["price"] <= max_price
        ]

    return {
        "products": filtered_products,
        "total": len(filtered_products),
    }


@app.get("/products/{product_id}")
async def get_product(product_id: int):
    """Get a specific product"""
    product = next(
        (p for p in products_db if p["id"] == product_id), None
    )

    if not product:
        raise HTTPException(
            status_code=404, detail="Product not found"
        )

    return product


# ============================================================================
# Authentication Endpoints (Vulnerable to testing)
# ============================================================================


@app.post("/register")
async def register(user: User):
    """Register a new user - This endpoint is vulnerable to injection attacks for testing"""
    # Check if user exists (vulnerable to SQL injection patterns)
    if any(u["username"] == user.username for u in users_db):
        raise HTTPException(
            status_code=400, detail="User already exists"
        )

    # Add user (Blackwall will detect malicious payloads)
    user_dict = user.dict()
    user_dict["id"] = len(users_db) + 1
    user_dict["created_at"] = datetime.now().isoformat()
    users_db.append(user_dict)

    return {
        "message": "User registered successfully",
        "user_id": user_dict["id"],
        "username": user.username,
    }


@app.post("/login")
async def login(user: User):
    """Login endpoint - Vulnerable to SQL injection for testing"""
    # Simulate authentication (vulnerable pattern)
    authenticated_user = next(
        (
            u
            for u in users_db
            if u["username"] == user.username
            and u["password"] == user.password
        ),
        None,
    )

    if not authenticated_user:
        raise HTTPException(
            status_code=401, detail="Invalid credentials"
        )

    return {
        "message": "Login successful",
        "token": f"fake-jwt-token-{authenticated_user['id']}",
        "user": {
            "id": authenticated_user["id"],
            "username": authenticated_user["username"],
            "email": authenticated_user.get("email"),
        },
    }


# ============================================================================
# Search Endpoint (Vulnerable to XSS and injection)
# ============================================================================


@app.post("/search")
async def search(query: SearchQuery):
    """Search endpoint - Vulnerable to XSS and injection attacks for testing"""
    # Simple search implementation
    results = [
        p
        for p in products_db
        if query.query.lower() in p["name"].lower()
        or query.query.lower() in p["description"].lower()
    ]

    return {
        "query": query.query,
        "results": results,
        "total": len(results),
    }


# ============================================================================
# Admin Endpoints (Vulnerable to command injection)
# ============================================================================


@app.post("/admin/command")
async def admin_command(command: AdminCommand):
    """Admin command endpoint - Vulnerable to command injection for testing"""
    # This is intentionally vulnerable for testing Blackwall
    allowed_commands = ["status", "stats", "backup", "restart"]

    if command.command not in allowed_commands:
        raise HTTPException(status_code=400, detail="Invalid command")

    return {
        "command": command.command,
        "status": "executed",
        "result": f"Command '{command.command}' executed successfully",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/admin/users")
async def admin_get_users():
    """Get all users (admin only)"""
    return {"users": users_db, "total": len(users_db)}


# ============================================================================
# File Upload Endpoint (Vulnerable to path traversal)
# ============================================================================


@app.post("/upload")
async def upload_file(
    filename: str = Body(...), content: str = Body(...)
):
    """File upload endpoint - Vulnerable to path traversal for testing"""
    # This is intentionally vulnerable for testing
    return {
        "message": "File uploaded successfully",
        "filename": filename,
        "size": len(content),
        "timestamp": datetime.now().isoformat(),
    }


# ============================================================================
# Security Management Endpoints
# ============================================================================


@app.get("/security/status")
async def security_status():
    """Get current security status"""
    return {
        "blocked_ips": list(security_state.blocked_ips),
        "blocked_ranges": [
            str(r) for r in security_state.blocked_ip_ranges
        ],
        "whitelisted_ips": list(security_state.whitelist_ips),
        "total_threats": len(security_state.threat_events),
        "suspicious_ips": dict(
            list(security_state.suspicious_ips.items())[:10]
        ),
        "monitored_ips": len(security_state.rate_limit_data),
    }


@app.get("/security/report")
async def security_report():
    """Generate comprehensive security report"""
    report = blackwall_agent.run(
        "Generate a comprehensive security report"
    )

    return {
        "report": report,
        "generated_at": datetime.now().isoformat(),
    }


@app.get("/security/threats")
async def get_threats(
    limit: int = Query(50, description="Number of threats to return")
):
    """Get recent threat events"""
    recent_threats = security_state.threat_events[-limit:]

    return {
        "threats": [
            {
                "timestamp": t.timestamp,
                "ip_address": t.ip_address,
                "threat_type": t.threat_type,
                "severity": t.severity,
                "action_taken": t.action_taken,
                "details": t.details,
            }
            for t in recent_threats
        ],
        "total": len(recent_threats),
    }


@app.post("/security/analyze")
async def analyze_payload(payload: Dict[str, Any] = Body(...)):
    """Manually analyze a payload for threats"""
    import json

    payload_str = json.dumps(payload)

    analysis_task = f"""
    Analyze this payload for security threats:
    {payload_str}
    
    Provide detailed analysis and recommendations.
    """

    analysis = blackwall_agent.run(analysis_task)

    return {
        "analysis": analysis,
        "payload_size": len(payload_str),
        "timestamp": datetime.now().isoformat(),
    }


# ============================================================================
# Error Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url),
        },
    )


# ============================================================================
# Startup Event
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    print("=" * 70)
    print("🛡️  BLACKWALL SECURITY AGENT ACTIVE")
    print("=" * 70)
    print("API Server: http://localhost:8000")
    print("API Docs: http://localhost:8000/docs")
    print("Security Status: http://localhost:8000/security/status")
    print("Security Report: http://localhost:8000/security/report")
    print("=" * 70)
    print("\n🔍 Monitoring all incoming traffic for threats...\n")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
