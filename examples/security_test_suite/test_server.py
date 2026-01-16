"""
Comprehensive Test Server: Blackwall Middleware Testing

This server provides multiple API endpoints to thoroughly test
the Blackwall security middleware with various scenarios.

Run with: uvicorn examples.security_test_suite.test_server:app --reload --port 8001
Or from this directory: uvicorn test_server:app --reload --port 8001
"""

from fastapi import FastAPI, HTTPException, Query, Path
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from blackwall.main import BlackwallMiddleware, rate_limit_config

# ============================================================================
# Create FastAPI Application
# ============================================================================

app = FastAPI(
    title="Blackwall Test API",
    description="Comprehensive test server for Blackwall security middleware",
    version="1.0.0",
)

# ============================================================================
# Configure Blackwall Middleware
# ============================================================================

# Increase rate limits for testing (allows comprehensive test suite to run)
rate_limit_config.requests_per_minute = 200  # Increased from 60
rate_limit_config.requests_per_hour = 5000   # Increased from 1000
rate_limit_config.burst_limit = 50           # Increased from 10

app.add_middleware(
    BlackwallMiddleware,
    model_name="gpt-4.1",
    selected_tools=None,  # All tools enabled
    run_agent_on_all_requests=True,  # Agent analyzes all requests
)

# ============================================================================
# Data Models
# ============================================================================


class LoginRequest(BaseModel):
    """Login request model"""

    username: str = Field(
        ..., description="Username for authentication"
    )
    password: str = Field(
        ..., description="Password for authentication"
    )


class UserCreate(BaseModel):
    """User creation model"""

    name: str = Field(..., description="User's full name")
    email: EmailStr = Field(..., description="User's email address")
    bio: Optional[str] = Field(None, description="User biography")
    age: Optional[int] = Field(
        None, ge=0, le=150, description="User age"
    )


class ProductCreate(BaseModel):
    """Product creation model"""

    name: str = Field(..., description="Product name")
    description: str = Field(..., description="Product description")
    price: float = Field(..., gt=0, description="Product price")
    category: str = Field(..., description="Product category")


class CommentCreate(BaseModel):
    """Comment creation model"""

    post_id: int = Field(..., description="Post ID")
    content: str = Field(
        ..., min_length=1, description="Comment content"
    )
    author: str = Field(..., description="Comment author")


class SearchRequest(BaseModel):
    """Search request model"""

    query: str = Field(..., description="Search query")
    filters: Optional[dict] = Field(
        None, description="Search filters"
    )


# ============================================================================
# Public Endpoints
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Blackwall Test API",
        "status": "active",
        "security": "protected",
        "endpoints": {
            "GET /": "API information",
            "GET /health": "Health check",
            "GET /api/info": "API details",
            "POST /api/auth/login": "User login",
            "POST /api/users": "Create user",
            "GET /api/users/{user_id}": "Get user by ID",
            "POST /api/products": "Create product",
            "GET /api/products": "List products",
            "POST /api/comments": "Create comment",
            "POST /api/search": "Search endpoint",
            "GET /api/data/{resource}": "Get data resource",
        },
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "security": "active",
        "middleware": "Blackwall",
    }


@app.get("/api/info")
async def api_info():
    """Get API information"""
    return {
        "name": "Blackwall Test API",
        "version": "1.0.0",
        "description": "Test server for Blackwall security middleware",
        "security_features": [
            "IP blocking",
            "Rate limiting",
            "Threat detection",
            "AI-powered analysis",
        ],
    }


# ============================================================================
# Authentication Endpoints
# ============================================================================


@app.post("/api/auth/login")
async def login(credentials: LoginRequest):
    """
    User login endpoint.

    This endpoint is protected by Blackwall and will detect:
    - SQL injection attempts
    - Command injection attempts
    - Other malicious patterns
    """
    # Simulate authentication
    if (
        credentials.username == "admin"
        and credentials.password == "password123"
    ):
        return {
            "message": "Login successful",
            "token": "fake-jwt-token-12345",
            "user": {
                "username": credentials.username,
                "role": "admin",
            },
        }
    elif (
        credentials.username == "user"
        and credentials.password == "userpass"
    ):
        return {
            "message": "Login successful",
            "token": "fake-jwt-token-67890",
            "user": {
                "username": credentials.username,
                "role": "user",
            },
        }
    else:
        raise HTTPException(
            status_code=401, detail="Invalid username or password"
        )


# ============================================================================
# User Management Endpoints
# ============================================================================


@app.post("/api/users")
async def create_user(user: UserCreate):
    """
    Create a new user.

    This endpoint will detect XSS attempts and other malicious payloads
    in user input fields.
    """
    return {
        "message": "User created successfully",
        "user": {
            "id": 123,
            "name": user.name,
            "email": user.email,
            "bio": user.bio,
            "age": user.age,
        },
    }


@app.get("/api/users/{user_id}")
async def get_user(user_id: int = Path(..., description="User ID")):
    """Get user by ID"""
    return {
        "id": user_id,
        "name": "John Doe",
        "email": "john@example.com",
        "bio": "Sample user",
    }


# ============================================================================
# Product Management Endpoints
# ============================================================================


@app.post("/api/products")
async def create_product(product: ProductCreate):
    """
    Create a new product.

    This endpoint tests protection against injection attacks in
    product descriptions and other fields.
    """
    return {
        "message": "Product created successfully",
        "product": {
            "id": 456,
            "name": product.name,
            "description": product.description,
            "price": product.price,
            "category": product.category,
        },
    }


@app.get("/api/products")
async def list_products(
    category: Optional[str] = Query(
        None, description="Filter by category"
    ),
    limit: int = Query(
        10, ge=1, le=100, description="Number of products to return"
    ),
):
    """List products with optional filtering"""
    products = [
        {
            "id": 1,
            "name": "Laptop",
            "price": 999.99,
            "category": "Electronics",
        },
        {
            "id": 2,
            "name": "Mouse",
            "price": 29.99,
            "category": "Electronics",
        },
    ]

    if category:
        products = [p for p in products if p["category"] == category]

    return {"products": products[:limit], "total": len(products)}


# ============================================================================
# Comment Endpoints
# ============================================================================


@app.post("/api/comments")
async def create_comment(comment: CommentCreate):
    """
    Create a comment on a post.

    This endpoint is vulnerable to XSS if not properly protected.
    Blackwall will detect and block XSS attempts.
    """
    return {
        "message": "Comment created",
        "comment": {
            "id": 789,
            "post_id": comment.post_id,
            "content": comment.content,
            "author": comment.author,
            "created_at": "2024-01-01T00:00:00Z",
        },
    }


# ============================================================================
# Search Endpoint
# ============================================================================


@app.post("/api/search")
async def search(request: SearchRequest):
    """
    Search endpoint.

    This endpoint tests protection against:
    - SQL injection in search queries
    - Path traversal attempts
    - Command injection
    """
    return {
        "query": request.query,
        "results": [
            {"id": 1, "title": "Result 1", "match": request.query},
            {"id": 2, "title": "Result 2", "match": request.query},
        ],
        "filters": request.filters,
    }


# ============================================================================
# Data Endpoint (Path Parameter Testing)
# ============================================================================


@app.get("/api/data/{resource}")
async def get_data(
    resource: str = Path(..., description="Resource name or path"),
    format: Optional[str] = Query(
        "json", description="Response format"
    ),
):
    """
    Get data by resource name.

    This endpoint tests protection against path traversal attacks
    (e.g., ../../../etc/passwd).
    """
    return {
        "resource": resource,
        "format": format,
        "data": {"sample": "data", "resource": resource},
    }


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    print("🛡️  Starting Blackwall Test Server...")
    print("📖 API Docs: http://localhost:8001/docs")
    print("🔍 All requests are monitored by Blackwall security agent")
    print("🧪 Test with: python examples/security_test_suite/test_client.py\n")

    uvicorn.run(
        "test_server:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
    )
