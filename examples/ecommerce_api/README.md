# E-Commerce API

A full-featured e-commerce API protected by Blackwall, featuring user management, product catalog, search functionality, and admin operations.

## Files

- **`api.py`** - Complete e-commerce API with Blackwall protection

## Features

- User authentication and registration
- Product catalog management
- Product search with filters
- Admin commands
- Security status monitoring

## Quick Start

```bash
# Start the server
uvicorn api:app --reload --port 8000
```

## Endpoints

### Public
- `GET /` - API information
- `GET /health` - Health check
- `GET /products` - Browse products

### Authentication
- `POST /login` - User login
- `POST /register` - User registration

### Protected
- `GET /users/me` - Get current user
- `POST /admin` - Admin commands

### Security
- `GET /security/status` - Security status
- `GET /security/report` - Security report
