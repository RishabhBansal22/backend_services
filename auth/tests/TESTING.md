# Running Tests

This document explains how to run the unit tests for the authentication microservice.

## Prerequisites

Make sure you have installed all dependencies:

```bash
uv sync
```

Or install testing dependencies specifically:

```bash
uv add --dev pytest pytest-cov
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run tests with verbose output
```bash
pytest -v
```

### Run specific test file
```bash
# Test database functionality
pytest auth/tests/test_db.py

# Test authentication functionality
pytest auth/tests/test_auth.py
```

### Run specific test class
```bash
pytest auth/tests/test_db.py::TestUsersModel
pytest auth/tests/test_auth.py::TestPasswordHashing
```

### Run specific test function
```bash
pytest auth/tests/test_auth.py::TestPasswordHashing::test_hash_password
```

### Run with coverage report
```bash
# Basic coverage
pytest --cov=auth

# Coverage with HTML report
pytest --cov=auth --cov-report=html

# Coverage with missing lines
pytest --cov=auth --cov-report=term-missing
```

### Run tests and stop at first failure
```bash
pytest -x
```

### Run tests and show print statements
```bash
pytest -s
```

## Test Structure

### test_db.py
Tests for database models and operations:
- `TestUsersModel`: Tests for Users table operations (CRUD)
- `TestRefreshTokenModel`: Tests for RefreshToken table operations
- `TestDatabaseOperations`: Tests for complex database queries

### test_auth.py
Tests for authentication functionality:
- `TestPasswordHashing`: Tests for password hashing and verification
- `TestUserRegistration`: Tests for user registration flow
- `TestUserLogin`: Tests for user login functionality
- `TestTokenOperations`: Tests for JWT token creation and decoding
- `TestRefreshTokenOperations`: Tests for refresh token management
- `TestUserQuery`: Tests for user query functions

## Notes

- Tests use SQLite in-memory database for isolation
- Each test function gets a fresh database session
- Mock objects are used to avoid database dependencies where appropriate
- Tests are independent and can run in any order
