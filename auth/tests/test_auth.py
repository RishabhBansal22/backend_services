"""
Comprehensive test suite for authentication system.
Tests cover:
- Password hashing and verification
- User registration and validation
- User login and authentication
- JWT token creation, validation, and expiration
- Refresh token management
- User query operations
- Logout functionality
- Password reset flow
"""

import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import redis

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import Base, Users, RefreshToken
from functions import (
    hash_password,
    varify_password,
    user_registration,
    user_login,
    create_token,
    decode_token,
    find_user_by_email,
    find_user_by_id,
    save_refresh_token,
    get_referesh_token,
    delete_refresh_token,
    create_access_token,
    reset_pass,
    update_pass_in_db
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="function")
def test_engine():
    """Create a test database engine using SQLite in-memory database."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=None
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="function")
def test_session(test_engine):
    """Create a test database session with context manager support."""
    TestSession = sessionmaker(bind=test_engine)
    session = TestSession()
    
    # Make the session work as a context manager
    session.__enter__ = lambda: session
    session.__exit__ = lambda exc_type, exc_val, exc_tb: False
    
    yield session
    session.close()


@pytest.fixture(scope="function")
def mock_session(test_session):
    """Mock the Session to use test_session for all database operations."""
    with patch('functions.Session') as mock_session_class:
        mock_session_class.return_value = test_session
        yield mock_session_class


@pytest.fixture
def mock_redis():
    """Mock Redis connection for password reset tests."""
    mock_conn = MagicMock()
    mock_conn.setex = MagicMock(return_value=True)
    mock_conn.get = MagicMock(return_value=None)
    mock_conn.delete = MagicMock(return_value=1)
    mock_conn.ping = MagicMock(return_value=True)
    return mock_conn


@pytest.fixture
def sample_user(test_session):
    """Create a sample user in the test database."""
    user_id = str(uuid.uuid4())
    email = "testuser@example.com"
    password = "TestPassword123"
    
    user = Users(
        id=user_id,
        first_name="Test",
        last_name="User",
        email=email,
        password=hash_password(password),
        created_at=datetime.utcnow()
    )
    test_session.add(user)
    test_session.commit()
    
    return {
        "user_id": user_id,
        "email": email,
        "password": password,
        "first_name": "Test",
        "last_name": "User"
    }


# ============================================================================
# PASSWORD HASHING TESTS
# ============================================================================

class TestPasswordHashing:
    """Test suite for password hashing and verification functions."""
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns a hashed string."""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0
    
    def test_hash_password_different_salts(self):
        """Test that hashing the same password twice produces different hashes due to different salts."""
        password = "samePassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Test verifying a correct password."""
        password = "correctPassword"
        hashed = hash_password(password)
        
        assert varify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test verifying an incorrect password."""
        correct_password = "correctPassword"
        wrong_password = "wrongPassword"
        hashed = hash_password(correct_password)
        
        assert varify_password(wrong_password, hashed) is False
    
    def test_verify_password_empty_string(self):
        """Test verifying with empty password."""
        password = "password"
        hashed = hash_password(password)
        
        assert varify_password("", hashed) is False
    
    def test_hash_password_special_characters(self):
        """Test hashing passwords with special characters."""
        password = "P@ssw0rd!#$%^&*()"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert varify_password(password, hashed) is True
    
    def test_hash_password_unicode(self):
        """Test hashing passwords with unicode characters."""
        password = "пароль密码🔒"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert varify_password(password, hashed) is True
    
    def test_hash_password_very_long(self):
        """Test hashing very long passwords (within bcrypt's 72 byte limit)."""
        password = "a" * 70
        hashed = hash_password(password)
        
        assert hashed is not None
        assert varify_password(password, hashed) is True
    
    def test_verify_password_case_sensitive(self):
        """Test that password verification is case-sensitive."""
        password = "Password123"
        hashed = hash_password(password)
        
        assert varify_password("password123", hashed) is False
        assert varify_password("PASSWORD123", hashed) is False
        assert varify_password(password, hashed) is True
    
    def test_verify_password_whitespace_matters(self):
        """Test that whitespace in passwords matters."""
        password = "password"
        hashed = hash_password(password)
        
        assert varify_password(" password", hashed) is False
        assert varify_password("password ", hashed) is False
        assert varify_password(" password ", hashed) is False


# ============================================================================
# USER REGISTRATION TESTS
# ============================================================================

class TestUserRegistration:
    """Test suite for user registration functionality."""
    
    def test_user_registration_success(self, mock_session, test_session):
        """Test successful user registration."""
        result = user_registration(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            password="securePassword123"
        )
        
        assert "new_user" in result
        assert result["status_code"] == 201
        assert result["new_user"]["name"] == "John Doe"
        assert result["new_user"]["email"] == "john.doe@example.com"
        assert "user_id" in result["new_user"]
        assert "created_at" in result["new_user"]
    
    def test_user_registration_duplicate_email(self, mock_session, test_session):
        """Test registration with duplicate email."""
        email = "duplicate@example.com"
        
        # First registration
        user_registration(
            first_name="Jane",
            last_name="Smith",
            email=email,
            password="password123"
        )
        
        # Attempt duplicate registration
        result = user_registration(
            first_name="Jane",
            last_name="Duplicate",
            email=email,
            password="password456"
        )
        
        assert "error" in result
        assert result["status_code"] == 409
    
    def test_user_registration_case_insensitive_email(self, mock_session, test_session):
        """Test that email comparison is case-insensitive."""
        email = "test@example.com"
        
        # Register with lowercase email
        user_registration(
            first_name="Test",
            last_name="User",
            email=email,
            password="password123"
        )
        
        # Try to register with uppercase email
        result = user_registration(
            first_name="Test",
            last_name="User2",
            email="TEST@EXAMPLE.COM",
            password="password456"
        )
        
        assert result["status_code"] == 409
    
    def test_user_registration_no_last_name(self, mock_session, test_session):
        """Test registration without last name."""
        result = user_registration(
            first_name="SingleName",
            email="singlename@example.com",
            password="password123",
            last_name=None
        )
        
        assert result["status_code"] == 201
        assert result["new_user"]["name"] == "SingleName"
    
    def test_user_registration_strips_whitespace(self, mock_session, test_session):
        """Test that registration strips whitespace from inputs."""
        result = user_registration(
            first_name="  John  ",
            last_name="  Doe  ",
            email="  john@example.com  ",
            password="password123"
        )
        
        assert result["status_code"] == 201
        assert result["new_user"]["email"] == "john@example.com"
        assert result["new_user"]["name"] == "John Doe"
    
    def test_user_registration_email_normalization(self, mock_session, test_session):
        """Test that emails are normalized to lowercase."""
        result = user_registration(
            first_name="Test",
            last_name="User",
            email="TEST@EXAMPLE.COM",
            password="password123"
        )
        
        assert result["status_code"] == 201
        assert result["new_user"]["email"] == "test@example.com"
    
    def test_user_registration_creates_database_entry(self, mock_session, test_session):
        """Test that registration actually creates database entry."""
        email = "dbtest@example.com"
        
        result = user_registration(
            first_name="Database",
            last_name="Test",
            email=email,
            password="password123"
        )
        
        assert result["status_code"] == 201
        
        # Verify user was created in database
        user = test_session.query(Users).filter_by(email=email).first()
        assert user is not None
        assert user.first_name == "Database"
        assert user.last_name == "Test"
        assert user.email == email
    
    def test_user_registration_password_hashed(self, mock_session, test_session):
        """Test that password is hashed in database."""
        email = "hashtest@example.com"
        password = "plainPassword123"
        
        result = user_registration(
            first_name="Hash",
            last_name="Test",
            email=email,
            password=password
        )
        
        assert result["status_code"] == 201
        
        # Verify password is hashed
        user = test_session.query(Users).filter_by(email=email).first()
        assert user.password != password
        assert varify_password(password, user.password) is True


# ============================================================================
# USER LOGIN TESTS
# ============================================================================

class TestUserLogin:
    """Test suite for user login functionality."""
    
    def test_user_login_success(self, mock_session, test_session):
        """Test successful user login returns access and refresh tokens."""
        password = "myPassword123"
        email = "login@example.com"
        
        # Register a user first
        user_registration(
            first_name="Login",
            last_name="Test",
            email=email,
            password=password
        )
        
        # Attempt login
        result = user_login(email=email, password=password)
        
        # Should return tuple of tuples
        assert isinstance(result, tuple)
        assert len(result) == 2
        
        access_token_tuple, refresh_token_tuple = result
        assert isinstance(access_token_tuple, tuple)
        assert isinstance(refresh_token_tuple, tuple)
        
        access_token, access_exp = access_token_tuple
        refresh_token, refresh_exp = refresh_token_tuple
        
        # Verify tokens
        assert isinstance(access_token, str)
        assert len(access_token) > 0
        assert isinstance(refresh_token, str)
        assert len(refresh_token) > 0
        assert isinstance(access_exp, datetime)
        assert isinstance(refresh_exp, datetime)
    
    def test_user_login_wrong_password(self, mock_session, test_session):
        """Test login with wrong password returns error."""
        email = "wrongpass@example.com"
        correct_password = "correctPassword"
        wrong_password = "wrongPassword"
        
        # Register user
        user_registration(
            first_name="Wrong",
            last_name="Pass",
            email=email,
            password=correct_password
        )
        
        # Attempt login with wrong password
        result = user_login(email=email, password=wrong_password)
        
        assert isinstance(result, dict)
        assert "error" in result
        assert result["status_code"] == 401
        assert "Invalid email or password" in result["error"]
    
    def test_user_login_nonexistent_user(self, mock_session, test_session):
        """Test login with non-existent user returns error."""
        result = user_login(
            email="nonexistent@example.com",
            password="anyPassword"
        )
        
        assert isinstance(result, dict)
        assert "error" in result
        assert result["status_code"] == 401
    
    def test_user_login_case_insensitive_email(self, mock_session, test_session):
        """Test that login is case-insensitive for email addresses."""
        password = "TestPass123"
        email = "CaseSensitive@Example.COM"
        
        # Register with mixed case email
        user_registration(
            first_name="Case",
            last_name="Test",
            email=email,
            password=password
        )
        
        # Login with different case
        result = user_login(email="casesensitive@example.com", password=password)
        
        assert isinstance(result, tuple)
        access_token_tuple, _ = result
        access_token, _ = access_token_tuple
        
        decoded = decode_token(access_token)
        assert decoded["email"] == "casesensitive@example.com"
    
    def test_user_login_whitespace_trimming(self, mock_session, test_session):
        """Test that login trims whitespace from email."""
        password = "TestPass123"
        email = "whitespace@example.com"
        
        user_registration(
            first_name="White",
            last_name="Space",
            email=email,
            password=password
        )
        
        # Login with whitespace
        result = user_login(email="  whitespace@example.com  ", password=password)
        
        assert isinstance(result, tuple)
    
    def test_user_login_refresh_token_saved(self, mock_session, test_session):
        """Test that refresh token is saved to database on successful login."""
        password = "TestPass123"
        email = "tokentest@example.com"
        
        # Register user
        reg_result = user_registration(
            first_name="Token",
            last_name="Test",
            email=email,
            password=password
        )
        user_id = reg_result["new_user"]["user_id"]
        
        # Login
        result = user_login(email=email, password=password)
        
        assert isinstance(result, tuple)
        _, refresh_token_tuple = result
        refresh_token, _ = refresh_token_tuple
        
        # Check database for refresh token
        saved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert saved_token is not None
        assert saved_token.refresh_token == refresh_token
    
    def test_user_login_empty_password(self, mock_session, test_session):
        """Test login with empty password returns error."""
        email = "emptypass@example.com"
        
        user_registration(
            first_name="Empty",
            last_name="Pass",
            email=email,
            password="RealPassword123"
        )
        
        result = user_login(email=email, password="")
        
        assert isinstance(result, dict)
        assert result["status_code"] == 401
    
    def test_user_login_token_contains_user_data(self, mock_session, test_session):
        """Test that access token contains correct user data."""
        password = "TestPass123"
        email = "tokendata@example.com"
        
        reg_result = user_registration(
            first_name="Token",
            last_name="Data",
            email=email,
            password=password
        )
        user_id = reg_result["new_user"]["user_id"]
        
        result = user_login(email=email, password=password)
        access_token_tuple, _ = result
        access_token, _ = access_token_tuple
        
        decoded = decode_token(access_token)
        assert decoded["sub"] == user_id
        assert decoded["email"] == email
        assert "exp" in decoded


# ============================================================================
# TOKEN OPERATIONS TESTS
# ============================================================================

class TestTokenOperations:
    """Test suite for JWT token creation and validation."""
    
    def test_create_token(self):
        """Test creating a JWT token."""
        data = {
            "user_id": "123",
            "email": "test@example.com"
        }
        expires_delta = timedelta(minutes=30)
        
        token, expire_time = create_token(data, expires_delta)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        assert isinstance(expire_time, datetime)
    
    def test_decode_token_valid(self):
        """Test decoding a valid JWT token."""
        data = {
            "user_id": "123",
            "email": "test@example.com"
        }
        expires_delta = timedelta(minutes=30)
        
        token, _ = create_token(data, expires_delta)
        decoded = decode_token(token)
        
        assert decoded is not None
        assert decoded["user_id"] == "123"
        assert decoded["email"] == "test@example.com"
        assert "exp" in decoded
    
    def test_decode_token_expired(self):
        """Test decoding an expired token returns None."""
        data = {
            "user_id": "123",
            "email": "test@example.com"
        }
        expires_delta = timedelta(seconds=-1)
        
        token, _ = create_token(data, expires_delta)
        decoded = decode_token(token)
        
        assert decoded is None
    
    def test_decode_token_invalid(self):
        """Test decoding an invalid token returns None."""
        invalid_token = "invalid.token.string"
        decoded = decode_token(invalid_token)
        
        assert decoded is None
    
    def test_token_includes_expiration(self):
        """Test that created tokens include expiration claim."""
        data = {"user_id": "123", "email": "test@example.com"}
        expires_delta = timedelta(minutes=15)
        
        token, expire_time = create_token(data, expires_delta)
        decoded = decode_token(token)
        
        assert "exp" in decoded
        assert decoded["exp"] > datetime.utcnow().timestamp()
    
    def test_token_expiration_matches_timedelta(self):
        """Test that token expiration matches the provided timedelta."""
        data = {"user_id": "123"}
        expires_delta = timedelta(minutes=30)
        
        before_time = datetime.utcnow()
        token, expire_time = create_token(data, expires_delta)
        after_time = datetime.utcnow()
        
        expected_min = before_time + expires_delta
        expected_max = after_time + expires_delta
        
        assert expected_min <= expire_time <= expected_max
    
    def test_create_access_token_success(self, mock_session, test_session):
        """Test creating an access token for a valid user."""
        user_id = str(uuid.uuid4())
        email = "accesstoken@example.com"
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Access",
            last_name="Token",
            email=email,
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('functions.Session', return_value=test_session):
            access_token, expire_time = create_access_token(user_id)
        
        assert access_token is not None
        assert isinstance(access_token, str)
        assert expire_time is not None
        assert isinstance(expire_time, datetime)
        
        decoded = decode_token(access_token)
        assert decoded is not None
        assert decoded["sub"] == user_id
        assert decoded["email"] == email
    
    def test_create_access_token_nonexistent_user(self, mock_session, test_session):
        """Test creating access token with non-existent user."""
        fake_user_id = str(uuid.uuid4())
        
        with patch('functions.Session', return_value=test_session):
            access_token, expire_time = create_access_token(fake_user_id)
        
        assert access_token is None
        assert expire_time is None


# ============================================================================
# REFRESH TOKEN OPERATIONS TESTS
# ============================================================================

class TestRefreshTokenOperations:
    """Test suite for refresh token database operations."""
    
    def test_save_refresh_token_new_user(self, mock_session, test_session):
        """Test saving a refresh token for a user who doesn't have one yet."""
        user_id = str(uuid.uuid4())
        refresh_token = "new_refresh_token_123"
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Save refresh token
        result = save_refresh_token(user_id, refresh_token)
        
        assert result is None
        
        # Verify token was saved
        saved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert saved_token is not None
        assert saved_token.refresh_token == refresh_token
    
    def test_save_refresh_token_update_existing(self, mock_session, test_session):
        """Test updating an existing refresh token."""
        user_id = str(uuid.uuid4())
        old_token = "old_refresh_token"
        new_token = "new_refresh_token"
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="update@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create initial token
        token = RefreshToken(
            user_id=user_id,
            refresh_token=old_token,
            created_at=datetime.utcnow()
        )
        test_session.add(token)
        test_session.commit()
        
        # Update with new token
        result = save_refresh_token(user_id, new_token)
        
        assert result is None
        
        # Verify token was updated (not duplicated)
        all_tokens = test_session.query(RefreshToken).filter_by(user_id=user_id).all()
        assert len(all_tokens) == 1
        assert all_tokens[0].refresh_token == new_token
    
    def test_get_refresh_token_exists(self, mock_session, test_session):
        """Test retrieving an existing refresh token."""
        user_id = str(uuid.uuid4())
        refresh_token_value = "stored_refresh_token_abc123"
        
        # Create and save a refresh token
        token = RefreshToken(
            user_id=user_id,
            refresh_token=refresh_token_value,
            created_at=datetime.utcnow()
        )
        test_session.add(token)
        test_session.commit()
        
        # Retrieve the token
        retrieved = get_referesh_token(user_id)
        
        assert retrieved is not None
        assert retrieved.refresh_token == refresh_token_value
        assert retrieved.user_id == user_id
    
    def test_get_refresh_token_not_exists(self, mock_session, test_session):
        """Test retrieving refresh token for user who doesn't have one."""
        user_id = str(uuid.uuid4())
        retrieved = get_referesh_token(user_id)
        
        assert retrieved is None
    
    def test_delete_refresh_token_success(self, mock_session, test_session):
        """Test successfully deleting a refresh token."""
        user_id = str(uuid.uuid4())
        refresh_token_value = "token_to_delete_123"
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Delete",
            last_name="Test",
            email="delete@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create refresh token
        token = RefreshToken(
            user_id=user_id,
            refresh_token=refresh_token_value,
            created_at=datetime.utcnow()
        )
        test_session.add(token)
        test_session.commit()
        
        # Delete token
        result = delete_refresh_token(refresh_token_value)
        
        assert result is not None
        assert result["status_code"] == 200
        
        # Verify token was deleted
        deleted_token = test_session.query(RefreshToken).filter_by(refresh_token=refresh_token_value).first()
        assert deleted_token is None
    
    def test_delete_refresh_token_not_found(self, mock_session, test_session):
        """Test deleting a non-existent refresh token."""
        non_existent_token = "does_not_exist_token"
        
        result = delete_refresh_token(non_existent_token)
        
        assert result is not None
        assert result["status_code"] == 404
        assert "not found" in result["message"].lower()
    
    def test_delete_refresh_token_empty_string(self, mock_session, test_session):
        """Test deleting with empty string as token."""
        result = delete_refresh_token("")
        
        assert result is not None
        assert result["status_code"] == 404


# ============================================================================
# USER QUERY TESTS
# ============================================================================

class TestUserQuery:
    """Test suite for user query functions."""
    
    def test_find_user_by_email_exists(self, mock_session, test_session):
        """Test finding an existing user by email."""
        user_id = str(uuid.uuid4())
        email = "findme@example.com"
        
        user = Users(
            id=user_id,
            first_name="Find",
            last_name="Me",
            email=email,
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_email(email)
        
        assert result is not None
        assert result["email"] == email
        assert result["first_name"] == "Find"
        assert result["last_name"] == "Me"
        assert result["user_id"] == user_id
    
    def test_find_user_by_email_not_exists(self, mock_session, test_session):
        """Test finding a non-existent user by email."""
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_email("nonexistent@example.com")
        
        assert result is None
    
    def test_find_user_by_email_case_insensitive(self, mock_session, test_session):
        """Test that email search is case-insensitive."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="Case",
            last_name="Test",
            email="lowercase@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_email("LOWERCASE@EXAMPLE.COM")
        
        assert result is not None
        assert result["email"] == "lowercase@example.com"
    
    def test_find_user_by_id_exists(self, mock_session, test_session):
        """Test finding an existing user by ID."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_id(user_id)
        
        assert result is not None
        assert result["user_id"] == user_id
        assert result["first_name"] == "Test"
        assert result["email"] == "test@example.com"
    
    def test_find_user_by_id_not_exists(self, mock_session, test_session):
        """Test finding a non-existent user by ID."""
        fake_id = str(uuid.uuid4())
        
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_id(fake_id)
        
        assert result is None


# ============================================================================
# PASSWORD RESET FLOW TESTS
# ============================================================================

class TestPasswordResetFlow:
    """Test suite for password reset functionality (forget password and reset)."""
    
    def test_reset_pass_success(self, mock_redis):
        """Test successful generation of password reset token."""
        user_id = str(uuid.uuid4())
        
        with patch('functions.conn', mock_redis):
            reset_token = reset_pass(user_id)
        
        assert reset_token is not None
        assert isinstance(reset_token, str)
        assert len(reset_token) > 0
        
        # Verify Redis was called
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        
        redis_key = call_args[0][0]
        assert redis_key.startswith("password_reset:")
        assert reset_token in redis_key
        
        expiration = call_args[0][1]
        assert expiration == 900  # 15 minutes
        
        stored_user_id = call_args[0][2]
        assert stored_user_id == user_id
    
    def test_reset_pass_no_redis_connection(self):
        """Test reset_pass when Redis connection is not available."""
        user_id = str(uuid.uuid4())
        
        with patch('functions.conn', None):
            reset_token = reset_pass(user_id)
        
        assert reset_token is None
    
    def test_reset_pass_redis_error(self, mock_redis):
        """Test reset_pass when Redis raises an error."""
        user_id = str(uuid.uuid4())
        mock_redis.setex.side_effect = redis.RedisError("Connection failed")
        
        with patch('functions.conn', mock_redis):
            reset_token = reset_pass(user_id)
        
        assert reset_token is None
    
    def test_reset_pass_generates_unique_tokens(self, mock_redis):
        """Test that reset_pass generates unique tokens for each call."""
        user_id = str(uuid.uuid4())
        
        with patch('functions.conn', mock_redis):
            token1 = reset_pass(user_id)
            token2 = reset_pass(user_id)
        
        assert token1 != token2
    
    def test_update_pass_in_db_success(self, mock_session, test_session, mock_redis):
        """Test successful password update with valid reset token."""
        user_id = str(uuid.uuid4())
        reset_token = str(uuid.uuid4())
        new_password = "newSecurePass123"
        
        # Create test user
        user = Users(
            id=user_id,
            first_name="Reset",
            last_name="Test",
            email="reset@example.com",
            password=hash_password("oldPassword"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Mock Redis to return user_id as bytes
        mock_redis.get.return_value = user_id.encode('utf-8')
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 200
        assert "successfully" in result["message"].lower()
        
        # Verify Redis was queried
        redis_key = f"password_reset:{reset_token}"
        mock_redis.get.assert_called_with(redis_key)
        
        # Verify Redis token was deleted
        mock_redis.delete.assert_called_with(redis_key)
        
        # Verify password was updated
        updated_user = test_session.query(Users).filter_by(id=user_id).first()
        assert varify_password(new_password, updated_user.password) is True
        assert varify_password("oldPassword", updated_user.password) is False
    
    def test_update_pass_in_db_invalid_token(self, mock_session, test_session, mock_redis):
        """Test password update with invalid/expired reset token."""
        reset_token = str(uuid.uuid4())
        new_password = "newPassword123"
        
        # Mock Redis to return None (token not found/expired)
        mock_redis.get.return_value = None
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 400
        assert "error" in result
    
    def test_update_pass_in_db_user_not_found(self, mock_session, test_session, mock_redis):
        """Test password update when user doesn't exist in database."""
        fake_user_id = str(uuid.uuid4())
        reset_token = str(uuid.uuid4())
        new_password = "newPassword123"
        
        # Mock Redis to return a user_id that doesn't exist
        mock_redis.get.return_value = fake_user_id.encode('utf-8')
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 404
        assert "error" in result
    
    def test_update_pass_in_db_no_redis_connection(self):
        """Test password update when Redis connection is not available."""
        reset_token = str(uuid.uuid4())
        new_password = "newPassword123"
        
        with patch('functions.conn', None):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 500
        assert "error" in result
    
    def test_update_pass_in_db_deletes_refresh_token(self, mock_session, test_session, mock_redis):
        """Test that password update deletes existing refresh token."""
        user_id = str(uuid.uuid4())
        reset_token = str(uuid.uuid4())
        new_password = "newSecurePass123"
        refresh_token_value = "existing_refresh_token"
        
        # Create test user
        user = Users(
            id=user_id,
            first_name="Token",
            last_name="Delete",
            email="tokendelete@example.com",
            password=hash_password("oldPassword"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create existing refresh token
        refresh_token = RefreshToken(
            user_id=user_id,
            refresh_token=refresh_token_value,
            created_at=datetime.utcnow()
        )
        test_session.add(refresh_token)
        test_session.commit()
        
        # Mock Redis
        mock_redis.get.return_value = user_id.encode('utf-8')
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 200
        
        # Verify refresh token was deleted
        deleted_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert deleted_token is None


# ============================================================================
# EDGE CASES AND ERROR HANDLING TESTS
# ============================================================================

class TestEdgeCases:
    """Test suite for edge cases and error handling."""
    
    def test_find_user_by_email_with_whitespace(self, mock_session, test_session):
        """Test finding user with whitespace in email."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_email("  test@example.com  ")
        
        assert result is not None
        assert result["email"] == "test@example.com"
    
    def test_find_user_by_email_empty_string(self, mock_session, test_session):
        """Test finding user with empty email."""
        with patch('functions.Session', return_value=test_session):
            result = find_user_by_email("")
        
        assert result is None
    
    def test_save_refresh_token_updates_timestamp(self, mock_session, test_session):
        """Test that saving refresh token updates the created_at timestamp."""
        user_id = str(uuid.uuid4())
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="timestamp@example.com",
            password=hash_password("password"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Save first token
        old_time = datetime(2024, 1, 1, 0, 0, 0)
        token = RefreshToken(
            user_id=user_id,
            refresh_token="token1",
            created_at=old_time
        )
        test_session.add(token)
        test_session.commit()
        
        # Update token
        save_refresh_token(user_id, "token2")
        
        # Verify timestamp was updated
        saved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert saved_token.created_at > old_time
    
    def test_delete_refresh_token_handles_none(self, mock_session, test_session):
        """Test deleting with None as token."""
        result = delete_refresh_token(None)
        
        assert result is not None
        assert result["status_code"] in [404, 500]
    
    def test_update_pass_in_db_empty_token(self, mock_redis):
        """Test password update with empty reset token."""
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db("", "newPassword123")
        
        assert result["status_code"] == 400
        assert "error" in result
    
    def test_update_pass_in_db_empty_password(self, mock_redis):
        """Test password update with empty new password."""
        reset_token = str(uuid.uuid4())
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, "")
        
        assert result["status_code"] == 400
        assert "error" in result
    
    def test_update_pass_in_db_whitespace_handling(self, mock_session, test_session, mock_redis):
        """Test that password update strips whitespace from password."""
        user_id = str(uuid.uuid4())
        reset_token = str(uuid.uuid4())
        new_password = "  newPassword123  "
        
        # Create test user
        user = Users(
            id=user_id,
            first_name="Whitespace",
            last_name="Test",
            email="whitespace@example.com",
            password=hash_password("oldPassword"),
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Mock Redis
        mock_redis.get.return_value = user_id.encode('utf-8')
        
        with patch('functions.conn', mock_redis):
            result = update_pass_in_db(reset_token, new_password)
        
        assert result["status_code"] == 200
        
        # Verify password was stored without whitespace
        updated_user = test_session.query(Users).filter_by(id=user_id).first()
        assert varify_password("newPassword123", updated_user.password) is True
        assert varify_password("  newPassword123  ", updated_user.password) is False


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for complete user workflows."""
    
    def test_full_registration_login_logout_flow(self, mock_session, test_session):
        """Test complete flow: register -> login -> logout."""
        email = "fullflow@example.com"
        password = "password123"
        
        # Step 1: Register
        reg_result = user_registration(
            first_name="Full",
            last_name="Flow",
            email=email,
            password=password
        )
        
        assert reg_result["status_code"] == 201
        user_id = reg_result["new_user"]["user_id"]
        
        # Step 2: Login
        login_result = user_login(email=email, password=password)
        assert isinstance(login_result, tuple)
        
        access_token_tuple, refresh_token_tuple = login_result
        access_token, _ = access_token_tuple
        refresh_token, _ = refresh_token_tuple
        
        # Verify tokens are valid
        decoded = decode_token(access_token)
        assert decoded["sub"] == user_id
        
        # Step 3: Logout
        logout_result = delete_refresh_token(refresh_token)
        assert logout_result["status_code"] == 200
        
        # Verify refresh token was deleted
        token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert token is None
    
    def test_full_password_reset_flow(self, mock_session, test_session, mock_redis):
        """Test complete password reset flow: forget -> reset."""
        email = "resetflow@example.com"
        old_password = "oldPassword123"
        new_password = "newPassword456"
        
        # Step 1: Register user
        reg_result = user_registration(
            first_name="Reset",
            last_name="Flow",
            email=email,
            password=old_password
        )
        user_id = reg_result["new_user"]["user_id"]
        
        # Step 2: Request password reset
        with patch('functions.conn', mock_redis):
            reset_token = reset_pass(user_id)
        
        assert reset_token is not None
        
        # Step 3: Reset password
        mock_redis.get.return_value = user_id.encode('utf-8')
        
        with patch('functions.conn', mock_redis):
            reset_result = update_pass_in_db(reset_token, new_password)
        
        assert reset_result["status_code"] == 200
        
        # Step 4: Verify old password doesn't work
        old_login_result = user_login(email=email, password=old_password)
        assert isinstance(old_login_result, dict)
        assert old_login_result["status_code"] == 401
        
        # Step 5: Verify new password works
        new_login_result = user_login(email=email, password=new_password)
        assert isinstance(new_login_result, tuple)
    
    def test_token_refresh_after_login(self, mock_session, test_session):
        """Test refreshing access token after login."""
        email = "tokenrefresh@example.com"
        password = "password123"
        
        # Register and login
        reg_result = user_registration(
            first_name="Token",
            last_name="Refresh",
            email=email,
            password=password
        )
        user_id = reg_result["new_user"]["user_id"]
        
        login_result = user_login(email=email, password=password)
        _, refresh_token_tuple = login_result
        refresh_token, _ = refresh_token_tuple
        
        # Decode refresh token to get user_id
        decoded_refresh = decode_token(refresh_token)
        assert decoded_refresh["sub"] == user_id
        
        # Create new access token
        new_access_token, _ = create_access_token(user_id)
        assert new_access_token is not None
        
        # Verify new access token is valid
        decoded_access = decode_token(new_access_token)
        assert decoded_access["sub"] == user_id


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
