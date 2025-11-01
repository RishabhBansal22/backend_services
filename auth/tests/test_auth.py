import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import Base, Users, RefreshToken
from tokens import (
    hash_password,
    varify_password,
    user_registration,
    user_login,
    create_token,
    decode_token,
    find_user_by_email,
    find_user_by_id,
    save_refresh_token,
    get_referesh_token
)


@pytest.fixture(scope="function")
def test_engine():
    """Create a test database engine using SQLite in-memory database."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="function")
def test_session(test_engine):
    """Create a test database session."""
    TestSession = sessionmaker(bind=test_engine)
    session = TestSession()
    yield session
    session.close()


@pytest.fixture(scope="function")
def mock_session(test_session):
    """Mock the Session to use test_session."""
    with patch('tokens.Session') as mock:
        mock.return_value.__enter__ = Mock(return_value=test_session)
        mock.return_value.__exit__ = Mock(return_value=False)
        # Also support direct session call
        mock.return_value = test_session
        yield mock


class TestPasswordHashing:
    """Test suite for password hashing functions."""
    
    def test_hash_password(self):
        """Test that hash_password returns a hashed string."""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0
    
    def test_hash_password_different_each_time(self):
        """Test that hashing the same password twice produces different hashes."""
        password = "samePassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Bcrypt uses different salts, so hashes should be different
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Test verifying a correct password."""
        password = "correctPassword"
        hashed = hash_password(password)
        
        result = varify_password(password, hashed)
        assert result is True
    
    def test_verify_password_incorrect(self):
        """Test verifying an incorrect password."""
        correct_password = "correctPassword"
        wrong_password = "wrongPassword"
        hashed = hash_password(correct_password)
        
        result = varify_password(wrong_password, hashed)
        assert result is False
    
    def test_verify_password_empty_string(self):
        """Test verifying with empty password."""
        password = "password"
        hashed = hash_password(password)
        
        result = varify_password("", hashed)
        assert result is False


class TestUserRegistration:
    """Test suite for user registration."""
    
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
    
    def test_user_registration_duplicate_email(self, mock_session, test_session):
        """Test registration with duplicate email."""
        # First registration
        user_registration(
            first_name="Jane",
            last_name="Smith",
            email="jane@example.com",
            password="password123"
        )
        
        # Attempt duplicate registration
        result = user_registration(
            first_name="Jane",
            last_name="Duplicate",
            email="jane@example.com",
            password="password456"
        )
        
        assert "error" in result
        assert result["status_code"] == 409
        assert result["error"] == "Registration failed"
    
    def test_user_registration_case_insensitive_email(self, mock_session, test_session):
        """Test that email comparison is case-insensitive."""
        # Register with lowercase email
        user_registration(
            first_name="Test",
            last_name="User",
            email="test@example.com",
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


class TestUserLogin:
    """Test suite for user login function."""
    
    def test_user_login_success(self, mock_session, test_session):
        """Test successful user login returns access and refresh tokens."""
        # First register a user
        password = "myPassword123"
        email = "login@example.com"
        
        user_registration(
            first_name="Login",
            last_name="Test",
            email=email,
            password=password
        )
        
        # Attempt login
        result = user_login(email=email, password=password)
        
        # Should return tuple of tuples: ((access_token, access_exp), (refresh_token, refresh_exp))
        assert isinstance(result, tuple)
        assert len(result) == 2
        
        access_token_tuple, refresh_token_tuple = result
        assert isinstance(access_token_tuple, tuple)
        assert isinstance(refresh_token_tuple, tuple)
        
        access_token, access_exp = access_token_tuple
        refresh_token, refresh_exp = refresh_token_tuple
        
        # Verify tokens are not empty strings
        assert isinstance(access_token, str)
        assert len(access_token) > 0
        assert isinstance(refresh_token, str)
        assert len(refresh_token) > 0
        
        # Verify tokens can be decoded
        decoded_access = decode_token(access_token)
        assert decoded_access is not None
        assert decoded_access["email"] == email.lower()
    
    def test_user_login_wrong_password(self, mock_session, test_session):
        """Test login with wrong password returns error."""
        email = "user@example.com"
        correct_password = "correctPassword"
        wrong_password = "wrongPassword"
        
        # Register user
        user_registration(
            first_name="User",
            last_name="Test",
            email=email,
            password=correct_password
        )
        
        # Attempt login with wrong password
        result = user_login(email=email, password=wrong_password)
        
        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "status_code" in result
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
        assert "status_code" in result
        assert result["status_code"] == 401
        assert "Invalid email or password" in result["error"]
    
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
        access_token_tuple, _ = result
        access_token, _ = access_token_tuple
        assert len(access_token) > 0
    
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
        email = "test@example.com"
        
        user_registration(
            first_name="Test",
            last_name="User",
            email=email,
            password="RealPassword123"
        )
        
        result = user_login(email=email, password="")
        
        assert isinstance(result, dict)
        assert result["status_code"] == 401


class TestTokenOperations:
    """Test suite for JWT token operations."""
    
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
        # Create a token that expires immediately
        expires_delta = timedelta(seconds=-1)
        
        token, _ = create_token(data, expires_delta)
        
        # Attempt to decode expired token
        decoded = decode_token(token)
        
        # Should return None for expired tokens
        assert decoded is None
    
    def test_decode_token_invalid(self):
        """Test decoding an invalid token returns None."""
        invalid_token = "invalid.token.string"
        
        decoded = decode_token(invalid_token)
        
        # Should return None for invalid tokens
        assert decoded is None


class TestRefreshTokenOperations:
    """Test suite for refresh token operations."""
    
    def test_save_refresh_token_new_user(self, mock_session, test_session):
        """Test saving a refresh token for a user who doesn't have one yet."""
        user_id = str(uuid.uuid4())
        refresh_token = "new_refresh_token_123"
        
        # First create a user
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password="hashed_pass",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Save refresh token (first time for this user)
        result = save_refresh_token(user_id, refresh_token)
        
        # Should return None on success
        assert result is None
        
        # Verify token was saved
        saved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert saved_token is not None
        assert saved_token.refresh_token == refresh_token
        assert saved_token.user_id == user_id
    
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
            password="hashed_pass",
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
        assert all_tokens[0].refresh_token != old_token
    
    def test_save_refresh_token_updates_timestamp(self, mock_session, test_session):
        """Test that saving refresh token updates the created_at timestamp."""
        user_id = str(uuid.uuid4())
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="timestamp@example.com",
            password="hashed_pass",
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
        
        # Attempt to retrieve non-existent token
        retrieved = get_referesh_token(user_id)
        
        assert retrieved is None
    
    def test_save_refresh_token_handles_special_characters(self, mock_session, test_session):
        """Test that refresh tokens with special characters are saved correctly."""
        user_id = str(uuid.uuid4())
        # JWT tokens can contain special characters
        refresh_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Special",
            last_name="Chars",
            email="special@example.com",
            password="hashed_pass",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Save token
        result = save_refresh_token(user_id, refresh_token)
        
        assert result is None
        
        # Verify token was saved correctly
        saved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert saved_token.refresh_token == refresh_token


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
            password="hashed_password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Mock the Session to return our test_session
        with patch('tokens.Session', return_value=test_session):
            result = find_user_by_email(email)
        
        assert result is not None
        assert result["email"] == email
        assert result["first_name"] == "Find"
        assert result["last_name"] == "Me"
    
    def test_find_user_by_email_not_exists(self, mock_session, test_session):
        """Test finding a non-existent user by email."""
        with patch('tokens.Session', return_value=test_session):
            result = find_user_by_email("nonexistent@example.com")
        
        assert result is None
    
    def test_find_user_by_id_exists(self, mock_session, test_session):
        """Test finding an existing user by ID."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password="hashed_password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('tokens.Session', return_value=test_session):
            result = find_user_by_id(user_id)
        
        assert result is not None
        assert result["id"] == user_id
        assert result["first_name"] == "Test"
        assert result["email"] == "test@example.com"
    
    def test_find_user_by_id_not_exists(self, mock_session, test_session):
        """Test finding a non-existent user by ID."""
        fake_id = str(uuid.uuid4())
        
        with patch('tokens.Session', return_value=test_session):
            result = find_user_by_id(fake_id)
        
        assert result is None
    
    def test_find_user_by_email_case_insensitive(self, mock_session, test_session):
        """Test that email search is case-insensitive."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="Case",
            last_name="Test",
            email="lowercase@example.com",
            password="hashed_password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        with patch('tokens.Session', return_value=test_session):
            result = find_user_by_email("LOWERCASE@EXAMPLE.COM")
        
        assert result is not None
        assert result["email"] == "lowercase@example.com"
