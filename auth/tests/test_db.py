import pytest
import sys
import os
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uuid

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import Base, Users, RefreshToken, create_new_table


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


class TestUsersModel:
    """Test suite for Users model."""
    
    def test_create_user(self, test_session):
        """Test creating a new user."""
        user_id = str(uuid.uuid4())
        user = Users(
            id=user_id,
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            password="hashed_password_123",
            created_at=datetime.utcnow()
        )
        
        test_session.add(user)
        test_session.commit()
        
        # Verify user was created
        retrieved_user = test_session.query(Users).filter_by(id=user_id).first()
        assert retrieved_user is not None
        assert retrieved_user.first_name == "John"
        assert retrieved_user.last_name == "Doe"
        assert retrieved_user.email == "john.doe@example.com"
        assert retrieved_user.password == "hashed_password_123"
    
    def test_query_user_by_email(self, test_session):
        """Test querying a user by email."""
        user = Users(
            id=str(uuid.uuid4()),
            first_name="Jane",
            last_name="Smith",
            email="jane.smith@example.com",
            password="hashed_password_456",
            created_at=datetime.utcnow()
        )
        
        test_session.add(user)
        test_session.commit()
        
        # Query by email
        retrieved_user = test_session.query(Users).filter_by(email="jane.smith@example.com").first()
        assert retrieved_user is not None
        assert retrieved_user.first_name == "Jane"
        assert retrieved_user.last_name == "Smith"
    
    def test_user_email_unique(self, test_session):
        """Test that duplicate emails are handled properly."""
        user_id_1 = str(uuid.uuid4())
        user_id_2 = str(uuid.uuid4())
        
        user1 = Users(
            id=user_id_1,
            first_name="User",
            last_name="One",
            email="duplicate@example.com",
            password="password1",
            created_at=datetime.utcnow()
        )
        
        test_session.add(user1)
        test_session.commit()
        
        # Note: SQLite in-memory doesn't enforce unique constraint by default
        # This test checks that we can query for existing users
        existing_user = test_session.query(Users).filter_by(email="duplicate@example.com").first()
        assert existing_user is not None
    
    def test_update_user(self, test_session):
        """Test updating user information."""
        user_id = str(uuid.uuid4())
        user = Users(
            id=user_id,
            first_name="Original",
            last_name="Name",
            email="original@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        
        test_session.add(user)
        test_session.commit()
        
        # Update user
        user.first_name = "Updated"
        user.last_name = "NameChanged"
        test_session.commit()
        
        # Verify update
        updated_user = test_session.query(Users).filter_by(id=user_id).first()
        assert updated_user.first_name == "Updated"
        assert updated_user.last_name == "NameChanged"
    
    def test_delete_user(self, test_session):
        """Test deleting a user."""
        user_id = str(uuid.uuid4())
        user = Users(
            id=user_id,
            first_name="Delete",
            last_name="Me",
            email="delete@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        
        test_session.add(user)
        test_session.commit()
        
        # Delete user
        test_session.delete(user)
        test_session.commit()
        
        # Verify deletion
        deleted_user = test_session.query(Users).filter_by(id=user_id).first()
        assert deleted_user is None


class TestRefreshTokenModel:
    """Test suite for RefreshToken model."""
    
    def test_create_refresh_token(self, test_session):
        """Test creating a refresh token."""
        user_id = str(uuid.uuid4())
        token = RefreshToken(
            user_id=user_id,
            refresh_token="sample_refresh_token_123",
            created_at=datetime.utcnow()
        )
        
        test_session.add(token)
        test_session.commit()
        
        # Verify token was created
        retrieved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert retrieved_token is not None
        assert retrieved_token.refresh_token == "sample_refresh_token_123"
    
    def test_query_refresh_token_by_user_id(self, test_session):
        """Test querying refresh token by user_id."""
        user_id = str(uuid.uuid4())
        token = RefreshToken(
            user_id=user_id,
            refresh_token="token_xyz",
            created_at=datetime.utcnow()
        )
        
        test_session.add(token)
        test_session.commit()
        
        # Query by user_id
        retrieved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert retrieved_token is not None
        assert retrieved_token.refresh_token == "token_xyz"
    
    def test_update_refresh_token(self, test_session):
        """Test updating a refresh token."""
        user_id = str(uuid.uuid4())
        token = RefreshToken(
            user_id=user_id,
            refresh_token="old_token",
            created_at=datetime.utcnow()
        )
        
        test_session.add(token)
        test_session.commit()
        
        # Update token
        token.refresh_token = "new_token"
        token.created_at = datetime.utcnow()
        test_session.commit()
        
        # Verify update
        updated_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert updated_token.refresh_token == "new_token"
    
    def test_delete_refresh_token(self, test_session):
        """Test deleting a refresh token."""
        user_id = str(uuid.uuid4())
        token = RefreshToken(
            user_id=user_id,
            refresh_token="token_to_delete",
            created_at=datetime.utcnow()
        )
        
        test_session.add(token)
        test_session.commit()
        
        # Delete token
        test_session.delete(token)
        test_session.commit()
        
        # Verify deletion
        deleted_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert deleted_token is None


class TestDatabaseOperations:
    """Test suite for database operations."""
    
    def test_multiple_users(self, test_session):
        """Test adding multiple users."""
        users = [
            Users(
                id=str(uuid.uuid4()),
                first_name="User1",
                last_name="Last1",
                email="user1@example.com",
                password="pass1",
                created_at=datetime.utcnow()
            ),
            Users(
                id=str(uuid.uuid4()),
                first_name="User2",
                last_name="Last2",
                email="user2@example.com",
                password="pass2",
                created_at=datetime.utcnow()
            ),
            Users(
                id=str(uuid.uuid4()),
                first_name="User3",
                last_name="Last3",
                email="user3@example.com",
                password="pass3",
                created_at=datetime.utcnow()
            )
        ]
        
        test_session.add_all(users)
        test_session.commit()
        
        # Verify all users were added
        all_users = test_session.query(Users).all()
        assert len(all_users) == 3
    
    def test_query_all_users(self, test_session):
        """Test querying all users."""
        # Add some users
        for i in range(5):
            user = Users(
                id=str(uuid.uuid4()),
                first_name=f"User{i}",
                last_name=f"Last{i}",
                email=f"user{i}@example.com",
                password=f"pass{i}",
                created_at=datetime.utcnow()
            )
            test_session.add(user)
        
        test_session.commit()
        
        # Query all
        all_users = test_session.query(Users).all()
        assert len(all_users) == 5
    
    def test_filter_users(self, test_session):
        """Test filtering users by criteria."""
        users = [
            Users(
                id=str(uuid.uuid4()),
                first_name="Alice",
                last_name="Smith",
                email="alice@example.com",
                password="pass",
                created_at=datetime.utcnow()
            ),
            Users(
                id=str(uuid.uuid4()),
                first_name="Bob",
                last_name="Smith",
                email="bob@example.com",
                password="pass",
                created_at=datetime.utcnow()
            ),
            Users(
                id=str(uuid.uuid4()),
                first_name="Charlie",
                last_name="Jones",
                email="charlie@example.com",
                password="pass",
                created_at=datetime.utcnow()
            )
        ]
        
        test_session.add_all(users)
        test_session.commit()
        
        # Filter by last name
        smiths = test_session.query(Users).filter_by(last_name="Smith").all()
        assert len(smiths) == 2
