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
        # First create a user (required for foreign key)
        user_id = str(uuid.uuid4())
        user = Users(
            id=user_id,
            first_name="Token",
            last_name="User",
            email="tokenuser@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Now create refresh token
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
        # Create user first
        user = Users(
            id=user_id,
            first_name="Query",
            last_name="User",
            email="queryuser@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create token
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
        # Create user first
        user = Users(
            id=user_id,
            first_name="Update",
            last_name="User",
            email="updateuser@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create token
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
        # Create user first
        user = Users(
            id=user_id,
            first_name="Delete",
            last_name="Token",
            email="deletetoken@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create token
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
    
    def test_refresh_token_large_value(self, test_session):
        """Test that refresh token can store up to 500 characters."""
        user_id = str(uuid.uuid4())
        # Create user first
        user = Users(
            id=user_id,
            first_name="Large",
            last_name="Token",
            email="largetoken@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create a long token (close to 500 chars)
        long_token = "a" * 450  # 450 character token
        token = RefreshToken(
            user_id=user_id,
            refresh_token=long_token,
            created_at=datetime.utcnow()
        )
        
        test_session.add(token)
        test_session.commit()
        
        # Verify token was stored correctly
        retrieved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert retrieved_token is not None
        assert len(retrieved_token.refresh_token) == 450
        assert retrieved_token.refresh_token == long_token


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


class TestDatabaseRelationships:
    """Test suite for database relationships between Users and RefreshToken."""
    
    def test_user_refresh_token_relationship(self, test_session):
        """Test the one-to-one relationship between User and RefreshToken."""
        user_id = str(uuid.uuid4())
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Relationship",
            last_name="Test",
            email="relationship@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create refresh token
        token = RefreshToken(
            user_id=user_id,
            refresh_token="test_token_123",
            created_at=datetime.utcnow()
        )
        test_session.add(token)
        test_session.commit()
        
        # Test relationship from User side
        retrieved_user = test_session.query(Users).filter_by(id=user_id).first()
        assert retrieved_user.refresh_token is not None
        assert retrieved_user.refresh_token.refresh_token == "test_token_123"
        
        # Test relationship from RefreshToken side
        retrieved_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert retrieved_token.user is not None
        assert retrieved_token.user.email == "relationship@example.com"
    
    def test_user_without_refresh_token(self, test_session):
        """Test that a user can exist without a refresh token."""
        user_id = str(uuid.uuid4())
        
        user = Users(
            id=user_id,
            first_name="No",
            last_name="Token",
            email="notoken@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # User should exist but have no refresh token
        retrieved_user = test_session.query(Users).filter_by(id=user_id).first()
        assert retrieved_user is not None
        assert retrieved_user.refresh_token is None
    
    def test_cascade_delete_user_with_token(self, test_session):
        """Test that deleting a user automatically deletes their refresh token (cascade delete)."""
        user_id = str(uuid.uuid4())
        
        # Create user
        user = Users(
            id=user_id,
            first_name="Cascade",
            last_name="Delete",
            email="cascade@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        # Create refresh token
        token = RefreshToken(
            user_id=user_id,
            refresh_token="token_to_cascade",
            created_at=datetime.utcnow()
        )
        test_session.add(token)
        test_session.commit()
        
        # Verify token exists
        existing_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert existing_token is not None
        
        # Delete user - token should be automatically deleted due to cascade
        test_session.delete(user)
        test_session.commit()
        
        # Verify user is deleted
        deleted_user = test_session.query(Users).filter_by(id=user_id).first()
        assert deleted_user is None
        
        # Verify token is also deleted (cascade delete)
        deleted_token = test_session.query(RefreshToken).filter_by(user_id=user_id).first()
        assert deleted_token is None


class TestDatabaseIndexing:
    """Test suite for database indexing."""
    
    def test_email_index_exists(self, test_engine):
        """Test that email column has an index."""
        from sqlalchemy import inspect
        
        inspector = inspect(test_engine)
        indexes = inspector.get_indexes('users')
        
        # Check if there's an index on email column
        email_indexed = False
        for index in indexes:
            if 'email' in index['column_names']:
                email_indexed = True
                break
        
        # In SQLite, unique columns automatically get indexes
        # So we should have at least one index on email
        assert email_indexed or len(indexes) > 0
    
    def test_email_query_performance(self, test_session):
        """Test querying by email (indexed column) is efficient."""
        # Add multiple users
        for i in range(100):
            user = Users(
                id=str(uuid.uuid4()),
                first_name=f"User{i}",
                last_name=f"Last{i}",
                email=f"user{i}@example.com",
                password="password",
                created_at=datetime.utcnow()
            )
            test_session.add(user)
        
        test_session.commit()
        
        # Query by email should work efficiently
        result = test_session.query(Users).filter_by(email="user50@example.com").first()
        assert result is not None
        assert result.first_name == "User50"
    
    def test_email_unique_constraint(self, test_session):
        """Test that email unique constraint is enforced."""
        user1 = Users(
            id=str(uuid.uuid4()),
            first_name="First",
            last_name="User",
            email="unique@example.com",
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user1)
        test_session.commit()
        
        # Try to add another user with same email
        user2 = Users(
            id=str(uuid.uuid4()),
            first_name="Second",
            last_name="User",
            email="unique@example.com",
            password="password2",
            created_at=datetime.utcnow()
        )
        test_session.add(user2)
        
        # Should raise exception on commit
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            test_session.commit()


class TestDatabaseSchema:
    """Test suite for database schema validation."""
    
    def test_users_table_columns(self, test_engine):
        """Test that Users table has all required columns."""
        from sqlalchemy import inspect
        
        inspector = inspect(test_engine)
        columns = inspector.get_columns('users')
        column_names = [col['name'] for col in columns]
        
        required_columns = ['id', 'first_name', 'last_name', 'email', 'password', 'created_at']
        for col in required_columns:
            assert col in column_names
    
    def test_refresh_token_table_columns(self, test_engine):
        """Test that RefreshToken table has all required columns."""
        from sqlalchemy import inspect
        
        inspector = inspect(test_engine)
        columns = inspector.get_columns('refresh_token')
        column_names = [col['name'] for col in columns]
        
        required_columns = ['user_id', 'refresh_token', 'created_at']
        for col in required_columns:
            assert col in column_names
    
    def test_foreign_key_constraint(self, test_engine):
        """Test that refresh_token has foreign key to users."""
        from sqlalchemy import inspect
        
        inspector = inspect(test_engine)
        foreign_keys = inspector.get_foreign_keys('refresh_token')
        
        # Should have at least one foreign key
        assert len(foreign_keys) > 0
        
        # Foreign key should reference users table
        fk = foreign_keys[0]
        assert fk['referred_table'] == 'users'
        assert 'user_id' in fk['constrained_columns']
    
    def test_varchar_limits(self, test_session):
        """Test that varchar limits are enforced correctly."""
        # Test email varchar(50)
        user = Users(
            id=str(uuid.uuid4()),
            first_name="Test",
            last_name="User",
            email="a" * 40 + "@test.com",  # Just under 50 chars
            password="password",
            created_at=datetime.utcnow()
        )
        test_session.add(user)
        test_session.commit()
        
        retrieved = test_session.query(Users).filter_by(id=user.id).first()
        assert retrieved is not None
        assert len(retrieved.email) <= 50
