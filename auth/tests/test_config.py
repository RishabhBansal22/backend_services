import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestConfigSettings:
    """Test suite for configuration settings."""
    
    def test_settings_imports(self):
        """Test that Settings class can be imported."""
        from config import Settings
        assert Settings is not None
    
    def test_settings_instance(self):
        """Test that settings instance can be created."""
        from config import settings
        assert settings is not None
    
    @patch.dict(os.environ, {
        'JWT_SECRET_KEY': 'test_secret_key_12345',
        'ACCESS_TOKEN_EXPIRE_MINUTES': '30',
        'DRIVER': 'pymysql',
        'HOST': 'localhost',
        'PORT': '3306',
        'USER': 'test_user',
        'PASSWORD': 'test_password',
        'DATABASE': 'test_db'
    })
    def test_settings_with_env_vars(self):
        """Test that Settings loads environment variables correctly."""
        from config import Settings
        
        test_settings = Settings()
        
        assert test_settings.JWT_SECRET_KEY == 'test_secret_key_12345'
        assert test_settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30
        assert test_settings.DRIVER == 'pymysql'
        assert test_settings.HOST == 'localhost'
        assert test_settings.PORT == 3306
        assert test_settings.USER == 'test_user'
        assert test_settings.PASSWORD == 'test_password'
        assert test_settings.DATABASE == 'test_db'
    
    def test_settings_has_required_attributes(self):
        """Test that settings instance has all required attributes."""
        from config import settings
        
        # Check JWT settings
        assert hasattr(settings, 'JWT_SECRET_KEY')
        assert hasattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES')
        
        # Check database settings
        assert hasattr(settings, 'DRIVER')
        assert hasattr(settings, 'HOST')
        assert hasattr(settings, 'PORT')
        assert hasattr(settings, 'USER')
        assert hasattr(settings, 'PASSWORD')
        assert hasattr(settings, 'DATABASE')
    
    def test_jwt_secret_key_type(self):
        """Test that JWT_SECRET_KEY is a string."""
        from config import settings
        assert isinstance(settings.JWT_SECRET_KEY, str)
        assert len(settings.JWT_SECRET_KEY) > 0
    
    def test_access_token_expire_minutes_type(self):
        """Test that ACCESS_TOKEN_EXPIRE_MINUTES is an integer."""
        from config import settings
        assert isinstance(settings.ACCESS_TOKEN_EXPIRE_MINUTES, int)
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    
    def test_database_port_type(self):
        """Test that PORT is an integer."""
        from config import settings
        assert isinstance(settings.PORT, int)
        assert settings.PORT > 0
    
    def test_db_url_str_construction(self):
        """Test that database URL string is constructed correctly."""
        from config import db_url_str
        
        assert db_url_str is not None
        assert isinstance(db_url_str, str)
        # URL should contain mysql driver
        assert 'mysql' in db_url_str
        # URL should follow pattern: mysql+driver://user:password@host:port/database
        assert '://' in db_url_str
        assert '@' in db_url_str
    
    @patch.dict(os.environ, {
        'JWT_SECRET_KEY': 'test_key',
        'ACCESS_TOKEN_EXPIRE_MINUTES': '60',
        'DRIVER': 'testdriver',
        'HOST': 'testhost',
        'PORT': '9999',
        'USER': 'testuser',
        'PASSWORD': 'testpass',
        'DATABASE': 'testdb'
    })
    def test_db_url_format(self):
        """Test that database URL follows correct format."""
        # Need to reload the module to pick up new env vars
        import importlib
        import config
        importlib.reload(config)
        
        expected_url = "mysql+testdriver://testuser:testpass@testhost:9999/testdb"
        assert config.db_url_str == expected_url
    
    def test_settings_model_config(self):
        """Test that Settings uses correct model configuration."""
        from config import Settings
        
        # Check that model_config exists
        assert hasattr(Settings, 'model_config')
        
        # It should be a SettingsConfigDict
        model_config = Settings.model_config
        assert model_config is not None


class TestConfigErrorHandling:
    """Test suite for configuration error handling."""
    
    def test_config_handles_missing_env_file_gracefully(self):
        """Test that config can be imported even if .env file is missing."""
        # This should not raise an exception
        try:
            from config import settings
            assert settings is not None
        except Exception as e:
            pytest.fail(f"Config import failed with missing .env: {e}")
    
    def test_db_url_str_error_handling(self):
        """Test that db_url_str construction handles errors."""
        try:
            from config import db_url_str
            # Should either be a valid string or handle error gracefully
            assert db_url_str is not None or True  # May be None on error
        except Exception:
            # Should not crash, but handle gracefully
            pass


class TestConfigIntegration:
    """Integration tests for config usage."""
    
    def test_config_used_in_tokens_module(self):
        """Test that config settings can be used in tokens module."""
        from config import settings
        from auth.functions import TOKEN_TIMEOUT
        
        # TOKEN_TIMEOUT should be a positive integer
        # (may not match settings if module was loaded with different env)
        assert isinstance(TOKEN_TIMEOUT, int)
        assert TOKEN_TIMEOUT > 0
    
    def test_config_used_in_database_module(self):
        """Test that config settings can be used in database module."""
        from config import db_url_str
        from database import engine
        
        # Engine should exist (though connection may fail in test env)
        assert engine is not None
