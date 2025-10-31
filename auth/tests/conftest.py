"""
Pytest configuration file with shared fixtures for testing.
"""
import pytest
import sys
import os

# Add parent directory to path for all test files
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
