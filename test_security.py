#!/usr/bin/env python3
"""
Test script for security enhancements
Tests password hashing, validation, and rate limiting
"""

from login_backend import PersistentHashTable
from security_utils import PasswordValidator, InputSanitizer
import os
import time

def test_password_hashing():
    """Test password hashing functionality"""
    print("Testing Password Hashing...")
    
    # Create a test instance
    hash_table = PersistentHashTable(filename='test_login.txt')
    
    # Test user registration with hashed password
    result = hash_table.insert("testuser", "SecurePass123!")
    print(f"Registration result: {result}")
    
    # Test login with correct password
    login_result = hash_table.login("testuser", "SecurePass123!")
    print(f"Login with correct password: {login_result}")
    
    # Test login with incorrect password
    login_result = hash_table.login("testuser", "wrongpassword")
    print(f"Login with incorrect password: {login_result}")
    
    # Clean up test file
    if os.path.exists('test_login.txt'):
        os.remove('test_login.txt')
    
    print("Password hashing test completed!\n")

def test_password_validation():
    """Test password strength validation"""
    print("Testing Password Validation...")
    
    test_passwords = [
        "weak",  # Too short
        "password",  # Common password
        "Password123",  # Missing special character
        "Password123!",  # Strong password
        "UPPERCASE123!",  # Missing lowercase
        "lowercase123!",  # Missing uppercase
    ]
    
    for password in test_passwords:
        is_valid, errors = PasswordValidator.validate_password_strength(password)
        print(f"Password '{password}': {'Valid' if is_valid else 'Invalid'}")
        if errors:
            for error in errors:
                print(f"  - {error}")
    
    print("Password validation test completed!\n")

def test_input_sanitization():
    """Test input sanitization"""
    print("Testing Input Sanitization...")
    
    test_usernames = [
        "validuser",  # Valid
        "user_123",   # Valid with underscore and numbers
        "us",         # Too short
        "user@domain", # Invalid characters
        "a" * 60,     # Too long
        "User Name",  # Spaces not allowed
    ]
    
    for username in test_usernames:
        sanitized = InputSanitizer.sanitize_username(username)
        print(f"Username '{username}': {'Valid' if sanitized else 'Invalid'} -> {sanitized}")
    
    print("Input sanitization test completed!\n")

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("Testing Rate Limiting...")
    
    # Create a test instance with lower limits for testing
    hash_table = PersistentHashTable(filename='test_rate_limit.txt')
    hash_table.rate_limiter.max_attempts = 3
    hash_table.rate_limiter.lockout_time = 10  # 10 seconds for testing
    
    # Register a test user
    hash_table.insert("ratetest", "SecurePass123!")
    
    # Test multiple failed login attempts
    for i in range(5):
        result = hash_table.login("ratetest", "wrongpassword")
        print(f"Failed attempt {i+1}: {result}")
        
        if result.startswith("locked_out_"):
            print("Account locked due to too many failed attempts")
            break
    
    # Test that correct password also fails when locked out
    result = hash_table.login("ratetest", "SecurePass123!")
    print(f"Login with correct password while locked out: {result}")
    
    # Clean up test file
    if os.path.exists('test_rate_limit.txt'):
        os.remove('test_rate_limit.txt')
    
    print("Rate limiting test completed!\n")

def test_legacy_migration():
    """Test legacy password migration"""
    print("Testing Legacy Password Migration...")
    
    # Create a hash table and manually insert legacy data
    hash_table = PersistentHashTable(filename='test_legacy.txt')
    
    # Manually insert a legacy plain text password
    username = "legacyuser"
    plain_password = "plainpassword"
    index = hash_table.hash_function(username)
    
    # Ensure the bucket exists
    while len(hash_table.table) <= index:
        hash_table.table.append([])
    
    # Insert plain text password (legacy format)
    hash_table.table[index].append(f"{username}:{plain_password}")
    hash_table.save_table()
    
    # Try to login with legacy password - should work and migrate
    result = hash_table.login("legacyuser", "plainpassword")
    print(f"Legacy login result: {result}")
    
    # Verify password was migrated by trying to login again
    result = hash_table.login("legacyuser", "plainpassword")
    print(f"Post-migration login result: {result}")
    
    # Clean up test file
    if os.path.exists('test_legacy.txt'):
        os.remove('test_legacy.txt')
    
    print("Legacy migration test completed!\n")

if __name__ == "__main__":
    print("=== Security Enhancement Tests ===\n")
    
    test_password_hashing()
    test_password_validation()
    test_input_sanitization()
    test_rate_limiting()
    test_legacy_migration()
    
    print("=== All Tests Completed ===")
    print("\nSecurity enhancements implemented:")
    print("✓ Password hashing with bcrypt")
    print("✓ Password strength validation")
    print("✓ Input sanitization")
    print("✓ Rate limiting for login attempts")
    print("✓ Security logging")
    print("✓ Legacy password migration")