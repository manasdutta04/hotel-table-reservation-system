import hashlib
import os
import bcrypt
import base64
from security_utils import SecurityLogger, RateLimiter, InputSanitizer


class PersistentHashTable:
    def __init__(self, filename='login_data.txt', num_buckets=100):
        self.filename = filename
        self.num_buckets = num_buckets
        self.table = self.load_table()
        self.rate_limiter = RateLimiter()

    def hash_function(self, username):
        """Hash function for username to determine bucket index"""
        return int(hashlib.sha256(username.encode()).hexdigest(), 16) % self.num_buckets

    def _hash_password(self, password):
        """Hash password using bcrypt with salt"""
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        # Encode to base64 for safe storage in text file
        return base64.b64encode(hashed).decode('utf-8')

    def _verify_password(self, password, hashed_password):
        """Verify password against stored hash"""
        try:
            # Decode from base64
            stored_hash = base64.b64decode(hashed_password.encode('utf-8'))
            # Verify password
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except Exception as e:
            print(f"Password verification error: {e}")
            return False

    def _is_legacy_password(self, stored_password):
        """Check if stored password is in legacy plain text format"""
        try:
            # Try to decode as base64 - if it fails, it's likely plain text
            base64.b64decode(stored_password.encode('utf-8'))
            return False
        except:
            return True

    def _migrate_legacy_password(self, username, plain_password):
        """Migrate legacy plain text password to hashed format"""
        index = self.hash_function(username)
        for i, entry in enumerate(self.table[index]):
            stored_username, _ = entry.split(':')
            if stored_username == username:
                # Replace with hashed password
                hashed_password = self._hash_password(plain_password)
                self.table[index][i] = f"{username}:{hashed_password}"
                self.save_table()
                print(f"Migrated password for user: {username}")
                return True
        return False

    def insert(self, username, password):
        """Insert new user with hashed password"""
        # Sanitize username input
        sanitized_username = InputSanitizer.sanitize_username(username)
        if not sanitized_username:
            return "invalid_username"
        
        index = self.hash_function(sanitized_username)
        
        # Check if username already exists
        for entry in self.table[index]:
            stored_username, _ = entry.split(':')
            if stored_username == sanitized_username:
                return "already"
        
        # Hash the password before storing
        hashed_password = self._hash_password(password)
        self.table[index].append(f"{sanitized_username}:{hashed_password}")
        self.save_table()
        
        # Log the registration
        SecurityLogger.log_login_attempt(sanitized_username, True)
        return "successfully"

    def login(self, username, password):
        """Authenticate user with password verification"""
        # Sanitize username input
        sanitized_username = InputSanitizer.sanitize_username(username)
        if not sanitized_username:
            SecurityLogger.log_login_attempt(username, False)
            return "invalid"
        
        # Check rate limiting
        if self.rate_limiter.is_locked_out(sanitized_username):
            remaining_time = self.rate_limiter.get_remaining_lockout_time(sanitized_username)
            SecurityLogger.log_login_attempt(sanitized_username, False)
            return f"locked_out_{remaining_time}"
        
        index = self.hash_function(sanitized_username)
        
        for entry in self.table[index]:
            stored_username, stored_password = entry.split(':')
            if stored_username == sanitized_username:
                # Check if it's a legacy plain text password
                if self._is_legacy_password(stored_password):
                    # For backward compatibility, check plain text first
                    if stored_password == password:
                        # Migrate to hashed password
                        self._migrate_legacy_password(sanitized_username, password)
                        self.rate_limiter.record_attempt(sanitized_username, True)
                        SecurityLogger.log_login_attempt(sanitized_username, True)
                        return "successfully"
                    else:
                        self.rate_limiter.record_attempt(sanitized_username, False)
                        SecurityLogger.log_login_attempt(sanitized_username, False)
                        return "invalid"
                else:
                    # Use bcrypt verification for hashed passwords
                    if self._verify_password(password, stored_password):
                        self.rate_limiter.record_attempt(sanitized_username, True)
                        SecurityLogger.log_login_attempt(sanitized_username, True)
                        return "successfully"
                    else:
                        self.rate_limiter.record_attempt(sanitized_username, False)
                        SecurityLogger.log_login_attempt(sanitized_username, False)
                        return "invalid"
        
        # User not found
        self.rate_limiter.record_attempt(sanitized_username, False)
        SecurityLogger.log_login_attempt(sanitized_username, False)
        return "invalid"

    def save_table(self):
        with open(self.filename, 'w') as f:
            for bucket in self.table:
                f.write(','.join(bucket) + '\n')

    def load_table(self):
        table = [[] for _ in range(self.num_buckets)]
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                for i, line in enumerate(f):
                    if line.strip():
                        table[i] = line.strip().split(',')
        return table
