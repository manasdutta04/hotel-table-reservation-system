"""
Security utilities for the hotel reservation system
Provides password validation, input sanitization, and security helpers
"""

import re
import string
import secrets


class PasswordValidator:
    """Password validation utility class"""
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password strength according to security best practices
        Returns: (is_valid: bool, errors: list)
        """
        errors = []
        
        # Check minimum length
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for digit
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in weak_passwords:
            errors.append("Password is too common and easily guessable")
        
        return len(errors) == 0, errors

    @staticmethod
    def generate_secure_password(length=12):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password


class InputSanitizer:
    """Input sanitization utility class"""
    
    @staticmethod
    def sanitize_username(username):
        """Sanitize username input"""
        if not username:
            return None
        
        # Remove leading/trailing whitespace
        username = username.strip()
        
        # Check for valid characters (alphanumeric and underscore only)
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return None
        
        # Check length constraints
        if len(username) < 3 or len(username) > 50:
            return None
        
        return username
    
    @staticmethod
    def sanitize_email(email):
        """Basic email sanitization and validation"""
        if not email:
            return None
        
        email = email.strip().lower()
        
        # Basic email regex validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return None
        
        return email
    
    @staticmethod
    def sanitize_string_input(input_str, max_length=255):
        """General string input sanitization"""
        if not input_str:
            return None
        
        # Remove leading/trailing whitespace
        input_str = input_str.strip()
        
        # Check length
        if len(input_str) > max_length:
            return None
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        
        return input_str


class SecurityLogger:
    """Security event logging utility"""
    
    @staticmethod
    def log_login_attempt(username, success, ip_address=None):
        """Log login attempts for security monitoring"""
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "SUCCESS" if success else "FAILED"
        ip_info = f" from {ip_address}" if ip_address else ""
        
        log_entry = f"[{timestamp}] LOGIN {status}: {username}{ip_info}\n"
        
        try:
            with open('security.log', 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write security log: {e}")
    
    @staticmethod
    def log_password_change(username):
        """Log password change events"""
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] PASSWORD CHANGE: {username}\n"
        
        try:
            with open('security.log', 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write security log: {e}")


class RateLimiter:
    """Simple rate limiting for login attempts"""
    
    def __init__(self, max_attempts=5, lockout_time=300):  # 5 minutes lockout
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.attempts = {}  # username -> (count, last_attempt_time)
    
    def is_locked_out(self, username):
        """Check if user is currently locked out"""
        import time
        
        if username not in self.attempts:
            return False
        
        count, last_attempt = self.attempts[username]
        
        # Check if lockout period has expired
        if time.time() - last_attempt > self.lockout_time:
            # Reset attempts after lockout period
            del self.attempts[username]
            return False
        
        return count >= self.max_attempts
    
    def record_attempt(self, username, success):
        """Record a login attempt"""
        import time
        
        current_time = time.time()
        
        if username not in self.attempts:
            self.attempts[username] = (0, current_time)
        
        if success:
            # Reset attempts on successful login
            if username in self.attempts:
                del self.attempts[username]
        else:
            # Increment failed attempts
            count, _ = self.attempts[username]
            self.attempts[username] = (count + 1, current_time)
    
    def get_remaining_lockout_time(self, username):
        """Get remaining lockout time in seconds"""
        import time
        
        if username not in self.attempts:
            return 0
        
        count, last_attempt = self.attempts[username]
        if count < self.max_attempts:
            return 0
        
        elapsed = time.time() - last_attempt
        remaining = max(0, self.lockout_time - elapsed)
        return int(remaining)