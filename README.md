# Secure Login System

A secure, production-ready login web application built with PHP and MySQL. This system implements industry-standard security practices including password hashing, SQL injection protection, session management, and optional two-factor authentication (2FA).

## Features

- **Secure Password Storage**: Uses bcrypt with configurable cost factor for password hashing
- **Input Validation**: Comprehensive validation for usernames, emails, and passwords
- **SQL Injection Protection**: All database queries use prepared statements with PDO
- **Session Management**: Secure session handling with timeout and regeneration
- **CSRF Protection**: Cross-Site Request Forgery tokens on all forms
- **Account Lockout**: Automatic account lockout after multiple failed login attempts
- **Security Logging**: Logs all login attempts for security monitoring
- **Two-Factor Authentication (2FA)**: Optional TOTP-based 2FA using authenticator apps
- **Remember Me**: Secure persistent login with token-based authentication
- **Responsive Design**: Modern, mobile-friendly UI with gradient styling

## Security Features

### Password Security
- Bcrypt hashing with cost factor of 12 (configurable)
- Password strength requirements (8+ characters, uppercase, lowercase, number, special character)
- Password confirmation during registration

### Session Security
- Secure session configuration (HttpOnly, SameSite, Strict mode)
- Session ID regeneration on login
- Session timeout (1 hour default, configurable)
- Automatic session expiration

### Account Security
- Account lockout after 5 failed login attempts (15-minute lockout)
- Failed login attempt tracking
- IP address and user agent logging
- Last login timestamp tracking

### Two-Factor Authentication
- TOTP (Time-based One-Time Password) implementation
- QR code generation for easy setup
- Compatible with Google Authenticator, Authy, Microsoft Authenticator
- Time window validation with clock drift tolerance

## Requirements

- PHP 7.4 or higher
- MySQL 5.7 or higher (or MariaDB 10.2+)
- XAMPP, WAMP, or similar PHP/MySQL environment
- PDO extension enabled
- OpenSSL extension (for secure random number generation)

## Installation

### Step 1: Setup Database

1. Open phpMyAdmin (http://localhost/phpmyadmin)
2. Click on the "SQL" tab
3. Copy and paste the contents of `database.sql`
4. Click "Go" to execute the SQL script

This will create:
- Database: `secure_login_system`
- Tables: `users`, `user_sessions`, `password_reset_tokens`, `login_attempts`

### Step 2: Configure Database Connection

Open `config.php` and update the database credentials if needed:

```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_login_system');
define('DB_USER', 'root');
define('DB_PASS', '');
```

### Step 3: Configure Security Settings

In `config.php`, you can adjust security settings:

```php
define('BCRYPT_COST', 12); // Password hashing cost (higher = more secure but slower)
define('MAX_LOGIN_ATTEMPTS', 5); // Failed attempts before lockout
define('LOGIN_ATTEMPT_WINDOW', 900); // Lockout duration in seconds (15 minutes)
define('SESSION_TIMEOUT', 3600); // Session timeout in seconds (1 hour)
define('REMEMBER_ME_TIMEOUT', 2592000); // Remember me duration in seconds (30 days)
```

### Step 4: Enable HTTPS (Production)

For production use, enable HTTPS by updating `config.php`:

```php
ini_set('session.cookie_secure', 1); // Set to 1 when using HTTPS
```

### Step 5: Test the Application

1. Open your browser and navigate to: `http://localhost/secure%20login%20system/register.php`
2. Register a new account
3. Login with your credentials
4. Optionally enable 2FA from the dashboard

## File Structure

```
secure login system/
├── config.php              # Configuration and security functions
├── database.sql           # Database schema and setup
├── register.php           # User registration page
├── login.php              # Login page
├── dashboard.php          # User dashboard
├── logout.php             # Logout handler
├── setup_2fa.php          # 2FA setup page
├── verify_2fa.php         # 2FA verification page
└── README.md              # This file
```

## Usage

### Registration

1. Navigate to `register.php`
2. Enter a username (3-50 characters, alphanumeric + underscore)
3. Enter a valid email address
4. Create a strong password (8+ characters with uppercase, lowercase, number, and special character)
5. Confirm password
6. Click "Register"

### Login

1. Navigate to `login.php`
2. Enter your username and password
3. Optionally check "Remember me" for persistent login
4. Click "Login"
5. If 2FA is enabled, enter the code from your authenticator app

### Dashboard

The dashboard displays:
- Account information (username, email, creation date, last login)
- 2FA status and toggle
- Session information (session ID, login time, expiration)

### Two-Factor Authentication Setup

1. Login to your account
2. Navigate to the dashboard
3. Click "Enable 2FA"
4. Scan the QR code with your authenticator app
5. Enter the 6-digit verification code
6. 2FA is now enabled for your account

### Logout

Click the "Logout" button in the dashboard header to securely end your session.

## Security Best Practices

### For Development

- Keep error reporting enabled for debugging
- Use strong database passwords in production
- Regularly update PHP and MySQL to latest versions
- Keep all dependencies updated

### For Production

- Enable HTTPS with a valid SSL certificate
- Move `config.php` outside the web root if possible
- Disable error reporting in production
- Use environment variables for sensitive configuration
- Implement rate limiting on login endpoints
- Regularly review and rotate security credentials
- Monitor login attempt logs for suspicious activity
- Implement IP whitelisting if needed
- Use a web application firewall (WAF)

### Database Security

- Create a dedicated database user with limited privileges
- Use strong database passwords
- Regularly backup the database
- Enable MySQL SSL/TLS for database connections
- Restrict database access to localhost

## Troubleshooting

### Database Connection Failed

- Verify MySQL is running in XAMPP
- Check database credentials in `config.php`
- Ensure the database was created successfully
- Check PHP PDO extension is enabled

### Session Issues

- Verify PHP session configuration in `php.ini`
- Check session save path permissions
- Clear browser cookies and try again
- Verify session timeout settings

### 2FA Not Working

- Ensure your authenticator app's time is synchronized
- Try entering the code again (codes change every 30 seconds)
- Verify the secret key was saved correctly in the database
- Try disabling and re-enabling 2FA

### Account Locked

- Wait for the lockout period to expire (15 minutes by default)
- Contact administrator if lockout persists
- Check `login_attempts` table for failed attempt logs

## Customization

### Styling

All pages use inline CSS with a modern gradient design. To customize:

1. Edit the `<style>` sections in each PHP file
2. Modify colors, fonts, and layout as needed
3. Consider extracting CSS to a separate file for better maintainability

### Password Requirements

Modify `validatePasswordStrength()` in `config.php` to change password requirements.

### Session Timeout

Adjust `SESSION_TIMEOUT` constant in `config.php` to change session duration.

### 2FA Implementation

The current implementation uses a custom TOTP implementation. For enhanced security, consider using a well-tested library like:
- spomky-labs/otphp
- christian-riesen/otpauth

## License

This project is provided as-is for educational and development purposes.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review PHP and MySQL error logs
3. Verify all configuration settings
4. Test with a fresh database installation

## Credits

Built with PHP, MySQL, and modern web security best practices.
