<?php
/**
 * Secure Database Configuration
 * 
 * This file contains database connection settings and security configurations.
 * Keep this file outside the web root in production environments.
 */

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_login_system');
define('DB_USER', 'root');
define('DB_PASS', '');

// Security configurations
define('BCRYPT_COST', 12); // Higher cost = more secure but slower
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_ATTEMPT_WINDOW', 900); // 15 minutes in seconds
define('SESSION_TIMEOUT', 3600); // 1 hour in seconds
define('REMEMBER_ME_TIMEOUT', 2592000); // 30 days in seconds

// Enable secure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

/**
 * Get database connection using PDO
 * 
 * @return PDO Database connection object
 * @throws PDOException If connection fails
 */
function getDBConnection() {
    try {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => false
        ];
        
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        throw new PDOException("Database connection failed. Please try again later.");
    }
}

/**
 * Start secure session
 */
function startSecureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
        
        // Regenerate session ID to prevent session fixation
        if (!isset($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
        }
        
        // Check session timeout
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
            session_unset();
            session_destroy();
            header("Location: login.php?session=expired");
            exit();
        }
        
        $_SESSION['last_activity'] = time();
    }
}

/**
 * Generate CSRF token
 * 
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 * 
 * @param string $token Token to verify
 * @return bool True if valid, false otherwise
 */
function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Sanitize input data
 * 
 * @param string $data Input data
 * @return string Sanitized data
 */
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

/**
 * Validate email address
 * 
 * @param string $email Email to validate
 * @return bool True if valid, false otherwise
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate password strength
 * 
 * @param string $password Password to validate
 * @return array Validation result with 'valid' boolean and 'message' string
 */
function validatePasswordStrength($password) {
    if (strlen($password) < 8) {
        return ['valid' => false, 'message' => 'Password must be at least 8 characters long'];
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one uppercase letter'];
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one lowercase letter'];
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one number'];
    }
    
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one special character'];
    }
    
    return ['valid' => true, 'message' => 'Password meets security requirements'];
}

/**
 * Log login attempt for security monitoring
 * 
 * @param PDO $pdo Database connection
 * @param string $username Username
 * @param bool $success Whether login was successful
 */
function logLoginAttempt($pdo, $username, $success) {
    try {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt = $pdo->prepare("INSERT INTO login_attempts (username, ip_address, success, user_agent) VALUES (?, ?, ?, ?)");
        $stmt->execute([$username, $ipAddress, $success ? 1 : 0, $userAgent]);
    } catch (PDOException $e) {
        error_log("Failed to log login attempt: " . $e->getMessage());
    }
}

/**
 * Check if account is locked due to too many failed attempts
 * 
 * @param PDO $pdo Database connection
 * @param string $username Username
 * @return bool True if locked, false otherwise
 */
function isAccountLocked($pdo, $username) {
    try {
        $stmt = $pdo->prepare("SELECT account_locked_until, failed_login_attempts FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if (!$user) {
            return false;
        }
        
        if ($user['account_locked_until'] && new DateTime($user['account_locked_until']) > new DateTime()) {
            return true;
        }
        
        // Reset failed attempts if lock period has expired
        if ($user['account_locked_until'] && new DateTime($user['account_locked_until']) <= new DateTime()) {
            $stmt = $pdo->prepare("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE username = ?");
            $stmt->execute([$username]);
        }
        
        return false;
    } catch (PDOException $e) {
        error_log("Failed to check account lock status: " . $e->getMessage());
        return false;
    }
}

/**
 * Increment failed login attempts
 * 
 * @param PDO $pdo Database connection
 * @param string $username Username
 */
function incrementFailedAttempts($pdo, $username) {
    try {
        $stmt = $pdo->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?");
        $stmt->execute([$username]);
        
        // Check if account should be locked
        $stmt = $pdo->prepare("SELECT failed_login_attempts FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && $user['failed_login_attempts'] >= MAX_LOGIN_ATTEMPTS) {
            $lockUntil = date('Y-m-d H:i:s', time() + LOGIN_ATTEMPT_WINDOW);
            $stmt = $pdo->prepare("UPDATE users SET account_locked_until = ? WHERE username = ?");
            $stmt->execute([$lockUntil, $username]);
        }
    } catch (PDOException $e) {
        error_log("Failed to increment failed attempts: " . $e->getMessage());
    }
}

/**
 * Reset failed login attempts on successful login
 * 
 * @param PDO $pdo Database connection
 * @param string $username Username
 */
function resetFailedAttempts($pdo, $username) {
    try {
        $stmt = $pdo->prepare("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = NOW() WHERE username = ?");
        $stmt->execute([$username]);
    } catch (PDOException $e) {
        error_log("Failed to reset failed attempts: " . $e->getMessage());
    }
}
?>
