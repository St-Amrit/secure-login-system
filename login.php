<?php
/**
 * Login Page
 * 
 * This page handles user authentication with secure password verification,
 * account lockout protection, and session management.
 */

require_once 'config.php';

$error = '';
$success = '';

startSecureSession();

// Check if user is already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

// Check for session expired message
if (isset($_GET['session']) && $_GET['session'] === 'expired') {
    $error = 'Your session has expired. Please login again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token. Please try again.';
    } else {
        // Get and sanitize input
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']);
        
        // Validate input
        if (empty($username)) {
            $error = 'Username is required.';
        } elseif (empty($password)) {
            $error = 'Password is required.';
        } else {
            try {
                $pdo = getDBConnection();
                
                // Check if account is locked
                if (isAccountLocked($pdo, $username)) {
                    $error = 'Account has been locked due to too many failed login attempts. Please try again later.';
                    logLoginAttempt($pdo, $username, false);
                } else {
                    // Get user from database
                    $stmt = $pdo->prepare("SELECT id, username, email, password_hash, is_active, two_factor_enabled FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    $user = $stmt->fetch();
                    
                    if ($user && $user['is_active'] && password_verify($password, $user['password_hash'])) {
                        // Password is correct
                        resetFailedAttempts($pdo, $username);
                        logLoginAttempt($pdo, $username, true);
                        
                        // Set session variables
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['email'] = $user['email'];
                        $_SESSION['two_factor_enabled'] = $user['two_factor_enabled'];
                        $_SESSION['login_time'] = time();
                        
                        // Handle remember me
                        if ($remember) {
                            $token = bin2hex(random_bytes(32));
                            $expires = date('Y-m-d H:i:s', time() + REMEMBER_ME_TIMEOUT);
                            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
                            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
                            
                            $stmt = $pdo->prepare("INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)");
                            $stmt->execute([$user['id'], $token, $ipAddress, $userAgent, $expires]);
                            
                            setcookie('remember_token', $token, time() + REMEMBER_ME_TIMEOUT, '/', '', false, true);
                        }
                        
                        // Check if 2FA is enabled
                        if ($user['two_factor_enabled']) {
                            header("Location: verify_2fa.php");
                            exit();
                        }
                        
                        header("Location: dashboard.php");
                        exit();
                    } else {
                        // Invalid credentials
                        $error = 'Invalid username or password.';
                        incrementFailedAttempts($pdo, $username);
                        logLoginAttempt($pdo, $username, false);
                    }
                }
            } catch (PDOException $e) {
                error_log("Login error: " . $e->getMessage());
                $error = 'Login failed. Please try again later.';
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Secure Login System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 400px;
            width: 100%;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .subtitle {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .remember-me {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .remember-me input[type="checkbox"] {
            margin-right: 8px;
            cursor: pointer;
        }
        
        .remember-me label {
            margin-bottom: 0;
            cursor: pointer;
            font-weight: normal;
        }
        
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
        }
        
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .register-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome Back</h1>
        <p class="subtitle">Login to your account</p>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <div class="remember-me">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me</label>
            </div>
            
            <button type="submit">Login</button>
        </form>
        
        <div class="register-link">
            Don't have an account? <a href="register.php">Register here</a>
        </div>
    </div>
</body>
</html>
