<?php
/**
 * Dashboard Page
 * 
 * This page displays user information and requires authentication.
 * It includes session management and security checks.
 */

require_once 'config.php';

startSecureSession();

// Check if user is authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Check if 2FA verification is needed
if ($_SESSION['two_factor_enabled'] && !isset($_SESSION['2fa_verified'])) {
    header("Location: verify_2fa.php");
    exit();
}

// Get user information
try {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT username, email, created_at, last_login, two_factor_enabled FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    if (!$user) {
        // User not found, destroy session
        session_unset();
        session_destroy();
        header("Location: login.php");
        exit();
    }
} catch (PDOException $e) {
    error_log("Dashboard error: " . $e->getMessage());
    $error = 'Failed to load user data.';
}

// Handle 2FA toggle
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_2fa'])) {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token.';
    } else {
        try {
            if ($user['two_factor_enabled']) {
                // Disable 2FA
                $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $_SESSION['two_factor_enabled'] = false;
                $success = 'Two-factor authentication has been disabled.';
            } else {
                // Redirect to 2FA setup
                header("Location: setup_2fa.php");
                exit();
            }
            
            // Refresh user data
            $stmt = $pdo->prepare("SELECT username, email, created_at, last_login, two_factor_enabled FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
        } catch (PDOException $e) {
            error_log("2FA toggle error: " . $e->getMessage());
            $error = 'Failed to update 2FA settings.';
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
    <title>Dashboard - Secure Login System</title>
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
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            padding: 30px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #333;
        }
        
        .logout-btn {
            padding: 10px 20px;
            background: #c33;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            font-weight: 600;
            transition: background 0.3s;
        }
        
        .logout-btn:hover {
            background: #a33;
        }
        
        .content {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }
        
        .welcome {
            color: #333;
            margin-bottom: 30px;
        }
        
        .info-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .info-card h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            color: #666;
            font-weight: 500;
        }
        
        .info-value {
            color: #333;
            font-weight: 600;
        }
        
        .security-section {
            margin-top: 30px;
        }
        
        .security-section h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .security-status {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        
        .status-enabled {
            color: #3c3;
            font-weight: 600;
        }
        
        .status-disabled {
            color: #c33;
            font-weight: 600;
        }
        
        .toggle-btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.3s;
        }
        
        .toggle-btn:hover {
            background: #5568d3;
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        
        .success {
            background: #efe;
            color: #3c3;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #3c3;
        }
        
        .session-info {
            margin-top: 20px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
            border-left: 4px solid #2196f3;
        }
        
        .session-info p {
            color: #333;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Dashboard</h1>
            <a href="logout.php" class="logout-btn">Logout</a>
        </div>
        
        <div class="content">
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if (isset($success)): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <h1 class="welcome">Welcome, <?php echo htmlspecialchars($user['username']); ?>!</h1>
            
            <div class="info-card">
                <h2>Account Information</h2>
                <div class="info-item">
                    <span class="info-label">Username:</span>
                    <span class="info-value"><?php echo htmlspecialchars($user['username']); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Email:</span>
                    <span class="info-value"><?php echo htmlspecialchars($user['email']); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Account Created:</span>
                    <span class="info-value"><?php echo date('F j, Y', strtotime($user['created_at'])); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Last Login:</span>
                    <span class="info-value"><?php echo $user['last_login'] ? date('F j, Y g:i A', strtotime($user['last_login'])) : 'Never'; ?></span>
                </div>
            </div>
            
            <div class="security-section">
                <h2>Security Settings</h2>
                <div class="security-status">
                    <div>
                        <span>Two-Factor Authentication:</span>
                        <span class="<?php echo $user['two_factor_enabled'] ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo $user['two_factor_enabled'] ? 'Enabled' : 'Disabled'; ?>
                        </span>
                    </div>
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        <input type="hidden" name="toggle_2fa" value="1">
                        <button type="submit" class="toggle-btn">
                            <?php echo $user['two_factor_enabled'] ? 'Disable 2FA' : 'Enable 2FA'; ?>
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="session-info">
                <p><strong>Session Information:</strong></p>
                <p>Session ID: <?php echo session_id(); ?></p>
                <p>Login Time: <?php echo date('Y-m-d H:i:s', $_SESSION['login_time']); ?></p>
                <p>Session Expires: <?php echo date('Y-m-d H:i:s', $_SESSION['login_time'] + SESSION_TIMEOUT); ?></p>
            </div>
        </div>
    </div>
</body>
</html>
