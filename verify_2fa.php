<?php
/**
 * Two-Factor Authentication Verification Page
 * 
 * This page handles 2FA code verification during login.
 */

require_once 'config.php';

$error = '';

startSecureSession();

// Check if user is authenticated and 2FA is enabled
if (!isset($_SESSION['user_id']) || !$_SESSION['two_factor_enabled']) {
    header("Location: login.php");
    exit();
}

// Check if already verified
if (isset($_SESSION['2fa_verified'])) {
    header("Location: dashboard.php");
    exit();
}

// Get user's 2FA secret
try {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT two_factor_secret FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    if (!$user || !$user['two_factor_secret']) {
        // Secret not found, redirect to setup
        header("Location: setup_2fa.php");
        exit();
    }
    
    $secret = $user['two_factor_secret'];
} catch (PDOException $e) {
    error_log("2FA verification error: " . $e->getMessage());
    $error = 'Failed to verify 2FA. Please try again.';
}

// TOTP verification functions (same as in setup_2fa.php)
function verifyTOTP($secret, $code) {
    $time = floor(time() / 30);
    
    for ($i = -1; $i <= 1; $i++) {
        $timeCounter = $time + $i;
        $expectedCode = generateTOTPCode($secret, $timeCounter);
        if (hash_equals($expectedCode, $code)) {
            return true;
        }
    }
    return false;
}

function generateTOTPCode($secret, $timeCounter) {
    $timeBytes = pack('N*', 0) . pack('N*', $timeCounter);
    $secretBytes = base32Decode($secret);
    $hmac = hash_hmac('sha1', $timeBytes, $secretBytes, true);
    $offset = ord($hmac[19]) & 0x0F;
    $code = ((ord($hmac[$offset]) & 0x7F) << 24 |
             (ord($hmac[$offset + 1]) & 0xFF) << 16 |
             (ord($hmac[$offset + 2]) & 0xFF) << 8 |
             (ord($hmac[$offset + 3]) & 0xFF));
    $code = $code % 1000000;
    return str_pad($code, 6, '0', STR_PAD_LEFT);
}

function base32Decode($secret) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    $secret = strtoupper($secret);
    
    for ($i = 0; $i < strlen($secret); $i++) {
        $char = $secret[$i];
        if (($pos = strpos($alphabet, $char)) !== false) {
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
    }
    
    $bytes = '';
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $bytes .= chr(bindec(substr($bits, $i, 8)));
    }
    
    return $bytes;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token.';
    } else {
        $verificationCode = $_POST['verification_code'] ?? '';
        
        if (empty($verificationCode) || strlen($verificationCode) !== 6) {
            $error = 'Please enter a valid 6-digit verification code.';
        } elseif (!verifyTOTP($secret, $verificationCode)) {
            $error = 'Invalid verification code. Please try again.';
        } else {
            // Verification successful
            $_SESSION['2fa_verified'] = true;
            header("Location: dashboard.php");
            exit();
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
    <title>Verify 2FA - Secure Login System</title>
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
        
        .icon {
            text-align: center;
            font-size: 60px;
            margin-bottom: 20px;
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
        
        input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            text-align: center;
            letter-spacing: 4px;
            font-size: 18px;
        }
        
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
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
        
        .info {
            background: #e3f2fd;
            color: #1976d2;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #1976d2;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>Two-Factor Authentication</h1>
        <p class="subtitle">Enter the code from your authenticator app</p>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <div class="info">
            Open your authenticator app and enter the 6-digit code to complete login.
        </div>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
            
            <div class="form-group">
                <label for="verification_code">Verification Code</label>
                <input type="text" id="verification_code" name="verification_code" maxlength="6" pattern="[0-9]{6}" required placeholder="123456" autocomplete="one-time-code" autofocus>
            </div>
            
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>
