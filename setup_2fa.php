<?php
/**
 * Two-Factor Authentication Setup Page
 * 
 * This page allows users to enable 2FA by generating a TOTP secret
 * and displaying a QR code for scanning with authenticator apps.
 */

require_once 'config.php';

$error = '';
$success = '';
$secret = '';
$qrCodeUrl = '';

startSecureSession();

// Check if user is authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Check if 2FA is already enabled
try {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT two_factor_enabled FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    if ($user['two_factor_enabled']) {
        header("Location: dashboard.php");
        exit();
    }
} catch (PDOException $e) {
    error_log("2FA setup error: " . $e->getMessage());
    $error = 'Failed to check 2FA status.';
}

// Generate TOTP secret
function generateTOTPSecret($length = 32) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $secret;
}

// Generate QR Code URL (using Google Charts API)
function generateQRCodeUrl($secret, $username, $issuer = 'SecureLogin') {
    $otpauth = 'otpauth://totp/' . urlencode($issuer . ':' . $username) . '?secret=' . $secret . '&issuer=' . urlencode($issuer);
    return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpauth);
}

// Verify TOTP code
function verifyTOTP($secret, $code) {
    // Get current time window
    $time = floor(time() / 30);
    
    // Check current and adjacent time windows (for clock drift)
    for ($i = -1; $i <= 1; $i++) {
        $timeCounter = $time + $i;
        $expectedCode = generateTOTPCode($secret, $timeCounter);
        if (hash_equals($expectedCode, $code)) {
            return true;
        }
    }
    return false;
}

// Generate TOTP code for a given time counter
function generateTOTPCode($secret, $timeCounter) {
    // Convert time counter to bytes
    $timeBytes = pack('N*', 0) . pack('N*', $timeCounter);
    
    // Decode base32 secret
    $secretBytes = base32Decode($secret);
    
    // Calculate HMAC-SHA1
    $hmac = hash_hmac('sha1', $timeBytes, $secretBytes, true);
    
    // Dynamic truncation
    $offset = ord($hmac[19]) & 0x0F;
    $code = ((ord($hmac[$offset]) & 0x7F) << 24 |
             (ord($hmac[$offset + 1]) & 0xFF) << 16 |
             (ord($hmac[$offset + 2]) & 0xFF) << 8 |
             (ord($hmac[$offset + 3]) & 0xFF));
    
    // Get 6-digit code
    $code = $code % 1000000;
    return str_pad($code, 6, '0', STR_PAD_LEFT);
}

// Base32 decode
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

// Generate secret on page load
$secret = generateTOTPSecret();
$qrCodeUrl = generateQRCodeUrl($secret, $_SESSION['username']);

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token.';
    } else {
        $verificationCode = $_POST['verification_code'] ?? '';
        $secret = $_POST['secret'] ?? '';
        
        if (empty($verificationCode) || strlen($verificationCode) !== 6) {
            $error = 'Please enter a valid 6-digit verification code.';
        } elseif (!verifyTOTP($secret, $verificationCode)) {
            $error = 'Invalid verification code. Please try again.';
        } else {
            try {
                // Save secret to database and enable 2FA
                $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = ? WHERE id = ?");
                $stmt->execute([$secret, $_SESSION['user_id']]);
                
                $_SESSION['two_factor_enabled'] = true;
                $_SESSION['2fa_verified'] = true;
                
                $success = 'Two-factor authentication has been enabled successfully!';
                
                // Redirect after 2 seconds
                header("refresh:2;url=dashboard.php");
            } catch (PDOException $e) {
                error_log("2FA enable error: " . $e->getMessage());
                $error = 'Failed to enable 2FA. Please try again.';
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
    <title>Setup 2FA - Secure Login System</title>
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
            max-width: 500px;
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
        
        .steps {
            margin-bottom: 30px;
        }
        
        .step {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        
        .step h3 {
            color: #333;
            margin-bottom: 8px;
            font-size: 16px;
        }
        
        .step p {
            color: #666;
            font-size: 14px;
            line-height: 1.5;
        }
        
        .qr-code {
            text-align: center;
            margin: 20px 0;
        }
        
        .qr-code img {
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 10px;
        }
        
        .secret-key {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }
        
        .secret-key p {
            color: #666;
            margin-bottom: 8px;
        }
        
        .secret-key code {
            background: #e0e0e0;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 16px;
            letter-spacing: 2px;
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
        
        .cancel-btn {
            background: #c33;
            margin-top: 10px;
        }
        
        .cancel-btn:hover {
            background: #a33;
            box-shadow: 0 5px 15px rgba(204, 51, 51, 0.4);
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
    </style>
</head>
<body>
    <div class="container">
        <h1>Setup Two-Factor Authentication</h1>
        <p class="subtitle">Add an extra layer of security to your account</p>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <?php if (!$success): ?>
            <div class="steps">
                <div class="step">
                    <h3>Step 1: Install an Authenticator App</h3>
                    <p>Download and install a TOTP-compatible authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your phone.</p>
                </div>
                
                <div class="step">
                    <h3>Step 2: Scan the QR Code</h3>
                    <p>Use your authenticator app to scan the QR code below:</p>
                    <div class="qr-code">
                        <img src="<?php echo htmlspecialchars($qrCodeUrl); ?>" alt="QR Code for 2FA Setup">
                    </div>
                </div>
                
                <div class="step">
                    <h3>Step 3: Enter Verification Code</h3>
                    <p>Enter the 6-digit code from your authenticator app to complete the setup:</p>
                </div>
            </div>
            
            <div class="secret-key">
                <p>Or enter this secret key manually:</p>
                <code><?php echo htmlspecialchars($secret); ?></code>
            </div>
            
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <input type="hidden" name="secret" value="<?php echo htmlspecialchars($secret); ?>">
                
                <div class="form-group">
                    <label for="verification_code">Verification Code</label>
                    <input type="text" id="verification_code" name="verification_code" maxlength="6" pattern="[0-9]{6}" required placeholder="123456" autocomplete="one-time-code">
                </div>
                
                <button type="submit">Enable 2FA</button>
            </form>
            
            <form method="GET" action="dashboard.php">
                <button type="submit" class="cancel-btn">Cancel</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
