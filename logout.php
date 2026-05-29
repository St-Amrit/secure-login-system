<?php
/**
 * Logout Page
 * 
 * This page handles user logout with proper session destruction
 * and cookie cleanup.
 */

require_once 'config.php';

startSecureSession();

// Get user info for logging before destroying session
$username = $_SESSION['username'] ?? 'Unknown';

// Destroy remember me cookie if present
if (isset($_COOKIE['remember_token'])) {
    try {
        $pdo = getDBConnection();
        $token = $_COOKIE['remember_token'];
        
        // Delete the session from database
        $stmt = $pdo->prepare("DELETE FROM user_sessions WHERE session_token = ?");
        $stmt->execute([$token]);
        
        // Expire the cookie
        setcookie('remember_token', '', time() - 3600, '/', '', false, true);
    } catch (PDOException $e) {
        error_log("Logout error: " . $e->getMessage());
    }
}

// Unset all session variables
$_SESSION = array();

// Delete the session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/', '', false, true);
}

// Destroy the session
session_destroy();

// Log the logout
error_log("User logged out: " . $username);

// Redirect to login page
header("Location: login.php?logged_out=true");
exit();
