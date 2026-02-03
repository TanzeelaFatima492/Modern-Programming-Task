<?php
require_once 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id']) || !$_SESSION['logged_in']) {
    redirect('login.php');
}

// Get user info
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT username, email, created_at FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Logout functionality
if (isset($_POST['logout'])) {
    // Clear session
    $_SESSION = array();

    // Destroy session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    // Destroy session
    session_destroy();

    redirect('login.php');
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - User System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .navbar {
            background: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .user-info span {
            color: #666;
        }

        .btn-logout {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.3s ease;
        }

        .btn-logout:hover {
            background: #5a6fd8;
        }

        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .welcome-card {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .welcome-card h1 {
            color: #333;
            margin-bottom: 20px;
            font-size: 36px;
        }

        .welcome-card p {
            color: #666;
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 10px;
        }

        .user-details {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 30px;
            margin-top: 30px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 15px 0;
            border-bottom: 1px solid #eee;
        }

        .detail-row:last-child {
            border-bottom: none;
        }

        .detail-label {
            font-weight: 600;
            color: #555;
        }

        .detail-value {
            color: #333;
        }

        @media (max-width: 768px) {
            .navbar {
                padding: 20px;
                flex-direction: column;
                gap: 20px;
            }

            .user-info {
                flex-direction: column;
                gap: 10px;
            }

            .welcome-card {
                padding: 30px 20px;
            }

            .welcome-card h1 {
                font-size: 28px;
            }
        }
    </style>
</head>

<body>
    <nav class="navbar">
        <div class="logo">User System</div>
        <div class="user-info">
            <span>Welcome, <strong><?php echo htmlspecialchars($user['username']); ?></strong></span>
            <form method="POST" action="" style="display: inline;">
                <button type="submit" name="logout" class="btn-logout">Logout</button>
            </form>
        </div>
    </nav>

    <div class="container">
        <div class="welcome-card">
            <h1>🎉 Welcome to Your Dashboard!</h1>
            <p>You have successfully logged into the User System.</p>
            <p>Your account is secure and ready to use.</p>

            <div class="user-details">
                <div class="detail-row">
                    <span class="detail-label">Username:</span>
                    <span class="detail-value"><?php echo htmlspecialchars($user['username']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Email:</span>
                    <span class="detail-value"><?php echo htmlspecialchars($user['email']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Account Created:</span>
                    <span class="detail-value"><?php echo date('F j, Y, g:i a', strtotime($user['created_at'])); ?></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Login Time:</span>
                    <span class="detail-value"><?php echo date('F j, Y, g:i a', $_SESSION['login_time']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Session ID:</span>
                    <span class="detail-value"><?php echo session_id(); ?></span>
                </div>
            </div>
        </div>
    </div>
</body>

</html>