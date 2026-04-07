<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login | Slider Manager</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            position: relative;
            overflow: hidden;
        }
        
        /* Animated Background */
        .circles {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
        }
        
        .circles li {
            position: absolute;
            display: block;
            list-style: none;
            width: 20px;
            height: 20px;
            background: rgba(255, 255, 255, 0.1);
            bottom: -150px;
            animation: float 25s infinite;
        }
        
        @keyframes float {
            0% { transform: translateY(0) rotate(0deg); opacity: 1; border-radius: 0; }
            100% { transform: translateY(-1000px) rotate(720deg); opacity: 0; border-radius: 50%; }
        }
        
        .login-container {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 450px;
            padding: 20px;
        }
        
        .login-card {
            background: white;
            border-radius: 30px;
            padding: 50px 40px;
            box-shadow: 0 30px 60px rgba(0,0,0,0.3);
            animation: slideUp 0.6s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(50px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 35px;
        }
        
        .login-header .icon {
            font-size: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 15px;
        }
        
        .login-header h2 {
            font-size: 28px;
            color: #333;
            font-weight: 700;
        }
        
        .login-header p {
            color: #888;
            font-size: 14px;
            margin-top: 5px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
            font-size: 14px;
        }
        
        .input-group {
            position: relative;
        }
        
        .input-group i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #aaa;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 15px 14px 45px;
            border: 2px solid #e0e0e0;
            border-radius: 12px;
            font-size: 15px;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .login-btn {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102,126,234,0.4);
        }
        
        .error-msg {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 25px;
            text-align: center;
            font-size: 14px;
            border-left: 4px solid #c00;
        }
        
        .demo-info {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .demo-info p {
            color: #888;
            font-size: 13px;
            margin-bottom: 8px;
        }
        
        .demo-info .credentials {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 8px;
            display: inline-block;
        }
        
        .demo-info strong {
            color: #667eea;
        }
        
        @media (max-width: 480px) {
            .login-card { padding: 35px 25px; }
            .login-header h2 { font-size: 24px; }
        }
    </style>
</head>
<body>
    <ul class="circles" id="circles"></ul>
    
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <div class="icon"><i class="fas fa-crown"></i></div>
                <h2>Welcome Back</h2>
                <p>Login to manage your slider</p>
            </div>
            
            <?php
            if (isset($_POST['login'])) {
                $username = $_POST['username'];
                $password = $_POST['password'];
                
                if ($username == 'admin' && $password == 'admin123') {
                    $_SESSION['admin_logged_in'] = true;
                    header('Location: dashboard.php');
                    exit();
                } else {
                    echo '<div class="error-msg"><i class="fas fa-exclamation-triangle"></i> Invalid username or password!</div>';
                }
            }
            ?>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label>Username</label>
                    <div class="input-group">
                        <i class="fas fa-user"></i>
                        <input type="text" name="username" placeholder="Enter username" required autofocus>
                    </div>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <div class="input-group">
                        <i class="fas fa-lock"></i>
                        <input type="password" name="password" placeholder="Enter password" required>
                    </div>
                </div>
                <button type="submit" name="login" class="login-btn">
                    <i class="fas fa-sign-in-alt"></i> Sign In
                </button>
            </form>
            
            <div class="demo-info">
                <p><i class="fas fa-info-circle"></i> Demo Credentials</p>
                <div class="credentials">
                    <strong>Username:</strong> admin &nbsp;|&nbsp; <strong>Password:</strong> admin123
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Animated background circles
        for (let i = 0; i < 50; i++) {
            const circle = document.createElement('li');
            const size = Math.random() * 80 + 20;
            circle.style.width = size + 'px';
            circle.style.height = size + 'px';
            circle.style.left = Math.random() * 100 + '%';
            circle.style.animationDelay = Math.random() * 20 + 's';
            circle.style.animationDuration = Math.random() * 20 + 15 + 's';
            document.getElementById('circles').appendChild(circle);
        }
    </script>
</body>
</html>