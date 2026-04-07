<?php
// Database configuration for XAMPP
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'dynamicslider';

// Create connection
$conn = mysqli_connect($host, $username, $password, $database);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

mysqli_set_charset($conn, "utf8");

// Create table if not exists
$create_table = "CREATE TABLE IF NOT EXISTS slider_images (
    id INT AUTO_INCREMENT PRIMARY KEY,
    image_path VARCHAR(500) NOT NULL,
    title VARCHAR(255) DEFAULT '',
    caption TEXT,
    order_position INT DEFAULT 0,
    status TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
mysqli_query($conn, $create_table);

// Insert sample data if table is empty
$check = mysqli_query($conn, "SELECT COUNT(*) as cnt FROM slider_images");
$row = mysqli_fetch_assoc($check);
if ($row['cnt'] == 0) {
    $samples = [
        ['https://picsum.photos/id/1015/1200/500', 'Mountain Adventure', 'Beautiful mountains', 1],
        ['https://picsum.photos/id/104/1200/500', 'Beach Paradise', 'Tropical beaches', 2],
        ['https://picsum.photos/id/106/1200/500', 'Flower Garden', 'Colorful flowers', 3]
    ];
    foreach ($samples as $s) {
        mysqli_query($conn, "INSERT INTO slider_images (image_path, title, caption, order_position, status) VALUES ('$s[0]', '$s[1]', '$s[2]', $s[3], 1)");
    }
}
?>