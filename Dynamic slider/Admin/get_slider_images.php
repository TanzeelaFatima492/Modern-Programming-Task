<?php
header('Content-Type: application/json');
include 'config.php';

$query = "SELECT id, image_path, title, caption, order_position 
          FROM slider_images 
          WHERE status = 1 
          ORDER BY order_position ASC";

$result = mysqli_query($conn, $query);
$images = [];

while ($row = mysqli_fetch_assoc($result)) {
    $image_path = $row['image_path'];
    
    // Path is already stored as 'uploads/filename.jpg'
    // Frontend can access it directly from root
    if (!empty($image_path) && strpos($image_path, 'http') !== 0) {
        // Make sure path starts with uploads/
        if (strpos($image_path, 'uploads/') !== 0) {
            $image_path = 'uploads/' . $image_path;
        }
    }
    
    $images[] = [
        'id' => $row['id'],
        'image_path' => $image_path,
        'title' => $row['title'],
        'caption' => $row['caption'],
        'order_position' => $row['order_position']
    ];
}

echo json_encode($images);
mysqli_close($conn);
?>