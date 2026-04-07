<?php
session_start();
header('Content-Type: application/json');

// Check if logged in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

include 'config.php';

$action = isset($_POST['action']) ? $_POST['action'] : '';

if ($action === 'add') {
    $title = mysqli_real_escape_string($conn, $_POST['title']);
    $caption = mysqli_real_escape_string($conn, $_POST['caption']);
    $order_position = intval($_POST['order_position']);
    
    if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {
        // Save to root uploads folder (go up one level from Admin folder)
        $target_dir = "../uploads/";
        if (!file_exists($target_dir)) mkdir($target_dir, 0777, true);
        
        $ext = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
        $filename = time() . '_' . uniqid() . '.' . $ext;
        $target_file = $target_dir . $filename;
        
        if (move_uploaded_file($_FILES['image']['tmp_name'], $target_file)) {
            // Store path relative to root (without ../)
            $db_path = 'uploads/' . $filename;
            $query = "INSERT INTO slider_images (image_path, title, caption, order_position, status) 
                      VALUES ('$db_path', '$title', '$caption', $order_position, 1)";
            if (mysqli_query($conn, $query)) {
                echo json_encode(['success' => true, 'message' => 'Image uploaded successfully']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Database error: ' . mysqli_error($conn)]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to upload file']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'No image file selected']);
    }
} 
elseif ($action === 'edit_full') {
    $id = intval($_POST['id']);
    $title = mysqli_real_escape_string($conn, $_POST['title']);
    $caption = mysqli_real_escape_string($conn, $_POST['caption']);
    $order_position = intval($_POST['order_position']);
    
    // Get current image path
    $query = "SELECT image_path FROM slider_images WHERE id=$id";
    $result = mysqli_query($conn, $query);
    $row = mysqli_fetch_assoc($result);
    $current_image = $row['image_path'];
    
    // Check if new image is uploaded
    if (isset($_FILES['new_image']) && $_FILES['new_image']['error'] === 0) {
        // Delete old image file if it exists in root uploads folder
        $old_file_path = "../" . $current_image;
        if ($current_image && file_exists($old_file_path)) {
            unlink($old_file_path);
        }
        
        // Upload new image to root uploads folder
        $target_dir = "../uploads/";
        if (!file_exists($target_dir)) mkdir($target_dir, 0777, true);
        
        $ext = strtolower(pathinfo($_FILES['new_image']['name'], PATHINFO_EXTENSION));
        $filename = time() . '_' . uniqid() . '.' . $ext;
        $target_file = $target_dir . $filename;
        
        if (move_uploaded_file($_FILES['new_image']['tmp_name'], $target_file)) {
            $db_path = 'uploads/' . $filename;
            // Update with new image path
            $query = "UPDATE slider_images SET 
                      image_path='$db_path',
                      title='$title', 
                      caption='$caption', 
                      order_position=$order_position 
                      WHERE id=$id";
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to upload new image']);
            exit();
        }
    } else {
        // Update without changing image
        $query = "UPDATE slider_images SET 
                  title='$title', 
                  caption='$caption', 
                  order_position=$order_position 
                  WHERE id=$id";
    }
    
    if (mysqli_query($conn, $query)) {
        echo json_encode(['success' => true, 'message' => 'Slide updated successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Update failed: ' . mysqli_error($conn)]);
    }
}
elseif ($action === 'delete') {
    $id = intval($_POST['id']);
    $query = "SELECT image_path FROM slider_images WHERE id=$id";
    $result = mysqli_query($conn, $query);
    $row = mysqli_fetch_assoc($result);
    if ($row && $row['image_path']) {
        $file_path = "../" . $row['image_path'];
        if (file_exists($file_path)) {
            unlink($file_path);
        }
    }
    $delete = "DELETE FROM slider_images WHERE id=$id";
    if (mysqli_query($conn, $delete)) {
        echo json_encode(['success' => true, 'message' => 'Deleted successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Delete failed']);
    }
}

mysqli_close($conn);
?>