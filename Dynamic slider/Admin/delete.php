<?php
session_start();
include 'config.php';

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: index.php');
    exit();
}

if (isset($_GET['id'])) {
    $id = intval($_GET['id']);
    
    $query = "SELECT image_path FROM slider_images WHERE id = $id";
    $result = mysqli_query($conn, $query);
    $row = mysqli_fetch_assoc($result);
    
    if ($row) {
        if (file_exists($row['image_path'])) {
            unlink($row['image_path']);
        }
        
        $delete_query = "DELETE FROM slider_images WHERE id = $id";
        if (mysqli_query($conn, $delete_query)) {
            header('Location: index.php?message=deleted');
            exit();
        }
    }
}

header('Location: index.php');
exit();
?>