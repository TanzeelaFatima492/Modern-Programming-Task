<?php
require_once 'config.php';

// Handle image upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'add') {
        $title = $_POST['title'] ?? '';
        $description = $_POST['description'] ?? '';
        $alt_text = $_POST['alt_text'] ?? '';
        $sort_order = $_POST['sort_order'] ?? 0;
        
        // Handle file upload
        if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {
            $upload_dir = 'uploads/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }
            
            $file_extension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $file_name = uniqid() . '.' . $file_extension;
            $file_path = $upload_dir . $file_name;
            
            if (move_uploaded_file($_FILES['image']['tmp_name'], $file_path)) {
                $sql = "INSERT INTO slider_images (image_path, title, description, alt_text, sort_order) 
                        VALUES (?, ?, ?, ?, ?)";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("ssssi", $file_path, $title, $description, $alt_text, $sort_order);
                $stmt->execute();
                $message = "Image added successfully!";
            }
        }
    } elseif ($_POST['action'] === 'delete') {
        $id = $_POST['id'];
        
        // Get image path before deleting
        $sql = "SELECT image_path FROM slider_images WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        $image = $result->fetch_assoc();
        
        // Delete from database
        $sql = "DELETE FROM slider_images WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $id);
        $stmt->execute();
        
        // Delete file if it's a local file (not URL)
        if ($image && file_exists($image['image_path'])) {
            unlink($image['image_path']);
        }
        
        $message = "Image deleted successfully!";
    } elseif ($_POST['action'] === 'toggle') {
        $id = $_POST['id'];
        $current_status = $_POST['current'];
        $new_status = $current_status == 1 ? 0 : 1;
        
        $sql = "UPDATE slider_images SET is_active = ? WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $new_status, $id);
        $stmt->execute();
        
        $message = "Image status updated!";
    }
}

// Fetch all images
$result = $conn->query("SELECT * FROM slider_images ORDER BY sort_order ASC");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Slider Admin Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1 {
            color: #1a1a1a;
            margin-bottom: 30px;
        }
        
        .admin-section {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        
        input[type="text"],
        textarea,
        input[type="number"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        input[type="file"] {
            padding: 10px 0;
        }
        
        button {
            background: #2a5298;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #1e3c72;
        }
        
        .message {
            background: #4caf50;
            color: white;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #f5f5f5;
            font-weight: 600;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .action-btn {
            padding: 5px 10px;
            margin: 0 2px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .delete-btn {
            background: #dc3545;
            color: white;
        }
        
        .toggle-btn {
            background: #ffc107;
            color: #333;
        }
        
        .active-badge {
            color: #28a745;
            font-weight: bold;
        }
        
        .inactive-badge {
            color: #dc3545;
            font-weight: bold;
        }
        
        .preview-image {
            width: 80px;
            height: 60px;
            object-fit: cover;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Slider Image Management</h1>
        
        <?php if (isset($message)): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <div class="admin-section">
            <h2>Add New Image</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="add">
                
                <div class="form-group">
                    <label for="title">Title:</label>
                    <input type="text" id="title" name="title" required>
                </div>
                
                <div class="form-group">
                    <label for="description">Description:</label>
                    <textarea id="description" name="description" rows="3"></textarea>
                </div>
                
                <div class="form-group">
                    <label for="alt_text">Alt Text:</label>
                    <input type="text" id="alt_text" name="alt_text">
                </div>
                
                <div class="form-group">
                    <label for="sort_order">Sort Order:</label>
                    <input type="number" id="sort_order" name="sort_order" value="0">
                </div>
                
                <div class="form-group">
                    <label for="image">Image:</label>
                    <input type="file" id="image" name="image" accept="image/*" required>
                </div>
                
                <button type="submit">Add Image</button>
            </form>
        </div>
        
        <div class="admin-section">
            <h2>Manage Images</h2>
            <table>
                <thead>
                    <tr>
                        <th>Preview</th>
                        <th>Title</th>
                        <th>Description</th>
                        <th>Sort Order</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $result->fetch_assoc()): ?>
                    <tr>
                        <td>
                            <img src="<?php echo $row['image_path']; ?>" 
                                 alt="<?php echo $row['alt_text']; ?>" 
                                 class="preview-image">
                        </td>
                        <td><?php echo htmlspecialchars($row['title']); ?></td>
                        <td><?php echo htmlspecialchars(substr($row['description'], 0, 50)) . '...'; ?></td>
                        <td><?php echo $row['sort_order']; ?></td>
                        <td>
                            <span class="<?php echo $row['is_active'] ? 'active-badge' : 'inactive-badge'; ?>">
                                <?php echo $row['is_active'] ? 'Active' : 'Inactive'; ?>
                            </span>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="toggle">
                                <input type="hidden" name="id" value="<?php echo $row['id']; ?>">
                                <input type="hidden" name="current" value="<?php echo $row['is_active']; ?>">
                                <button type="submit" class="action-btn toggle-btn">Toggle</button>
                            </form>
                            
                            <form method="POST" style="display: inline;" 
                                  onsubmit="return confirm('Are you sure you want to delete this image?');">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="id" value="<?php echo $row['id']; ?>">
                                <button type="submit" class="action-btn delete-btn">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>