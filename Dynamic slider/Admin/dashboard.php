<?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Slider Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .dashboard-container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .dashboard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dashboard-header h1 { font-size: 24px; }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
        }
        .dashboard-tabs {
            display: flex;
            border-bottom: 2px solid #eee;
            padding: 0 30px;
            background: #fafafa;
        }
        .tab-btn {
            padding: 15px 25px;
            background: none;
            border: none;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            color: #666;
        }
        .tab-btn.active { color: #667eea; border-bottom: 3px solid #667eea; background: white; }
        .tab-content { display: none; padding: 30px; background: white; }
        .tab-content.active { display: block; }
        .upload-form, .edit-form { max-width: 500px; }
        .upload-form .form-group, .edit-form .form-group { margin-bottom: 20px; }
        .upload-form label, .edit-form label { font-weight: 600; color: #555; margin-bottom: 8px; display: block; }
        .upload-form input, .edit-form input, 
        .upload-form textarea, .edit-form textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .upload-form textarea, .edit-form textarea {
            resize: vertical;
            min-height: 80px;
        }
        .submit-btn, .update-btn {
            background: #4CAF50;
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
        }
        .cancel-btn {
            background: #999;
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin-left: 10px;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
        .slide-preview { 
            width: 80px; 
            height: 50px; 
            object-fit: cover; 
            border-radius: 5px;
            background: #f0f0f0;
        }
        .edit-btn, .delete-btn {
            padding: 5px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin: 2px;
        }
        .edit-btn { background: #2196F3; color: white; }
        .delete-btn { background: #f44336; color: white; }
        .success-msg { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background-color: white;
            border-radius: 15px;
            padding: 30px;
            width: 90%;
            max-width: 550px;
            max-height: 90vh;
            overflow-y: auto;
            animation: slideDown 0.3s ease;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .modal-header h3 {
            color: #333;
            font-size: 22px;
        }
        .close-modal {
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
        }
        .close-modal:hover {
            color: #333;
        }
        .current-image {
            text-align: center;
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .current-image img {
            max-width: 100%;
            max-height: 150px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .change-image-box {
            border: 2px dashed #ddd;
            padding: 15px;
            border-radius: 8px;
            background: #fafafa;
            margin-top: 10px;
        }
        .change-image-box label {
            cursor: pointer;
            color: #2196F3;
            font-weight: bold;
        }
        .image-preview {
            margin-top: 10px;
            text-align: center;
        }
        .image-preview img {
            max-width: 100%;
            max-height: 100px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .info-text {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        @keyframes slideDown {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h1><i class="fas fa-image"></i> Slider Management Dashboard</h1>
            <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
        
        <div class="dashboard-tabs">
            <button class="tab-btn active" onclick="showTab('view')">📋 View & Manage</button>
            <button class="tab-btn" onclick="showTab('add')">➕ Add New Image</button>
        </div>
        
        <div id="viewTab" class="tab-content active">
            <div id="message"></div>
            <div id="imagesTable">Loading...</div>
        </div>
        
        <div id="addTab" class="tab-content">
            <h3>Upload New Slide</h3>
            <form id="uploadForm" class="upload-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Title *</label>
                    <input type="text" name="title" id="title" required>
                </div>
                <div class="form-group">
                    <label>Caption</label>
                    <textarea name="caption" id="caption" rows="3"></textarea>
                </div>
                <div class="form-group">
                    <label>Order Position</label>
                    <input type="number" name="order_position" id="order_position" value="0">
                </div>
                <div class="form-group">
                    <label>Image *</label>
                    <input type="file" name="image" id="image" accept="image/*" required>
                </div>
                <button type="submit" class="submit-btn"><i class="fas fa-upload"></i> Upload</button>
            </form>
        </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-edit"></i> Edit Slide</h3>
                <span class="close-modal" onclick="closeEditModal()">&times;</span>
            </div>
            <form id="editForm" enctype="multipart/form-data">
                <input type="hidden" id="edit_id">
                <div class="current-image">
                    <label>Current Image:</label><br>
                    <img id="current_image_preview" src="" alt="Current Image" onerror="this.src='https://via.placeholder.com/150x100?text=No+Image'">
                    <br><small>Current image in slider</small>
                </div>
                <div class="form-group">
                    <label>Title *</label>
                    <input type="text" id="edit_title" required placeholder="Enter slide title">
                </div>
                <div class="form-group">
                    <label>Caption</label>
                    <textarea id="edit_caption" rows="3" placeholder="Enter slide description"></textarea>
                </div>
                <div class="form-group">
                    <label>Order Position</label>
                    <input type="number" id="edit_order" placeholder="Order position (lower = earlier)">
                    <small style="color: #666;">Images will be displayed in ascending order</small>
                </div>
                
                <div class="change-image-box">
                    <label><i class="fas fa-image"></i> Change Image (Optional)</label>
                    <input type="file" id="edit_image" name="image" accept="image/jpeg,image/png,image/jpg,image/gif">
                    <div class="info-text">Leave empty to keep current image. Max size: 5MB</div>
                    <div class="image-preview" id="edit_image_preview"></div>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button type="submit" class="update-btn"><i class="fas fa-save"></i> Save Changes</button>
                    <button type="button" class="cancel-btn" onclick="closeEditModal()"><i class="fas fa-times"></i> Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        function showTab(tab) {
            $('.tab-btn').removeClass('active');
            $('.tab-content').removeClass('active');
            if (tab === 'view') {
                $('.tab-btn').first().addClass('active');
                $('#viewTab').addClass('active');
                loadImages();
            } else {
                $('.tab-btn').last().addClass('active');
                $('#addTab').addClass('active');
            }
        }
        
        function loadImages() {
            $.ajax({
                url: 'get_slider_images.php',
                type: 'GET',
                dataType: 'json',
                success: function(data) {
                    if (data.length === 0) {
                        $('#imagesTable').html('<p style="text-align:center;padding:40px;">No images found. Click "Add New Image" to upload.</p>');
                        return;
                    }
                    let html = '<table><thead><tr><th>Preview</th><th>Title</th><th>Caption</th><th>Order</th><th>Actions</th></tr></thead><tbody>';
                    data.forEach(slide => {
                        let imageUrl = slide.image_path;
                        html += `<tr>
                            <td><img src="${imageUrl}" class="slide-preview" onerror="this.src='https://via.placeholder.com/80x50?text=No+Image'"></strong></td>
                            <td><strong>${escapeHtml(slide.title)}</strong></td>
                            <td>${escapeHtml(slide.caption || '')}</td>
                            <td>${slide.order_position}</td>
                            <td>
                                <button class="edit-btn" onclick="openEditModal(${slide.id})"><i class="fas fa-edit"></i> Edit</button>
                                <button class="delete-btn" onclick="deleteSlide(${slide.id})"><i class="fas fa-trash"></i> Delete</button>
                            </td>
                        <tr>`;
                    });
                    html += '</tbody></table>';
                    $('#imagesTable').html(html);
                },
                error: function(xhr, status, error) {
                    $('#imagesTable').html('<p style="text-align:center;padding:40px;color:#c00;">Error loading images: ' + error + '</p>');
                }
            });
        }
        
        function openEditModal(id) {
            $.ajax({
                url: 'get_slider_images.php',
                type: 'GET',
                dataType: 'json',
                success: function(data) {
                    const slide = data.find(s => s.id == id);
                    if (slide) {
                        $('#edit_id').val(slide.id);
                        $('#edit_title').val(slide.title);
                        $('#edit_caption').val(slide.caption || '');
                        $('#edit_order').val(slide.order_position);
                        $('#current_image_preview').attr('src', slide.image_path);
                        $('#edit_image_preview').html('');
                        $('#edit_image').val('');
                        $('#editModal').css('display', 'flex');
                    }
                }
            });
        }
        
        $('#edit_image').on('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    $('#edit_image_preview').html(`<img src="${e.target.result}" alt="New Image Preview"><br><small>New image (will replace current)</small>`);
                }
                reader.readAsDataURL(file);
            } else {
                $('#edit_image_preview').html('');
            }
        });
        
        function closeEditModal() {
            $('#editModal').css('display', 'none');
            $('#editForm')[0].reset();
            $('#edit_image_preview').html('');
        }
        
        $('#editForm').on('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            formData.append('action', 'edit_full');
            formData.append('id', $('#edit_id').val());
            formData.append('title', $('#edit_title').val());
            formData.append('caption', $('#edit_caption').val());
            formData.append('order_position', $('#edit_order').val());
            
            const newImage = $('#edit_image')[0].files[0];
            if (newImage) {
                formData.append('new_image', newImage);
            }
            
            $('.update-btn').html('<i class="fas fa-spinner fa-spin"></i> Saving...').prop('disabled', true);
            
            $.ajax({
                url: 'admin_ajax.php',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                dataType: 'json',
                success: function(res) {
                    if (res.success) {
                        showMessage(res.message);
                        closeEditModal();
                        loadImages();
                    } else {
                        alert(res.message);
                    }
                },
                error: function() {
                    alert('Error saving changes. Please try again.');
                },
                complete: function() {
                    $('.update-btn').html('<i class="fas fa-save"></i> Save Changes').prop('disabled', false);
                }
            });
        });
        
        function deleteSlide(id) {
            if (confirm('Are you sure you want to delete this slide? This action cannot be undone.')) {
                $.ajax({
                    url: 'admin_ajax.php',
                    type: 'POST',
                    data: { action: 'delete', id: id },
                    dataType: 'json',
                    success: function(res) {
                        if (res.success) {
                            showMessage(res.message);
                            loadImages();
                        } else {
                            alert(res.message);
                        }
                    }
                });
            }
        }
        
        $('#uploadForm').on('submit', function(e) {
            e.preventDefault();
            const formData = new FormData();
            formData.append('action', 'add');
            formData.append('title', $('#title').val());
            formData.append('caption', $('#caption').val());
            formData.append('order_position', $('#order_position').val());
            formData.append('image', $('#image')[0].files[0]);
            
            $.ajax({
                url: 'admin_ajax.php',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                dataType: 'json',
                success: function(res) {
                    if (res.success) {
                        showMessage(res.message);
                        $('#uploadForm')[0].reset();
                        loadImages();
                        showTab('view');
                    } else {
                        alert(res.message);
                    }
                }
            });
        });
        
        function showMessage(msg) {
            $('#message').html(`<div class="success-msg"><i class="fas fa-check-circle"></i> ${msg}</div>`);
            setTimeout(() => $('#message').html(''), 3000);
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }
        
        $(window).on('click', function(e) {
            if ($(e.target).is('#editModal')) {
                closeEditModal();
            }
        });
        
        loadImages();
    </script>
</body>
</html>