<?php
session_start();

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: index.php');
    exit();
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit();
}
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard | Slider Manager</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .dashboard-container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 20px; 
            overflow: hidden;
            box-shadow: 0 30px 60px rgba(0,0,0,0.3);
        }
        .dashboard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px 35px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dashboard-header h1 { font-size: 28px; font-weight: 700; }
        .stats {
            background: rgba(255,255,255,0.2);
            padding: 8px 20px;
            border-radius: 10px;
        }
        .stats .number { font-size: 24px; font-weight: 700; }
        .stats .label { font-size: 12px; opacity: 0.9; }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
        }
        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        .dashboard-tabs {
            display: flex;
            border-bottom: 2px solid #eee;
            padding: 0 35px;
            background: #fafafa;
        }
        .tab-btn {
            padding: 18px 30px;
            background: none;
            border: none;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            color: #666;
            transition: all 0.3s;
        }
        .tab-btn i { margin-right: 8px; }
        .tab-btn.active { color: #667eea; border-bottom: 3px solid #667eea; }
        .tab-content { display: none; padding: 35px; background: white; }
        .tab-content.active { display: block; }
        .upload-form { max-width: 550px; }
        .form-group { margin-bottom: 25px; }
        .form-group label { font-weight: 600; color: #333; margin-bottom: 8px; display: block; }
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 14px;
        }
        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        .submit-btn, .update-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
        }
        .table-wrapper {
            overflow-x: auto;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
        }
        th, td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #f0f0f0; 
        }
        th { 
            background: #f8f9fa; 
            font-weight: 600; 
            color: #555; 
        }
        tr:hover {
            background: #fafafa;
        }
        .slide-preview { 
            width: 80px; 
            height: 55px; 
            object-fit: cover; 
            border-radius: 8px;
            background: #f0f0f0;
            border: 1px solid #ddd;
        }
        .edit-btn, .delete-btn {
            padding: 6px 14px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            margin: 2px;
            font-size: 12px;
            font-weight: 500;
        }
        .edit-btn { background: #2196F3; color: white; }
        .delete-btn { background: #f44336; color: white; }
        .alert-success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 25px;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: white;
            border-radius: 20px;
            padding: 30px;
            width: 90%;
            max-width: 550px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        .close-modal {
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
        }
        .current-image {
            text-align: center;
            margin-bottom: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
        }
        .current-image img {
            max-width: 100%;
            max-height: 180px;
            border-radius: 10px;
            object-fit: contain;
        }
        .change-image-box {
            border: 2px dashed #ddd;
            padding: 20px;
            border-radius: 12px;
            background: #fafafa;
            margin-top: 15px;
        }
        .image-preview { margin-top: 15px; text-align: center; }
        .image-preview img { max-width: 100%; max-height: 100px; border-radius: 8px; }
        .empty-state { text-align: center; padding: 60px; color: #999; }
        .empty-state i { font-size: 64px; margin-bottom: 20px; opacity: 0.5; }
        @media (max-width: 768px) {
            .dashboard-header { flex-direction: column; gap: 15px; text-align: center; }
            .dashboard-tabs { padding: 0 15px; }
            .tab-btn { padding: 12px 15px; font-size: 13px; }
            th, td { padding: 10px; font-size: 12px; }
            .slide-preview { width: 50px; height: 35px; }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h1><i class="fas fa-crown"></i> Slider Management</h1>
            <div class="stats" id="stats">
                <div class="number" id="slideCount">0</div>
                <div class="label">Total Slides</div>
            </div>
            <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
        
        <div class="dashboard-tabs">
            <button class="tab-btn active" onclick="showTab('view')"><i class="fas fa-images"></i> Manage Slides</button>
            <button class="tab-btn" onclick="showTab('add')"><i class="fas fa-plus-circle"></i> Add New Slide</button>
        </div>
        
        <div id="viewTab" class="tab-content active">
            <div id="message"></div>
            <div class="table-wrapper" id="imagesTable">
                <div class="empty-state"><i class="fas fa-spinner fa-spin"></i><p>Loading slides...</p></div>
            </div>
        </div>
        
        <div id="addTab" class="tab-content">
            <h2 style="margin-bottom: 25px;"><i class="fas fa-cloud-upload-alt"></i> Upload New Slide</h2>
            <form id="uploadForm" class="upload-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label><i class="fas fa-heading"></i> Slide Title *</label>
                    <input type="text" name="title" id="title" placeholder="Enter an eye-catching title" required>
                </div>
                <div class="form-group">
                    <label><i class="fas fa-align-left"></i> Description / Caption</label>
                    <textarea name="caption" id="caption" rows="3" placeholder="Write a brief description..."></textarea>
                </div>
                <div class="form-group">
                    <label><i class="fas fa-sort-numeric-down"></i> Display Order</label>
                    <input type="number" name="order_position" id="order_position" value="0" placeholder="Lower number appears first">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-image"></i> Slide Image *</label>
                    <input type="file" name="image" id="image" accept="image/*" required>
                    <small style="color: #888;">Recommended size: 1920x1080px | JPG, PNG, GIF</small>
                </div>
                <button type="submit" class="submit-btn"><i class="fas fa-upload"></i> Upload Slide</button>
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
                    <img id="current_image_preview" src="" alt="Current Image" onerror="this.src='https://via.placeholder.com/300x150?text=No+Image'">
                </div>
                <div class="form-group">
                    <label>Title *</label>
                    <input type="text" id="edit_title" required placeholder="Slide title">
                </div>
                <div class="form-group">
                    <label>Caption</label>
                    <textarea id="edit_caption" rows="3" placeholder="Slide description"></textarea>
                </div>
                <div class="form-group">
                    <label>Order Position</label>
                    <input type="number" id="edit_order" placeholder="Display order">
                </div>
                <div class="change-image-box">
                    <label><i class="fas fa-sync-alt"></i> Change Image (Optional)</label>
                    <input type="file" id="edit_image" name="image" accept="image/*" style="margin-top: 10px;">
                    <div class="image-preview" id="edit_image_preview"></div>
                </div>
                <div style="display: flex; gap: 12px; margin-top: 25px;">
                    <button type="submit" class="update-btn"><i class="fas fa-save"></i> Save Changes</button>
                    <button type="button" onclick="closeEditModal()" style="background:#999; color:white; padding:12px 25px; border:none; border-radius:10px; cursor:pointer;"><i class="fas fa-times"></i> Cancel</button>
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
                    $('#slideCount').text(data.length);
                    if (data.length === 0) {
                        $('#imagesTable').html('<div class="empty-state"><i class="fas fa-folder-open"></i><p>No slides yet.<br>Click "Add New Slide" to get started!</p></div>');
                        return;
                    }
                    let html = '<table><thead><tr><th>Preview</th><th>Title</th><th>Caption</th><th>Order</th><th>Actions</th></tr></thead><tbody>';
                    data.forEach(slide => {
                        // Fix image path for display
                        let imgPath = slide.image_path;
                        if (imgPath && !imgPath.startsWith('http') && !imgPath.startsWith('/')) {
                            imgPath = '../' + imgPath;
                        }
                        html += `<tr>
                            <td><img src="${imgPath}" class="slide-preview" onerror="this.src='https://via.placeholder.com/80x50?text=No+Image'"></td>
                            <td><strong>${escapeHtml(slide.title)}</strong></td>
                            <td>${escapeHtml(slide.caption || '-')}</td>
                            <td><span style="background:#f0f0f0; padding:4px 10px; border-radius:20px;">${slide.order_position}</span></td>
                            <td>
                                <button class="edit-btn" onclick="openEditModal(${slide.id})"><i class="fas fa-edit"></i> Edit</button>
                                <button class="delete-btn" onclick="deleteSlide(${slide.id})"><i class="fas fa-trash"></i> Delete</button>
                            </td>
                        </tr>`;
                    });
                    html += '</tbody></table>';
                    $('#imagesTable').html(html);
                },
                error: function(xhr, status, error) {
                    $('#imagesTable').html('<div class="empty-state"><i class="fas fa-database"></i><p>Error loading images: ' + error + '</p></div>');
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
                        // Fix image path for modal preview
                        let imgPath = slide.image_path;
                        if (imgPath && !imgPath.startsWith('http') && !imgPath.startsWith('/')) {
                            imgPath = '../' + imgPath;
                        }
                        $('#current_image_preview').attr('src', imgPath);
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
                    $('#edit_image_preview').html(`<img src="${e.target.result}" alt="Preview"><br><small>New image preview</small>`);
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
                    alert('Error saving changes');
                },
                complete: function() {
                    $('.update-btn').html('<i class="fas fa-save"></i> Save Changes').prop('disabled', false);
                }
            });
        });
        
        function deleteSlide(id) {
            if (confirm('⚠️ Delete this slide? This action cannot be undone.')) {
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
            
            const fileInput = $('#image')[0].files[0];
            if (!fileInput) {
                alert('Please select an image file');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'add');
            formData.append('title', $('#title').val());
            formData.append('caption', $('#caption').val());
            formData.append('order_position', $('#order_position').val());
            formData.append('image', fileInput);
            
            $('.submit-btn').html('<i class="fas fa-spinner fa-spin"></i> Uploading...').prop('disabled', true);
            
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
                },
                error: function() {
                    alert('Error uploading image');
                },
                complete: function() {
                    $('.submit-btn').html('<i class="fas fa-upload"></i> Upload Slide').prop('disabled', false);
                }
            });
        });
        
        function showMessage(msg) {
            $('#message').html(`<div class="alert-success"><i class="fas fa-check-circle"></i> ${msg}</div>`);
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
            if ($(e.target).is('#editModal')) closeEditModal();
        });
        
        loadImages();
    </script>
</body>
</html>