<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamic Image Slider</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 50px auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            padding: 20px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .admin-link {
            text-align: center;
            margin-top: 20px;
        }
        .admin-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
            padding: 10px 20px;
            background: #f0f0f0;
            border-radius: 8px;
            display: inline-block;
        }
        .slider-container {
            position: relative;
            width: 100%;
            max-width: 1000px;
            margin: 0 auto;
            overflow: hidden;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .slider {
            position: relative;
            width: 100%;
            height: 500px;
            overflow: hidden;
        }
        .slides {
            display: flex;
            width: 100%;
            height: 100%;
            transition: transform 0.5s ease-in-out;
        }
        .slide {
            min-width: 100%;
            height: 100%;
            position: relative;
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }
        .slide-content {
            position: absolute;
            bottom: 50px;
            left: 0;
            right: 0;
            text-align: center;
            color: white;
            background: rgba(0,0,0,0.6);
            padding: 20px;
        }
        .slide-content h2 { font-size: 2em; margin-bottom: 10px; }
        .slide-content p { font-size: 1.2em; }
        .slider-btn {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            background: rgba(0,0,0,0.5);
            color: white;
            border: none;
            padding: 15px 20px;
            cursor: pointer;
            border-radius: 50%;
            z-index: 10;
        }
        .prev-btn { left: 20px; }
        .next-btn { right: 20px; }
        .dots-container {
            text-align: center;
            padding: 20px;
            position: absolute;
            bottom: 20px;
            left: 0;
            right: 0;
            z-index: 10;
        }
        .dot {
            display: inline-block;
            width: 12px;
            height: 12px;
            margin: 0 5px;
            background: rgba(255,255,255,0.5);
            border-radius: 50%;
            cursor: pointer;
        }
        .dot.active { background: white; transform: scale(1.2); }
        .loading {
            text-align: center;
            padding: 50px;
            color: #666;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @media (max-width: 768px) {
            .slider { height: 300px; }
            .slide-content h2 { font-size: 1.2em; }
        }
    </style>
</head>
<body>
    <div class="container">
      
        <div class="slider-container">
            <div class="slider">
                <div class="slides" id="slides">
                    <div class="loading">
                        <div class="spinner"></div>
                        <p>Loading slider images...</p>
                    </div>
                </div>
                <button class="slider-btn prev-btn" id="prevBtn"><i class="fas fa-chevron-left"></i></button>
                <button class="slider-btn next-btn" id="nextBtn"><i class="fas fa-chevron-right"></i></button>
                <div class="dots-container" id="dotsContainer"></div>
            </div>
        </div>
        <div class="admin-link">
            <a href="Admin/index.php"><i class="fas fa-lock"></i> Admin Login</a>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            let currentIndex = 0, slides = [], slideCount = 0, autoPlayInterval, isPlaying = true;
            
            function fetchSliderImages() {
                $.ajax({
                    url: 'Admin/get_slider_images.php',
                    method: 'GET',
                    dataType: 'json',
                    success: function(data) {
                        if (data.length > 0) {
                            slides = data;
                            slideCount = slides.length;
                            renderSlider();
                            startAutoPlay();
                        } else {
                            $('#slides').html('<div class="loading"><p>No images found. <a href="Admin/index.php">Login to add images</a></p></div>');
                        }
                    },
                    error: function() {
                        $('#slides').html('<div class="loading"><p>Error loading images. Please check database connection.</p></div>');
                    }
                });
            }
            
            function renderSlider() {
                let slidesHtml = '', dotsHtml = '';
                slides.forEach((slide, index) => {
                    slidesHtml += `
                        <div class="slide" style="background-image: url('${slide.image_path}');">
                            <div class="slide-content">
                                <h2>${escapeHtml(slide.title || '')}</h2>
                                <p>${escapeHtml(slide.caption || '')}</p>
                            </div>
                        </div>
                    `;
                    dotsHtml += `<div class="dot" data-index="${index}"></div>`;
                });
                $('#slides').html(slidesHtml);
                $('#dotsContainer').html(dotsHtml);
                $('.dot').first().addClass('active');
                updateSliderPosition();
            }
            
            function updateSliderPosition() {
                $('.slides').css('transform', `translateX(${-currentIndex * 100}%)`);
                $('.dot').removeClass('active');
                $(`.dot[data-index="${currentIndex}"]`).addClass('active');
            }
            
            function nextSlide() { currentIndex = (currentIndex + 1) % slideCount; updateSliderPosition(); }
            function prevSlide() { currentIndex = (currentIndex - 1 + slideCount) % slideCount; updateSliderPosition(); }
            
            function startAutoPlay() {
                if (autoPlayInterval) clearInterval(autoPlayInterval);
                autoPlayInterval = setInterval(() => { if (isPlaying) nextSlide(); }, 5000);
            }
            
            $('#nextBtn').click(function() { clearInterval(autoPlayInterval); nextSlide(); startAutoPlay(); });
            $('#prevBtn').click(function() { clearInterval(autoPlayInterval); prevSlide(); startAutoPlay(); });
            $(document).on('click', '.dot', function() {
                clearInterval(autoPlayInterval);
                currentIndex = $(this).data('index');
                updateSliderPosition();
                startAutoPlay();
            });
            $('.slider-container').hover(() => isPlaying = false, () => isPlaying = true);
            
            function escapeHtml(str) {
                if (!str) return '';
                return str.replace(/[&<>]/g, function(m) {
                    if (m === '&') return '&amp;';
                    if (m === '<') return '&lt;';
                    if (m === '>') return '&gt;';
                    return m;
                });
            }
            
            fetchSliderImages();
        });
    </script>
</body>
</html>