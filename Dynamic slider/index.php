<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Luxury Slider | Dynamic Image Slider</title>
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
            overflow-x: hidden;
        }

        /* Animated Background */
        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }

        .bg-animation div {
            position: absolute;
            display: block;
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

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Header Section */
        .header-section {
            text-align: center;
            margin-bottom: 40px;
            animation: fadeInDown 0.8s ease;
        }

        .header-section h1 {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #f0f0f0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 10px;
        }

        .header-section p {
            color: rgba(255,255,255,0.9);
            font-size: 1.1rem;
            font-weight: 300;
        }

        /* Slider Container */
        .slider-wrapper {
            position: relative;
            max-width: 1200px;
            margin: 0 auto;
            border-radius: 20px;
            box-shadow: 0 30px 60px rgba(0,0,0,0.3);
            background: rgba(0,0,0,0.2);
            padding: 10px;
        }

        .slider-container {
            position: relative;
            width: 100%;
            overflow: hidden;
            border-radius: 15px;
            background: #000;
        }

        .slider {
            position: relative;
            width: 100%;
            height: 550px;
            overflow: hidden;
        }

        .slides {
            display: flex;
            width: 100%;
            height: 100%;
            transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .slide {
            min-width: 100%;
            height: 100%;
            position: relative;
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            transform: scale(1);
            transition: transform 0.3s ease;
        }

        .slide::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(0,0,0,0.4) 0%, rgba(0,0,0,0.2) 100%);
        }

        .slide-content {
            position: absolute;
            bottom: 80px;
            left: 0;
            right: 0;
            text-align: center;
            color: white;
            padding: 30px;
            animation: fadeInUp 0.8s ease;
            z-index: 2;
        }

        .slide-content h2 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 15px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            letter-spacing: -0.5px;
        }

        .slide-content p {
            font-size: 1.2rem;
            font-weight: 400;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            opacity: 0.95;
            max-width: 600px;
            margin: 0 auto;
        }

        /* Navigation Buttons */
        .slider-btn {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(10px);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 18px 22px;
            cursor: pointer;
            font-size: 20px;
            transition: all 0.3s ease;
            z-index: 10;
            border-radius: 50%;
            opacity: 0.7;
        }

        .slider-btn:hover {
            background: rgba(255,255,255,0.4);
            transform: translateY(-50%) scale(1.1);
            opacity: 1;
        }

        .prev-btn { left: 30px; }
        .next-btn { right: 30px; }

        /* Dots Navigation */
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
            margin: 0 6px;
            background: rgba(255,255,255,0.4);
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }

        .dot::after {
            content: '';
            position: absolute;
            top: -4px;
            left: -4px;
            right: -4px;
            bottom: -4px;
            border-radius: 50%;
            border: 1px solid rgba(255,255,255,0.3);
            opacity: 0;
            transition: all 0.3s ease;
        }

        .dot.active {
            background: white;
            transform: scale(1.3);
        }

        .dot.active::after {
            opacity: 1;
        }

        .dot:hover {
            background: white;
            transform: scale(1.1);
        }

        /* Admin Button */
        .admin-link {
            text-align: center;
            margin-top: 40px;
        }

        .admin-btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            color: white;
            text-decoration: none;
            padding: 12px 28px;
            border-radius: 50px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid rgba(255,255,255,0.3);
        }

        .admin-btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }

        /* Loading Animation */
        .loading {
            text-align: center;
            padding: 50px;
            color: white;
        }

        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255,255,255,0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        /* Progress Bar */
        .progress-bar {
            position: absolute;
            bottom: 0;
            left: 0;
            height: 3px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.1s linear;
            z-index: 20;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header-section h1 { font-size: 2rem; }
            .slider { height: 400px; }
            .slide-content { bottom: 40px; padding: 20px; }
            .slide-content h2 { font-size: 1.5rem; }
            .slide-content p { font-size: 0.9rem; }
            .slider-btn { padding: 12px 15px; font-size: 16px; }
            .prev-btn { left: 15px; }
            .next-btn { right: 15px; }
        }
    </style>
</head>
<body>
    <div class="bg-animation" id="bgAnimation"></div>

    <div class="container">
        <div class="header-section">
            <h1><i class="fas fa-images"></i> Dynamic Image Slider</h1>
            <p>Experience stunning visuals with our premium slider</p>
        </div>

        <div class="slider-wrapper">
            <div class="slider-container">
                <div class="slider">
                    <div class="slides" id="slides">
                        <div class="loading">
                            <div class="spinner"></div>
                            <p>Loading stunning images...</p>
                        </div>
                    </div>
                    
                    <button class="slider-btn prev-btn" id="prevBtn">
                        <i class="fas fa-chevron-left"></i>
                    </button>
                    <button class="slider-btn next-btn" id="nextBtn">
                        <i class="fas fa-chevron-right"></i>
                    </button>
                    
                    <div class="dots-container" id="dotsContainer"></div>
                    <div class="progress-bar" id="progressBar"></div>
                </div>
            </div>
        </div>

        <div class="admin-link">
            <a href="Admin/login.php" class="admin-btn">
                <i class="fas fa-crown"></i> Admin Dashboard
                <i class="fas fa-arrow-right"></i>
            </a>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            let currentIndex = 0, slides = [], slideCount = 0, autoPlayInterval, isPlaying = true;
            let progressInterval;
            
            // Animated background
            function createBubbles() {
                const bgAnimation = $('#bgAnimation');
                for (let i = 0; i < 50; i++) {
                    const bubble = $('<div></div>');
                    const size = Math.random() * 60 + 10;
                    bubble.css({
                        width: size + 'px',
                        height: size + 'px',
                        left: Math.random() * 100 + '%',
                        animationDelay: Math.random() * 20 + 's',
                        animationDuration: Math.random() * 20 + 15 + 's'
                    });
                    bgAnimation.append(bubble);
                }
            }
            createBubbles();
            
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
                            $('#slides').html('<div class="loading"><i class="fas fa-image fa-3x"></i><p>No images found. <a href="Admin/login.php" style="color:white;">Login to add images</a></p></div>');
                        }
                    },
                    error: function() {
                        $('#slides').html('<div class="loading"><i class="fas fa-database fa-3x"></i><p>Error loading images. Please check database connection.</p></div>');
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
                resetProgressBar();
            }
            
            function resetProgressBar() {
                if (progressInterval) clearInterval(progressInterval);
                $('#progressBar').css('width', '0%');
                let width = 0;
                progressInterval = setInterval(() => {
                    if (isPlaying) {
                        width += 0.5;
                        $('#progressBar').css('width', width + '%');
                        if (width >= 100) {
                            clearInterval(progressInterval);
                        }
                    }
                }, 25);
            }
            
            function nextSlide() { currentIndex = (currentIndex + 1) % slideCount; updateSliderPosition(); }
            function prevSlide() { currentIndex = (currentIndex - 1 + slideCount) % slideCount; updateSliderPosition(); }
            
            function startAutoPlay() {
                if (autoPlayInterval) clearInterval(autoPlayInterval);
                autoPlayInterval = setInterval(() => { if (isPlaying) nextSlide(); }, 5000);
                resetProgressBar();
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