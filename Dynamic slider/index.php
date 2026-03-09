<?php
require_once 'config.php';

// Fetch active images from database
$sql = "SELECT * FROM slider_images WHERE is_active = 1 ORDER BY sort_order ASC";
$result = $conn->query($sql);

$images = [];
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        $images[] = $row;
    }
}

// If no images in database, use fallback images
if (empty($images)) {
    $images = [
        ['image_path' => 'https://picsum.photos/800/400?random=1', 'title' => 'Default Image 1', 'description' => 'Sample description 1', 'alt_text' => 'Sample 1'],
        ['image_path' => 'https://picsum.photos/800/400?random=2', 'title' => 'Default Image 2', 'description' => 'Sample description 2', 'alt_text' => 'Sample 2'],
        ['image_path' => 'https://picsum.photos/800/400?random=3', 'title' => 'Default Image 3', 'description' => 'Sample description 3', 'alt_text' => 'Sample 3'],
        ['image_path' => 'https://picsum.photos/800/400?random=4', 'title' => 'Default Image 4', 'description' => 'Sample description 4', 'alt_text' => 'Sample 4']
    ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamic Image Slider from Database</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .slider-wrapper {
            width: 1000px;
            max-width: 95%;
            position: relative;
        }

        .slider-container {
            position: relative;
            overflow: hidden;
            border-radius: 20px;
            box-shadow: 0 30px 50px rgba(0,0,0,0.5);
        }

        .slider {
            display: flex;
            transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .slide {
            min-width: 100%;
            position: relative;
        }

        .slide img {
            width: 100%;
            height: 500px;
            object-fit: cover;
            display: block;
        }

        .slide-content {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            padding: 40px;
            background: linear-gradient(transparent, rgba(0,0,0,0.8));
            color: white;
            transform: translateY(100%);
            transition: transform 0.5s ease;
        }

        .slide:hover .slide-content {
            transform: translateY(0);
        }

        .slide-content h2 {
            font-size: 2rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }

        .slide-content p {
            font-size: 1.1rem;
            opacity: 0.9;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }

        .slider-nav {
            position: absolute;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            gap: 12px;
            z-index: 20;
        }

        .nav-dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: rgba(255,255,255,0.4);
            cursor: pointer;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }

        .nav-dot.active {
            background: white;
            transform: scale(1.3);
            border-color: #2a5298;
        }

        .slider-btn {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(5px);
            color: white;
            border: 2px solid rgba(255,255,255,0.3);
            width: 55px;
            height: 55px;
            border-radius: 50%;
            font-size: 28px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            z-index: 20;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }

        .slider-btn:hover {
            background: rgba(255,255,255,0.3);
            border-color: white;
            transform: translateY(-50%) scale(1.1);
        }

        .prev-btn {
            left: 20px;
        }

        .next-btn {
            right: 20px;
        }

        .image-counter {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(5px);
            color: white;
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 14px;
            z-index: 20;
            border: 1px solid rgba(255,255,255,0.2);
        }

        .play-pause {
            position: absolute;
            bottom: 30px;
            right: 30px;
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(5px);
            color: white;
            border: 2px solid rgba(255,255,255,0.3);
            width: 45px;
            height: 45px;
            border-radius: 50%;
            font-size: 20px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            z-index: 20;
        }

        .play-pause:hover {
            background: rgba(255,255,255,0.3);
            transform: scale(1.1);
        }

        @media (max-width: 768px) {
            .slide img {
                height: 350px;
            }
            
            .slide-content {
                padding: 20px;
            }
            
            .slide-content h2 {
                font-size: 1.5rem;
            }
            
            .slider-btn {
                width: 40px;
                height: 40px;
                font-size: 20px;
            }
        }
    </style>
    
    <!-- jQuery CDN -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <div class="slider-wrapper">
        <div class="slider-container">
            <div class="slider">
                <?php foreach ($images as $index => $image): ?>
                    <div class="slide">
                        <img src="<?php echo htmlspecialchars($image['image_path']); ?>" 
                             alt="<?php echo htmlspecialchars($image['alt_text'] ?? 'Slider Image ' . ($index + 1)); ?>">
                        <div class="slide-content">
                            <h2><?php echo htmlspecialchars($image['title'] ?? 'Image ' . ($index + 1)); ?></h2>
                            <p><?php echo htmlspecialchars($image['description'] ?? 'Beautiful image for your viewing pleasure'); ?></p>
                        </div>
                    </div>
                <?php endforeach; ?>
                <!-- Clone first slide for infinite effect -->
                <?php if (!empty($images)): ?>
                    <div class="slide">
                        <img src="<?php echo htmlspecialchars($images[0]['image_path']); ?>" 
                             alt="<?php echo htmlspecialchars($images[0]['alt_text'] ?? 'Slider Image 1'); ?>">
                        <div class="slide-content">
                            <h2><?php echo htmlspecialchars($images[0]['title'] ?? 'Image 1'); ?></h2>
                            <p><?php echo htmlspecialchars($images[0]['description'] ?? 'Beautiful image for your viewing pleasure'); ?></p>
                        </div>
                    </div>
                <?php endif; ?>
            </div>

            <button class="slider-btn prev-btn">&#10094;</button>
            <button class="slider-btn next-btn">&#10095;</button>
            
            <div class="image-counter">
                <span class="current-slide">1</span> / <span class="total-slides"><?php echo count($images); ?></span>
            </div>

            <button class="play-pause">⏸️</button>

            <div class="slider-nav">
                <?php foreach ($images as $index => $image): ?>
                    <span class="nav-dot <?php echo $index === 0 ? 'active' : ''; ?>" data-index="<?php echo $index; ?>"></span>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
        $(document).ready(function() {
            const $slider = $('.slider');
            const $slides = $('.slide');
            const $prevBtn = $('.prev-btn');
            const $nextBtn = $('.next-btn');
            const $navDots = $('.nav-dot');
            const $playPause = $('.play-pause');
            const $currentSlideSpan = $('.current-slide');
            
            const totalOriginalSlides = <?php echo count($images); ?>;
            
            // Exit if no slides
            if (totalOriginalSlides === 0) {
                $('.slider-container').html('<div style="padding: 50px; text-align: center; color: white;">No images found in database</div>');
                return;
            }
            
            let currentIndex = 0;
            let autoSlideInterval;
            let isPlaying = true;
            const autoSlideDelay = 4000; // 4 seconds

            // Set initial position
            $slider.css('transform', 'translateX(0)');

            // Function to update slider position
            function goToSlide(index) {
                $slider.css('transform', `translateX(-${index * 100}%)`);
                
                // Update active dot
                const activeDotIndex = index >= totalOriginalSlides ? 0 : index;
                $navDots.removeClass('active');
                $navDots.eq(activeDotIndex).addClass('active');
                
                // Update counter
                $currentSlideSpan.text(activeDotIndex + 1);
            }

            // Next slide function
            function nextSlide() {
                currentIndex++;
                goToSlide(currentIndex);

                // If we've reached the clone, jump to the first slide instantly
                if (currentIndex === totalOriginalSlides) {
                    setTimeout(function() {
                        $slider.css('transition', 'none');
                        currentIndex = 0;
                        goToSlide(currentIndex);
                        setTimeout(function() {
                            $slider.css('transition', 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)');
                        }, 50);
                    }, 600);
                }
            }

            // Previous slide function
            function prevSlide() {
                if (currentIndex === 0) {
                    // Jump to the clone instantly
                    $slider.css('transition', 'none');
                    currentIndex = totalOriginalSlides;
                    goToSlide(currentIndex);
                    setTimeout(function() {
                        $slider.css('transition', 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1)');
                        currentIndex = totalOriginalSlides - 1;
                        goToSlide(currentIndex);
                    }, 50);
                } else {
                    currentIndex--;
                    goToSlide(currentIndex);
                }
            }

            // Start auto-sliding
            function startAutoSlide() {
                if (isPlaying) {
                    autoSlideInterval = setInterval(nextSlide, autoSlideDelay);
                }
            }

            // Stop auto-sliding
            function stopAutoSlide() {
                clearInterval(autoSlideInterval);
            }

            // Toggle play/pause
            function togglePlayPause() {
                isPlaying = !isPlaying;
                $playPause.text(isPlaying ? '⏸️' : '▶️');
                
                if (isPlaying) {
                    startAutoSlide();
                } else {
                    stopAutoSlide();
                }
            }

            // Event listeners
            $nextBtn.on('click', function() {
                stopAutoSlide();
                nextSlide();
                if (isPlaying) {
                    startAutoSlide();
                }
            });

            $prevBtn.on('click', function() {
                stopAutoSlide();
                prevSlide();
                if (isPlaying) {
                    startAutoSlide();
                }
            });

            // Navigation dots click
            $navDots.on('click', function() {
                const index = $(this).data('index');
                stopAutoSlide();
                currentIndex = index;
                goToSlide(currentIndex);
                if (isPlaying) {
                    startAutoSlide();
                }
            });

            // Play/Pause button
            $playPause.on('click', togglePlayPause);

            // Pause on hover
            $('.slider-container').on('mouseenter', function() {
                if (isPlaying) {
                    stopAutoSlide();
                }
            });
            
            $('.slider-container').on('mouseleave', function() {
                if (isPlaying) {
                    startAutoSlide();
                }
            });

            // Keyboard navigation
            $(document).on('keydown', function(e) {
                if (e.key === 'ArrowLeft') {
                    e.preventDefault();
                    $prevBtn.click();
                } else if (e.key === 'ArrowRight') {
                    e.preventDefault();
                    $nextBtn.click();
                } else if (e.key === ' ') {
                    e.preventDefault();
                    togglePlayPause();
                }
            });

            // Start auto-sliding
            startAutoSlide();

            // Handle window resize
            $(window).on('resize', function() {
                goToSlide(currentIndex);
            });
        });
    </script>
</body>
</html>