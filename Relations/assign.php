<?php
// DB connection
$host = "localhost";
$user = "root";
$pass = "";
$db   = "task2";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $courseId = $_POST['course_id'];
    $students = $_POST['students'] ?? [];

    if (empty($students)) {
        die("Please select at least one student!");
    }

    // Optional: Remove previous assignments for this course
    $conn->query("DELETE FROM teaching_learning WHERE Course_id = $courseId");

    // Insert selected students
    $stmt = $conn->prepare("INSERT INTO teaching_learning (student_id, Course_id) VALUES (?, ?)");
    if (!$stmt) die("Prepare failed: " . $conn->error);

    foreach ($students as $studentId) {
        $stmt->bind_param("ii", $studentId, $courseId);
        $stmt->execute();
    }

    echo "Students assigned to course successfully!";
}

$conn->close();
