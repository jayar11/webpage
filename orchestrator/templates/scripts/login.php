<?php
// Database configuration
$servername = "localhost";
$username = "root"; // your database username
$password = ""; // your database password
$dbname = "user_db";

// Create a connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize user input
    $input_username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $input_password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    // Prepare and execute the SQL query
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->bind_param("s", $input_username);
    $stmt->execute();
    $stmt->store_result();

    // Check if username exists
    if ($stmt->num_rows === 1) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify the password
        if (password_verify($input_password, $hashed_password)) {
            echo "Login successful!";
            // Start session and redirect or other actions here
        } else {
            echo "Invalid username or password.";
        }
    } else {
        echo "Invalid username or password.";
    }

    // Close the statement and connection
    $stmt->close();
} else {
    echo "Please submit the form.";
}

$conn->close();
?>
