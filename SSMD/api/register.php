<?php

require "db.php";

$username = $_POST["username"];
$password = $_POST["password"];
$confirm = $_POST["confirm"];

if ($password !== $confirm) {
    die("Passwords do not match.");
}
$check = $conn->prepare("SELECT username FROM users WHERE username = ?");
$check->bind_param("s", $username);
$check->execute();
$check->store_result();

if ($check->num_rows > 0) {
    header("Location: ../account-exists.html");
    exit();
}

$check->close();

$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

$sql = "INSERT INTO users (username, password) VALUES (?, ?)";

$stmt = $conn->prepare($sql);

$stmt->bind_param("ss", $username, $hashedPassword);

if ($stmt->execute()) {
    header("Location: ../registration-success.html");
    exit();
} else {
    echo "Error creating account.";
}

$stmt->close();
$conn->close();

?>