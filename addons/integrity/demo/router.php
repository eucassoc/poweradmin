<?php
// Router for PHP's built-in server: existing files are served as they are, everything else goes to index.php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = $_SERVER['DOCUMENT_ROOT'] . $path;
if ($path !== '/' && is_file($file) && !preg_match('/\.php$/', $path) && !preg_match('#^/(config|lib|tests|bin|\.)#', $path)) {
    return false;
}
require $_SERVER['DOCUMENT_ROOT'] . '/index.php';
