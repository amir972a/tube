<?php

require_once __DIR__ . '/../app/core/ErrorHandler.php';

// Initialize error handler based on config
\App\Core\ErrorHandler::init();

// Autoloader
spl_autoload_register(function ($class) {
    $prefix = 'App\\';
    $base_dir = __DIR__ . '/../app/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);

    $parts = explode('\\', $relative_class);
    $className = array_pop($parts);
    $parts = array_map('strtolower', $parts);
    $parts[] = $className;

    $file = $base_dir . implode('/', $parts) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

// Initialize session
\App\Core\Session::init();

$request = new \App\Core\Request();
$response = new \App\Core\Response();
$router = new \App\Core\Router();

// Load routes
require_once __DIR__ . '/../routes/web.php';

// Dispatch
$router->dispatch($request, $response);
