<?php

namespace App\Core;

class ErrorHandler
{
    public static function init(): void
    {
        $config = require __DIR__ . '/../../config/config.php';
        $env = $config['app']['env'] ?? 'production';

        if ($env === 'development') {
            ini_set('display_errors', 1);
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        } else {
            ini_set('display_errors', 0);
            ini_set('display_startup_errors', 0);
            error_reporting(0);
        }

        ini_set('log_errors', 1);
        ini_set('error_log', __DIR__ . '/../../storage/logs/error.log');

        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
    }

    public static function handleError(int $level, string $message, string $file, int $line): bool
    {
        if (error_reporting() & $level) {
            throw new \ErrorException($message, 0, $level, $file, $line);
        }
        return false;
    }

    public static function handleException(\Throwable $exception): void
    {
        error_log((string) $exception);

        $config = require __DIR__ . '/../../config/config.php';
        $env = $config['app']['env'] ?? 'production';

        http_response_code(500);

        if ($env === 'development') {
            echo "<h1>Fatal Error</h1>";
            echo "<p><strong>Message:</strong> " . htmlspecialchars($exception->getMessage()) . "</p>";
            echo "<p><strong>File:</strong> " . htmlspecialchars($exception->getFile()) . " on line " . $exception->getLine() . "</p>";
            echo "<h2>Stack Trace:</h2>";
            echo "<pre>" . htmlspecialchars($exception->getTraceAsString()) . "</pre>";
        } else {
            echo "<h1>500 Internal Server Error</h1>";
            echo "<p>An unexpected error occurred. Please try again later.</p>";
        }
        exit;
    }
}
