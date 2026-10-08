<?php

return [
    'app' => [
        'name' => 'VideoCMS',
        'url' => 'http://localhost:8000',
        'env' => 'development', // development, production
        'timezone' => 'Asia/Tehran',
        'secret_key' => 'replace_this_with_a_secure_random_key_in_production',
    ],
    'db' => [
        'host' => '127.0.0.1',
        'port' => '3306',
        'database' => 'videocms',
        'username' => 'root',
        'password' => '',
        'charset' => 'utf8mb4',
    ],
    'session' => [
        'name' => 'videocms_session',
        'lifetime' => 86400,
    ]
];
