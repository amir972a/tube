<?php

namespace App\Helpers;

use App\Core\Session;

class Security
{
    public static function generateCsrfToken(): string
    {
        if (empty(Session::get('csrf_token'))) {
            Session::set('csrf_token', bin2hex(random_bytes(32)));
        }
        return Session::get('csrf_token');
    }

    public static function escape(?string $string): string
    {
        if ($string === null) {
            return '';
        }
        return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
