<?php

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;

class CsrfMiddleware
{
    public function handle(Request $request, Response $response): bool
    {
        if (in_array($request->getMethod(), ['POST', 'PUT', 'DELETE'])) {
            $token = $request->input('csrf_token') ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            $sessionToken = Session::get('csrf_token');

            if (empty($token) || empty($sessionToken) || !hash_equals($sessionToken, $token)) {
                $response->setStatusCode(403);
                $response->send('403 Forbidden - Invalid CSRF Token');
                return false;
            }
        }

        return true;
    }
}
