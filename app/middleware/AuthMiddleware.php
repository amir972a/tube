<?php

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;

class AuthMiddleware
{
    public function handle(Request $request, Response $response): bool
    {
        if (!Session::get('user_id')) {
            $response->redirect('/login');
            return false;
        }

        return true;
    }
}
