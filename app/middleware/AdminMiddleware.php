<?php

namespace App\Middleware;

use App\Core\Request;
use App\Core\Response;
use App\Core\Session;

class AdminMiddleware
{
    public function handle(Request $request, Response $response): bool
    {
        if (Session::get('role') !== 'admin') {
            $response->setStatusCode(403);
            $response->send('403 Forbidden');
            return false;
        }

        return true;
    }
}
