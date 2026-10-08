<?php

namespace App\Controllers;

use App\Core\Controller;
use App\Core\Request;
use App\Core\Response;

class HomeController extends Controller
{
    public function index(Request $request, Response $response): void
    {
        $this->render('home/index', [
            'title' => 'Home - VideoCMS'
        ]);
    }
}
