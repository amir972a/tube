<?php

namespace App\Controllers;

use App\Core\Controller;
use App\Core\Request;
use App\Core\Response;

class AdminController extends Controller
{
    public function dashboard(Request $request, Response $response): void
    {
        // Statistics placeholders for Phase 1
        $stats = [
            'users' => 0,
            'videos' => 0,
            'pending_videos' => 0,
            'reports' => 0,
            'categories' => 0
        ];

        $this->render('admin/dashboard', [
            'title' => 'Admin Dashboard - VideoCMS',
            'stats' => $stats
        ]);
    }
}
