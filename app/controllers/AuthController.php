<?php

namespace App\Controllers;

use App\Core\Controller;
use App\Core\Request;
use App\Core\Response;
use App\Core\Session;
use App\Models\User;
use App\Helpers\Security;

class AuthController extends Controller
{
    private User $userModel;

    public function __construct()
    {
        $this->userModel = new User();
    }

    public function showLogin(Request $request, Response $response): void
    {
        if (Session::get('user_id')) {
            $response->redirect('/');
            return;
        }

        $this->render('auth/login', [
            'title' => 'Login - VideoCMS',
            'csrf_token' => Security::generateCsrfToken()
        ]);
    }

    public function login(Request $request, Response $response): void
    {
        $email = $request->input('email');
        $password = $request->input('password');

        if (empty($email) || empty($password)) {
            $this->render('auth/login', [
                'title' => 'Login - VideoCMS',
                'error' => 'Please fill in all fields',
                'csrf_token' => Security::generateCsrfToken()
            ]);
            return;
        }

        $user = $this->userModel->findByEmail($email);

        if ($user && password_verify($password, $user['password'])) {
            Session::set('user_id', $user['id']);
            Session::set('username', $user['username']);
            Session::set('role', $user['role']);

            $response->redirect('/');
        } else {
            $this->render('auth/login', [
                'title' => 'Login - VideoCMS',
                'error' => 'Invalid email or password',
                'csrf_token' => Security::generateCsrfToken()
            ]);
        }
    }

    public function showRegister(Request $request, Response $response): void
    {
        if (Session::get('user_id')) {
            $response->redirect('/');
            return;
        }

        $this->render('auth/register', [
            'title' => 'Register - VideoCMS',
            'csrf_token' => Security::generateCsrfToken()
        ]);
    }

    public function register(Request $request, Response $response): void
    {
        $username = $request->input('username');
        $email = $request->input('email');
        $password = $request->input('password');

        // Basic validation
        if (empty($username) || empty($email) || empty($password)) {
            $this->render('auth/register', [
                'title' => 'Register - VideoCMS',
                'error' => 'All fields are required',
                'csrf_token' => Security::generateCsrfToken()
            ]);
            return;
        }

        // Check if user exists
        if ($this->userModel->findByEmail($email) || $this->userModel->findByUsername($username)) {
            $this->render('auth/register', [
                'title' => 'Register - VideoCMS',
                'error' => 'Username or email already exists',
                'csrf_token' => Security::generateCsrfToken()
            ]);
            return;
        }

        if ($this->userModel->create($username, $email, $password)) {
            // Log them in immediately
            $user = $this->userModel->findByEmail($email);
            Session::set('user_id', $user['id']);
            Session::set('username', $user['username']);
            Session::set('role', $user['role']);

            $response->redirect('/');
        } else {
            $this->render('auth/register', [
                'title' => 'Register - VideoCMS',
                'error' => 'Registration failed, please try again',
                'csrf_token' => Security::generateCsrfToken()
            ]);
        }
    }

    public function logout(Request $request, Response $response): void
    {
        Session::destroy();
        $response->redirect('/login');
    }
}
