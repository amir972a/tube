<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= \App\Helpers\Security::escape($title ?? 'VideoCMS') ?></title>
    <!-- Simple Google Font for Persian -->
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>

    <header>
        <div class="container header-inner">
            <a href="/" class="logo">VideoCMS</a>
            <nav>
                <ul>
                    <li><a href="/">خانه</a></li>
                    <?php if (\App\Core\Session::get('user_id')): ?>
                        <?php if (\App\Core\Session::get('role') === 'admin'): ?>
                            <li><a href="/admin">داشبورد مدیر</a></li>
                        <?php endif; ?>
                        <li><a href="/logout">خروج</a></li>
                    <?php else: ?>
                        <li><a href="/login">ورود</a></li>
                        <li><a href="/register">ثبت نام</a></li>
                    <?php endif; ?>
                </ul>
            </nav>
        </div>
    </header>

    <main class="container">
        <?= $content ?>
    </main>

    <footer style="text-align: center; margin-top: 3rem; padding: 2rem 0; border-top: 1px solid var(--border); color: var(--text-secondary);">
        <p>&copy; <?= date('Y') ?> VideoCMS. All rights reserved.</p>
    </footer>

</body>
</html>
