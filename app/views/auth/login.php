<div class="form-container">
    <h2 style="margin-bottom: 1.5rem; text-align: center;">ورود به حساب کاربری</h2>

    <?php if (isset($error)): ?>
        <div class="alert alert-error">
            <?= \App\Helpers\Security::escape($error) ?>
        </div>
    <?php endif; ?>

    <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="<?= \App\Helpers\Security::escape($csrf_token) ?>">

        <div class="form-group">
            <label for="email">ایمیل</label>
            <input type="email" id="email" name="email" class="form-control" required dir="ltr">
        </div>

        <div class="form-group">
            <label for="password">رمز عبور</label>
            <input type="password" id="password" name="password" class="form-control" required dir="ltr">
        </div>

        <button type="submit" class="btn btn-primary btn-block">ورود</button>
    </form>

    <p style="text-align: center; margin-top: 1.5rem;">
        حساب کاربری ندارید؟ <a href="/register">ثبت نام کنید</a>
    </p>
</div>
