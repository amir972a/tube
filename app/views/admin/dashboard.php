<div style="margin-top: 2rem;">
    <h2>داشبورد مدیریت</h2>
    <p style="color: var(--text-secondary); margin-top: 0.5rem;">خوش آمدید، <?= \App\Helpers\Security::escape(\App\Core\Session::get('username')) ?></p>
</div>

<div class="dashboard-stats">
    <div class="stat-card">
        <h3><?= $stats['users'] ?></h3>
        <p>کاربران ثبت نام شده</p>
    </div>
    <div class="stat-card">
        <h3><?= $stats['videos'] ?></h3>
        <p>ویدیوهای منتشر شده</p>
    </div>
    <div class="stat-card">
        <h3><?= $stats['pending_videos'] ?></h3>
        <p>ویدیوهای در انتظار تایید</p>
    </div>
    <div class="stat-card">
        <h3><?= $stats['reports'] ?></h3>
        <p>گزارشات تخلف</p>
    </div>
</div>
