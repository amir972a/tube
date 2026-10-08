<?php

require_once __DIR__ . '/../app/core/Database.php';

use App\Core\Database;

try {
    $db = Database::getInstance();
    $sql = file_get_contents(__DIR__ . '/schema.sql');

    // Disable foreign key checks before running the schema script to avoid ordering issues with drops
    $db->exec('SET FOREIGN_KEY_CHECKS = 0');
    $db->exec($sql);
    $db->exec('SET FOREIGN_KEY_CHECKS = 1');

    echo "Migration completed successfully.\n";
} catch (\PDOException $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
}
