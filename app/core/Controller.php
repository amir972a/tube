<?php

namespace App\Core;

class Controller
{
    protected function render(string $view, array $data = []): void
    {
        extract($data);

        $viewFile = __DIR__ . "/../views/$view.php";

        if (file_exists($viewFile)) {
            ob_start();
            require $viewFile;
            $content = ob_get_clean();

            require __DIR__ . "/../views/layouts/main.php";
        } else {
            echo "View '$view' not found.";
        }
    }
}
