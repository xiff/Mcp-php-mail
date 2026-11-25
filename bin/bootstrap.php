<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
umask(0077);
$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

function load_config(): array
{
    $file = dirname(__DIR__) . '/config/config.php';
    if (!is_file($file)) {
        fwrite(STDERR, "config/config.php absent : copiez config/config.example.php.\n");
        exit(1);
    }

    return require $file;
}

function prompt_hidden(string $label): string
{
    fwrite(STDOUT, $label);
    shell_exec('stty -echo 2>/dev/null');
    $v = rtrim((string) fgets(STDIN), "\r\n");
    shell_exec('stty echo 2>/dev/null');
    fwrite(STDOUT, "\n");

    return $v;
}
