<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('expose_php', '0');
error_reporting(E_ALL);
umask(0077);

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

if (!is_file($root . '/config/config.php')) {
    http_response_code(503);
    exit;
}
$cfg = require $root . '/config/config.php';
ini_set('error_log', $cfg['var_dir'] . '/log/php-error.log');

$http = new Nyholm\Psr7\Factory\Psr17Factory();
$request = (new Nyholm\Psr7Server\ServerRequestCreator($http, $http, $http, $http))->fromGlobals();
$response = (new MailMcp\App($cfg))->handle($request);

header_remove('X-Powered-By');
http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $v) {
        header("$name: $v", false);
    }
}
$body = $response->getBody();
if ($body->isSeekable()) {
    $body->rewind();
}
while (!$body->eof()) {
    echo $body->read(8192);
    flush();
}
