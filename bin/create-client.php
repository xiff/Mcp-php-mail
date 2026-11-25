#!/usr/bin/env php
<?php
// Crée le client OAuth pré-enregistré (confidentiel) pour claude.ai. Le secret n'est affiché qu'une fois.
require __DIR__ . '/bootstrap.php';

$cfg = load_config();
$redirect = $argv[1] ?? 'https://claude.ai/api/mcp/auth_callback';
if (!preg_match('#^https://[^\s*]+$#', $redirect)) {
    fwrite(STDERR, "redirect_uri invalide (https, sans joker).\n");
    exit(1);
}
$app = new MailMcp\App($cfg);
$c = $app->store->createClient('Claude', [$redirect], true);
echo "Client ID     : {$c['id']}\nClient Secret : {$c['secret']}\nRedirect URI  : $redirect\n";
echo "Saisissez-les dans claude.ai (Paramètres avancés du connecteur). Le secret n'est stocké que haché.\n";
