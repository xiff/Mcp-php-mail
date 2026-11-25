#!/usr/bin/env php
<?php
// KILL SWITCH : révoque immédiatement tous les codes, access tokens et refresh tokens.
// Option --clients : supprime aussi tous les clients OAuth (à recréer avec create-client.php).
require __DIR__ . '/bootstrap.php';

$cfg = load_config();
$app = new MailMcp\App($cfg);
MailMcp\Db::revokeAll($app->pdo);
if (in_array('--clients', $argv, true)) {
    $app->pdo->exec('DELETE FROM clients');
}
$app->log->log('kill_switch', ['clients_deleted' => in_array('--clients', $argv, true)]);
echo "Tous les jetons sont révoqués. Pensez aussi à révoquer le mot de passe d'application chez votre fournisseur mail.\n";
