#!/usr/bin/env php
<?php
// Crée le secret TOTP (RFC 6238, SHA1/6 chiffres/30 s, compatible toutes applis).
require __DIR__ . '/bootstrap.php';

$cfg = load_config();
$totp = OTPHP\TOTP::generate();
$totp->setLabel($cfg['owner']['username']);
$totp->setIssuer((string) parse_url($cfg['base_url'], PHP_URL_HOST));

echo "Copiez dans config.php, owner.totp_secret :\n", $totp->getSecret(), "\n\n";
echo "URI à importer dans l'application TOTP (ou à transformer en QR code localement,\n";
echo "ex. : qrencode -t ansiutf8 '<uri>') :\n", $totp->getProvisioningUri(), "\n\n";
echo "Effacez ensuite l'historique du terminal (history -c).\n";
