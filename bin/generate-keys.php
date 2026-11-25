#!/usr/bin/env php
<?php
// Génère la paire RSA (jetons JWT RS256) et la clé de chiffrement (codes/refresh tokens).
require __DIR__ . '/bootstrap.php';

$cfg = load_config();
$dir = $cfg['keys_dir'];
if (!is_dir($dir)) {
    mkdir($dir, 0700, true);
}
if (is_file("$dir/private.key") && !in_array('--force', $argv, true)) {
    fwrite(STDERR, "Des clés existent déjà. --force pour les remplacer (invalide tous les jetons).\n");
    exit(1);
}
$key = openssl_pkey_new(['private_key_bits' => 3072, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($key, $private);
file_put_contents("$dir/private.key", $private);
file_put_contents("$dir/public.key", openssl_pkey_get_details($key)['key']);
chmod("$dir/private.key", 0600);
chmod("$dir/public.key", 0600);

echo "Clés RSA écrites dans $dir (600).\n";
echo "Ajoutez dans config.php, oauth.encryption_key :\n";
echo Defuse\Crypto\Key::createNewRandomKey()->saveToAsciiSafeString(), "\n";
