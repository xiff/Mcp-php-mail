#!/usr/bin/env php
<?php
// Hache le mot de passe propriétaire en Argon2id. Le mot de passe n'est jamais affiché ni stocké en clair.
require __DIR__ . '/bootstrap.php';

$a = prompt_hidden('Mot de passe (min. 16 caractères) : ');
if (strlen($a) < 16) {
    fwrite(STDERR, "Trop court.\n");
    exit(1);
}
if (!hash_equals($a, prompt_hidden('Confirmation : '))) {
    fwrite(STDERR, "Les mots de passe diffèrent.\n");
    exit(1);
}
echo "Copiez dans config.php, owner.password_hash :\n";
echo password_hash($a, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]), "\n";
