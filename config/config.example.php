<?php

// Copiez ce fichier en config/config.php (chmod 600). Ne le committez JAMAIS.
// Les valeurs marquées « bin/… » sont produites par les scripts CLI.

return [
    // URL publique (sans slash final). La ressource MCP est {base_url}/mcp.
    'base_url' => 'https://mcp.mondomaine.ch',

    // Dossiers privés, frères de public/ (permissions 700).
    'var_dir' => dirname(__DIR__) . '/var',
    'keys_dir' => __DIR__ . '/keys',          // bin/generate-keys.php

    'owner' => [
        'username' => 'owner',
        'password_hash' => '',                // bin/hash-password.php (Argon2id)
        'totp_secret' => '',                  // bin/create-totp.php
    ],

    'oauth' => [
        'encryption_key' => '',               // bin/generate-keys.php (clé defuse)
        // Origines autorisées sur l'endpoint MCP (en-tête Origin, si présent).
        'allowed_origins' => ['https://claude.ai'],
        // Enregistrement dynamique (RFC 7591) : désactivé par défaut.
        'dcr_enabled' => false,
        'dcr_max_clients' => 2,
        // Liste blanche EXACTE des redirect_uri acceptées par le DCR.
        'dcr_redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ],

    'imap' => [
        'host' => 'mail.infomaniak.com',
        'port' => 993,
        'username' => 'moi@mondomaine.ch',
        'password' => '',                     // MOT DE PASSE D'APPLICATION dédié
        'timeout' => 10,
        'drafts_folder' => 'Drafts',
        'from_name' => '',
    ],

    // Architecture prévue pour un futur outil send_draft : NON implémenté en v1.
    // Même à true, rien n'est envoyé tant que l'outil n'existe pas dans le code.
    'send' => [
        'enabled' => false,
        'recipient_allowlist' => [],
    ],
];
