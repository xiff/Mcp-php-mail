<?php

declare(strict_types=1);

namespace MailMcp\Tests;

use Defuse\Crypto\Key;
use OTPHP\TOTP;

/** Environnement jetable : clés, config, base SQLite dans un dossier temporaire. */
final class TestEnv
{
    public const PASSWORD = 'correct horse battery staple!';
    public const BASE = 'https://mcp.test.example';

    public static function config(): array
    {
        $dir = sys_get_temp_dir() . '/mailmcp-' . bin2hex(random_bytes(6));
        mkdir("$dir/keys", 0700, true);
        mkdir("$dir/var/log", 0700, true);
        static $pair = null;
        if ($pair === null) {
            $k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($k, $priv);
            $pair = [$priv, openssl_pkey_get_details($k)['key']];
        }
        file_put_contents("$dir/keys/private.key", $pair[0]);
        file_put_contents("$dir/keys/public.key", $pair[1]);
        chmod("$dir/keys/private.key", 0600);

        return [
            'base_url' => self::BASE,
            'var_dir' => "$dir/var",
            'keys_dir' => "$dir/keys",
            'owner' => [
                'username' => 'owner',
                'password_hash' => password_hash(self::PASSWORD, PASSWORD_ARGON2ID, ['memory_cost' => 8192, 'time_cost' => 1]),
                'totp_secret' => TOTP::generate()->getSecret(),
            ],
            'oauth' => [
                'encryption_key' => Key::createNewRandomKey()->saveToAsciiSafeString(),
                'allowed_origins' => ['https://claude.ai'],
                'dcr_enabled' => false,
                'dcr_max_clients' => 1,
                'dcr_redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            ],
            'imap' => ['host' => 'x', 'username' => 'moi@example.ch', 'password' => 'imap-app-password-SECRET', 'drafts_folder' => 'Drafts', 'from_name' => 'Moi'],
            'send' => ['enabled' => false, 'recipient_allowlist' => []],
        ];
    }
}
