<?php

declare(strict_types=1);

namespace MailMcp;

use PDO;

final class Db
{
    public static function connect(string $file): PDO
    {
        $new = !is_file($file);
        $pdo = new PDO('sqlite:' . $file, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        if ($new) {
            @chmod($file, 0600);
        }
        $pdo->exec('PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;');
        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT,
                redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL, dynamic INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS auth_codes (
                id TEXT PRIMARY KEY, client_id TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS access_tokens (
                id TEXT PRIMARY KEY, client_id TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY, access_token_id TEXT NOT NULL, family TEXT NOT NULL, family_started INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS rt_family ON refresh_tokens(family);
            CREATE TABLE IF NOT EXISTS pending_auth (
                id_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, query TEXT NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS login_attempts (
                k TEXT PRIMARY KEY, fails INTEGER NOT NULL, last_at INTEGER NOT NULL, locked_until INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS rate_limits (
                k TEXT PRIMARY KEY, window INTEGER NOT NULL, hits INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            SQL);

        return $pdo;
    }

    /** Kill switch : révoque tous les codes et jetons. */
    public static function revokeAll(PDO $pdo): void
    {
        $pdo->exec('UPDATE auth_codes SET revoked = 1; UPDATE access_tokens SET revoked = 1;
                    UPDATE refresh_tokens SET revoked = 1; DELETE FROM pending_auth;');
    }
}
