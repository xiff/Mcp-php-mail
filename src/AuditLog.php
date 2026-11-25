<?php

declare(strict_types=1);

namespace MailMcp;

/**
 * Journal d'audit JSON-lines avec rotation par taille.
 * Règle : les appelants ne passent JAMAIS de mot de passe, jeton, secret ni contenu de mail.
 * En filet de sécurité, les clés sensibles connues sont masquées.
 */
final class AuditLog
{
    private const MAX_BYTES = 5_000_000;
    private const KEEP = 5;
    private const REDACT = ['password', 'totp', 'code', 'code_verifier', 'client_secret', 'token',
        'refresh_token', 'access_token', 'body_text', 'secret', 'authorization'];

    public function __construct(private readonly string $file)
    {
    }

    public function log(string $event, array $data = []): void
    {
        array_walk_recursive($data, function (&$v, $k) {
            if (is_string($k) && in_array(strtolower($k), self::REDACT, true)) {
                $v = '[redacted]';
            }
        });
        $line = json_encode(['ts' => gmdate('c'), 'event' => $event] + $data,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";

        $this->rotate();
        $new = !is_file($this->file);
        file_put_contents($this->file, $line, FILE_APPEND | LOCK_EX);
        if ($new) {
            @chmod($this->file, 0600);
        }
    }

    private function rotate(): void
    {
        clearstatcache(true, $this->file);
        if (!is_file($this->file) || filesize($this->file) < self::MAX_BYTES) {
            return;
        }
        for ($i = self::KEEP - 1; $i >= 1; $i--) {
            if (is_file("$this->file.$i")) {
                @rename("$this->file.$i", "$this->file." . ($i + 1));
            }
        }
        @rename($this->file, "$this->file.1");
    }
}
