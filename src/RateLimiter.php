<?php

declare(strict_types=1);

namespace MailMcp;

use PDO;

final class RateLimiter
{
    public const MAX_LOGIN_FAILS = 5;
    public const LOCK_SECONDS = 900;

    /** @var callable(): int */
    private $clock;

    public function __construct(private readonly PDO $pdo, ?callable $clock = null)
    {
        $this->clock = $clock ?? time(...);
    }

    /** Fenêtre fixe : true si la requête est autorisée. */
    public function hit(string $key, int $max, int $windowSeconds): bool
    {
        $window = intdiv(($this->clock)(), $windowSeconds);
        $this->pdo->prepare('INSERT INTO rate_limits (k, window, hits) VALUES (?, ?, 1)
            ON CONFLICT(k) DO UPDATE SET hits = CASE WHEN window = excluded.window THEN hits + 1 ELSE 1 END,
            window = excluded.window')->execute([$key, $window]);
        $st = $this->pdo->prepare('SELECT hits FROM rate_limits WHERE k = ?');
        $st->execute([$key]);

        return (int) $st->fetchColumn() <= $max;
    }

    /**
     * Connexion : null si une tentative est permise, sinon le nombre de secondes d'attente.
     * Backoff exponentiel (2^échecs s) puis verrouillage après MAX_LOGIN_FAILS échecs.
     */
    public function loginBlockedFor(string ...$keys): ?int
    {
        $now = ($this->clock)();
        $wait = 0;
        foreach ($keys as $k) {
            $row = $this->row($k);
            if ($row === null) {
                continue;
            }
            $wait = max($wait, $row['locked_until'] - $now, $row['fails'] > 0 ? $row['last_at'] + (2 ** $row['fails']) - $now : 0);
        }

        return $wait > 0 ? $wait : null;
    }

    /** @return list<string> clés nouvellement verrouillées */
    public function loginFailed(string ...$keys): array
    {
        $now = ($this->clock)();
        $locked = [];
        foreach ($keys as $k) {
            $row = $this->row($k);
            // Après expiration d'un verrou, on repart de zéro.
            $fails = ($row === null || ($row['locked_until'] > 0 && $row['locked_until'] <= $now)) ? 1 : $row['fails'] + 1;
            $until = 0;
            if ($fails >= self::MAX_LOGIN_FAILS) {
                $until = $now + self::LOCK_SECONDS;
                $locked[] = $k;
            }
            $this->pdo->prepare('REPLACE INTO login_attempts (k, fails, last_at, locked_until) VALUES (?, ?, ?, ?)')
                ->execute([$k, $fails, $now, $until]);
        }

        return $locked;
    }

    public function loginSucceeded(string ...$keys): void
    {
        foreach ($keys as $k) {
            $this->pdo->prepare('DELETE FROM login_attempts WHERE k = ?')->execute([$k]);
        }
    }

    private function row(string $k): ?array
    {
        $st = $this->pdo->prepare('SELECT fails, last_at, locked_until FROM login_attempts WHERE k = ?');
        $st->execute([$k]);
        $r = $st->fetch();

        return $r === false ? null : array_map('intval', $r);
    }
}
