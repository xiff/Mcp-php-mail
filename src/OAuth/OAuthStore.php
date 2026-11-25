<?php

declare(strict_types=1);

namespace MailMcp\OAuth;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MailMcp\AuditLog;
use PDO;

/**
 * Stockage SQLite de tous les objets OAuth. Une instance = une requête HTTP.
 */
final class OAuthStore implements ClientRepositoryInterface, AccessTokenRepositoryInterface, ScopeRepositoryInterface,
    AuthCodeRepositoryInterface, RefreshTokenRepositoryInterface
{
    public const REFRESH_FAMILY_MAX_SECONDS = 30 * 86400;

    /** Famille du refresh token consommé pendant cette requête (rotation). */
    private ?array $rotatingFamily = null;

    public function __construct(
        private readonly PDO $pdo,
        private readonly AuditLog $log,
        private readonly string $issuer,
        private readonly string $resource,
    ) {
    }

    // --- Clients ---

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $row = $this->clientRow($clientIdentifier);

        return $row === null ? null
            : new Client($row['id'], $row['name'], json_decode($row['redirect_uris'], true), $row['secret_hash'] !== null);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        if (!in_array($grantType, ['authorization_code', 'refresh_token'], true)) {
            return false;
        }
        $row = $this->clientRow($clientIdentifier);
        if ($row === null) {
            return false;
        }
        if ($row['secret_hash'] === null) {
            return true; // client public (DCR avec "none") : PKCE fait foi
        }

        return $clientSecret !== null && password_verify($clientSecret, $row['secret_hash']);
    }

    /** @return array{id:string,secret:?string} */
    public function createClient(string $name, array $redirectUris, bool $confidential, bool $dynamic = false): array
    {
        $id = bin2hex(random_bytes(16));
        $secret = $confidential ? rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=') : null;
        $this->pdo->prepare('INSERT INTO clients (id, name, secret_hash, redirect_uris, created_at, dynamic) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$id, $name, $secret === null ? null : password_hash($secret, PASSWORD_ARGON2ID),
                json_encode(array_values($redirectUris)), time(), (int) $dynamic]);
        $this->log->log('client_created', ['client_id' => $id, 'name' => $name, 'dynamic' => $dynamic]);

        return ['id' => $id, 'secret' => $secret];
    }

    public function countDynamicClients(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM clients WHERE dynamic = 1')->fetchColumn();
    }

    private function clientRow(string $id): ?array
    {
        $st = $this->pdo->prepare('SELECT * FROM clients WHERE id = ?');
        $st->execute([$id]);

        return $st->fetch() ?: null;
    }

    // --- Scopes ---

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $identifier === Scope::MAIL ? new Scope(Scope::MAIL) : null;
    }

    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        return [new Scope(Scope::MAIL)];
    }

    // --- Access tokens ---

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $t = new AccessToken($this->issuer, $this->resource);
        $t->setClient($clientEntity);
        foreach ($scopes as $s) {
            $t->addScope($s);
        }
        if ($userIdentifier !== null) {
            $t->setUserIdentifier($userIdentifier);
        }

        return $t;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->pdo->prepare('INSERT INTO access_tokens (id, client_id, expires_at) VALUES (?, ?, ?)')
            ->execute([$accessTokenEntity->getIdentifier(), $accessTokenEntity->getClient()->getIdentifier(),
                $accessTokenEntity->getExpiryDateTime()->getTimestamp()]);
        $this->log->log('access_token_issued', ['jti' => $accessTokenEntity->getIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier()]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->pdo->prepare('UPDATE access_tokens SET revoked = 1 WHERE id = ?')->execute([$tokenId]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $st = $this->pdo->prepare('SELECT 1 FROM access_tokens WHERE id = ? AND revoked = 0 AND expires_at > ?');
        $st->execute([$tokenId, time()]);

        return $st->fetchColumn() === false;
    }

    // --- Authorization codes (usage unique) ---

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->pdo->prepare('INSERT INTO auth_codes (id, client_id, expires_at) VALUES (?, ?, ?)')
            ->execute([$authCodeEntity->getIdentifier(), $authCodeEntity->getClient()->getIdentifier(),
                $authCodeEntity->getExpiryDateTime()->getTimestamp()]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->pdo->prepare('UPDATE auth_codes SET revoked = 1 WHERE id = ?')->execute([$codeId]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        // Consommation atomique : un seul appel peut passer de 0 à 1.
        $st = $this->pdo->prepare('UPDATE auth_codes SET revoked = 1 WHERE id = ? AND revoked = 0 AND expires_at > ?');
        $st->execute([$codeId, time()]);
        if ($st->rowCount() === 1) {
            return false;
        }
        $this->log->log('auth_code_rejected', ['reason' => 'reused_or_expired']);

        return true;
    }

    // --- Refresh tokens (rotation + détection de réutilisation) ---

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshToken();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $id = $refreshTokenEntity->getIdentifier();
        [$family, $started] = $this->rotatingFamily ?? [$id, time()];
        $this->pdo->prepare('INSERT INTO refresh_tokens (id, access_token_id, family, family_started, expires_at) VALUES (?, ?, ?, ?, ?)')
            ->execute([$id, $refreshTokenEntity->getAccessToken()->getIdentifier(), $family, $started,
                min($refreshTokenEntity->getExpiryDateTime()->getTimestamp(), $started + self::REFRESH_FAMILY_MAX_SECONDS)]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $st = $this->pdo->prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0');
        $st->execute([$tokenId]);
        $row = $this->refreshRow($tokenId);
        if ($row === null) {
            return;
        }
        if ($st->rowCount() === 0) {
            // Deux requêtes concurrentes avec le même jeton : réutilisation.
            $this->revokeFamily($row['family'], 'refresh_token_reuse');
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }
        $this->rotatingFamily = [$row['family'], (int) $row['family_started']];
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = $this->refreshRow($tokenId);
        if ($row === null) {
            return true;
        }
        if ((int) $row['revoked'] === 1) {
            $this->revokeFamily($row['family'], 'refresh_token_reuse');

            return true;
        }

        return (int) $row['expires_at'] <= time() || (int) $row['family_started'] + self::REFRESH_FAMILY_MAX_SECONDS <= time();
    }

    public function revokeFamily(string $family, string $reason): void
    {
        $st = $this->pdo->prepare('SELECT access_token_id FROM refresh_tokens WHERE family = ?');
        $st->execute([$family]);
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $atId) {
            $this->revokeAccessToken($atId);
        }
        $this->pdo->prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family = ?')->execute([$family]);
        $this->log->log('token_family_revoked', ['family' => substr($family, 0, 8), 'reason' => $reason]);
    }

    /** Pour la révocation RFC 7009 d'un access token : révoque aussi sa famille. */
    public function familyOfAccessToken(string $jti): ?string
    {
        $st = $this->pdo->prepare('SELECT family FROM refresh_tokens WHERE access_token_id = ?');
        $st->execute([$jti]);

        return $st->fetchColumn() ?: null;
    }

    public function familyOfRefreshToken(string $id): ?string
    {
        return $this->refreshRow($id)['family'] ?? null;
    }

    private function refreshRow(string $id): ?array
    {
        $st = $this->pdo->prepare('SELECT * FROM refresh_tokens WHERE id = ?');
        $st->execute([$id]);

        return $st->fetch() ?: null;
    }
}
