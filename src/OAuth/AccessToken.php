<?php

declare(strict_types=1);

namespace MailMcp\OAuth;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * JWT RS256. Contrairement à la bibliothèque (aud = client_id), l'audience est
 * l'URL de la ressource MCP (RFC 8707) et l'émetteur est fixé.
 */
final class AccessToken implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
    use TokenEntityTrait;

    public function __construct(private readonly string $issuer, private readonly string $audience)
    {
    }

    public function toString(): string
    {
        $this->initJwtConfiguration();
        $now = new DateTimeImmutable();

        return $this->jwtConfiguration->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($this->audience)
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('client_id', $this->getClient()->getIdentifier())
            ->withClaim('scope', implode(' ', array_map(fn ($s) => $s->getIdentifier(), $this->getScopes())))
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())
            ->toString();
    }
}
