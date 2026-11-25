<?php

declare(strict_types=1);

namespace MailMcp\OAuth;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

final class TokenValidator
{
    private Configuration $jwt;

    public function __construct(
        string $publicKeyFile,
        private readonly string $issuer,
        private readonly string $resource,
        private readonly OAuthStore $store,
    ) {
        $this->jwt = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText('unused'), InMemory::file($publicKeyFile));
    }

    /** @return ?array{jti:string, sub:string, client_id:string} null si invalide */
    public function validate(string $jwt): ?array
    {
        try {
            $token = $this->jwt->parser()->parse($jwt);
        } catch (\Throwable) {
            return null;
        }
        if (!$token instanceof UnencryptedToken || !$this->jwt->validator()->validate($token,
            new SignedWith($this->jwt->signer(), $this->jwt->verificationKey()),
            new StrictValidAt(new class implements \Psr\Clock\ClockInterface {
                public function now(): \DateTimeImmutable
                {
                    return new \DateTimeImmutable();
                }
            }),
            new IssuedBy($this->issuer),
            new PermittedFor($this->resource),
        )) {
            return null;
        }
        // Exactement une audience : la nôtre.
        if ($token->claims()->get('aud') !== [$this->resource]) {
            return null;
        }
        $jti = (string) $token->claims()->get('jti');
        if ($jti === '' || $this->store->isAccessTokenRevoked($jti)) {
            return null;
        }

        return ['jti' => $jti, 'sub' => (string) $token->claims()->get('sub'), 'client_id' => (string) $token->claims()->get('client_id')];
    }
}
