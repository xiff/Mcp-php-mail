<?php

declare(strict_types=1);

namespace MailMcp\OAuth;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

final class Client implements ClientEntityInterface
{
    use ClientTrait;
    use EntityTrait;

    /** @param list<string> $redirectUris */
    public function __construct(string $id, string $name, array $redirectUris, bool $confidential)
    {
        $this->setIdentifier($id);
        $this->name = $name;
        $this->redirectUri = $redirectUris;
        $this->isConfidential = $confidential;
    }
}
