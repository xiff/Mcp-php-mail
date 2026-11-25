<?php

declare(strict_types=1);

namespace MailMcp\OAuth;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

final class Scope implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    /** Seul droit existant : lire la boîte et créer des brouillons. */
    public const MAIL = 'mail';
    public const DESCRIPTION = 'Lire vos dossiers et messages, et créer des brouillons (aucun envoi, aucune suppression)';

    public function __construct(string $id)
    {
        $this->setIdentifier($id);
    }
}
