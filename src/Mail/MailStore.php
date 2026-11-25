<?php

declare(strict_types=1);

namespace MailMcp\Mail;

/**
 * Accès bas niveau à la boîte. Volontairement SANS méthode d'envoi, de suppression,
 * de déplacement ni de modification de drapeaux : ce qui n'existe pas ne peut pas être appelé.
 * Les entrées sont déjà validées par Tools.
 */
interface MailStore
{
    /** @return list<string> */
    public function listFolders(): array;

    /**
     * @return list<array{uid:int,date:?string,from:string,subject:string,snippet:string,flags:list<string>}>
     */
    public function search(string $folder, ?string $text, ?string $from, ?\DateTimeImmutable $since, bool $unseenOnly, int $limit): array;

    /**
     * @return ?array{uid:int,date:?string,from:string,to:list<string>,cc:list<string>,subject:string,
     *   message_id:?string,references:?string,flags:list<string>,text:?string,html:?string,
     *   attachments:list<array{name:string,type:string,size:?int}>}
     */
    public function getMessage(string $folder, int $uid): ?array;

    /** APPEND avec le drapeau \Draft. Retourne l'UID si le serveur le fournit. */
    public function appendDraft(string $folder, string $rawMessage): ?int;
}
