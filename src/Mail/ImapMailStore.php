<?php

declare(strict_types=1);

namespace MailMcp\Mail;

use DirectoryTree\ImapEngine\BodyStructurePart;
use DirectoryTree\ImapEngine\Mailbox;
use DirectoryTree\ImapEngine\Message;

/**
 * Implémentation ImapEngine (PHP pur, sans ext-imap). TLS implicite (993) avec
 * vérification du certificat, timeout court, connexion paresseuse fermée par close().
 * Tous les accès au corps utilisent BODY.PEEK : la lecture ne pose jamais \Seen.
 */
final class ImapMailStore implements MailStore
{
    private const MAX_PART_BYTES = 2_000_000;

    private ?Mailbox $mailbox = null;

    public function __construct(private readonly array $cfg)
    {
    }

    public function listFolders(): array
    {
        $out = [];
        foreach ($this->mailbox()->folders()->get() as $folder) {
            $out[] = $folder->path();
        }

        return $out;
    }

    public function search(string $folder, ?string $text, ?string $from, ?\DateTimeImmutable $since, bool $unseenOnly, int $limit): array
    {
        $q = $this->mailbox()->folders()->findOrFail($folder)->messages()
            ->leaveUnread()->withHeaders()->withFlags()->withBodyStructure();
        if ($text !== null) {
            $q->text($text);
        }
        if ($from !== null) {
            $q->from($from);
        }
        if ($since !== null) {
            $q->since($since);
        }
        if ($unseenOnly) {
            $q->unseen();
        }

        $out = [];
        foreach ($q->newest()->limit($limit)->get() as $m) {
            /** @var Message $m */
            $part = $this->textPart($m, false) ?? $this->textPart($m, true);
            $snippet = $part ? (string) $this->fetchPart($m, $part) : '';
            if ($part?->isHtml()) {
                $snippet = HtmlToText::convert($snippet);
            }
            $out[] = [
                'uid' => $m->uid(),
                'date' => $m->date()?->toIso8601String(),
                'from' => (string) $m->from()?->email(),
                'subject' => (string) $m->subject(),
                'snippet' => $snippet,
                'flags' => array_values(array_map('strval', $m->flags())),
            ];
        }

        return $out;
    }

    public function getMessage(string $folder, int $uid): ?array
    {
        $m = $this->mailbox()->folders()->findOrFail($folder)->messages()
            ->leaveUnread()->withHeaders()->withFlags()->withBodyStructure()->find($uid);
        if (!$m instanceof Message) {
            return null;
        }
        $textPart = $this->textPart($m, false);
        $htmlPart = $this->textPart($m, true);
        $attachments = [];
        foreach ($m->bodyStructure()?->flatten() ?? [] as $p) {
            if ($p->isAttachment()) {
                $attachments[] = ['name' => (string) $p->filename(), 'type' => $p->contentType(), 'size' => $p->size()];
            }
        }

        return [
            'uid' => $m->uid(),
            'date' => $m->date()?->toIso8601String(),
            'from' => (string) $m->from()?->email(),
            'to' => array_map(fn ($a) => $a->email(), $m->to()),
            'cc' => array_map(fn ($a) => $a->email(), $m->cc()),
            'subject' => (string) $m->subject(),
            'message_id' => $m->messageId(),
            'references' => $m->header('References')?->getRawValue(),
            'flags' => array_values(array_map('strval', $m->flags())),
            'text' => $textPart ? $this->fetchPart($m, $textPart) : null,
            'html' => $htmlPart ? $this->fetchPart($m, $htmlPart) : null,
            'attachments' => $attachments,
        ];
    }

    public function appendDraft(string $folder, string $rawMessage): ?int
    {
        $uid = $this->mailbox()->folders()->findOrFail($folder)->messages()->append($rawMessage, ['\\Draft']);

        return $uid > 0 ? $uid : null;
    }

    public function close(): void
    {
        if ($this->mailbox?->connected()) {
            $this->mailbox->disconnect();
        }
        $this->mailbox = null;
    }

    public function __destruct()
    {
        try {
            $this->close();
        } catch (\Throwable) {
        }
    }

    private function mailbox(): Mailbox
    {
        return $this->mailbox ??= new Mailbox([
            'host' => $this->cfg['host'],
            'port' => (int) ($this->cfg['port'] ?? 993),
            'encryption' => 'ssl',
            'validate_cert' => true,
            'timeout' => (int) ($this->cfg['timeout'] ?? 10),
            'username' => $this->cfg['username'],
            'password' => $this->cfg['password'],
            'debug' => false,
        ]);
    }

    private function textPart(Message $m, bool $html): ?BodyStructurePart
    {
        foreach ($m->bodyStructure()?->flatten() ?? [] as $p) {
            if (!$p->isAttachment() && ($html ? $p->isHtml() : $p->isText()) && ($p->size() ?? 0) <= self::MAX_PART_BYTES) {
                return $p;
            }
        }

        return null;
    }

    private function fetchPart(Message $m, BodyStructurePart $p): ?string
    {
        $raw = $m->bodyPart($p->partNumber(), true);
        if ($raw === null) {
            return null;
        }
        $raw = match (strtolower((string) $p->encoding())) {
            'base64' => (string) base64_decode($raw),
            'quoted-printable' => quoted_printable_decode($raw),
            default => $raw,
        };
        $charset = $p->charset() ?: 'UTF-8';
        if (strcasecmp($charset, 'UTF-8') !== 0) {
            try {
                $raw = (string) mb_convert_encoding($raw, 'UTF-8', $charset);
            } catch (\ValueError) {
                // jeu de caractères inconnu : on garde l'octet brut, nettoyé ci-dessous
            }
        }

        return mb_scrub($raw, 'UTF-8');
    }
}
