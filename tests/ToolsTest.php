<?php

declare(strict_types=1);

namespace MailMcp\Tests;

use MailMcp\AuditLog;
use MailMcp\Mail\MailStore;
use MailMcp\Mcp\ToolError;
use MailMcp\Mcp\Tools;
use Mcp\Schema\Result\CallToolResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ToolsTest extends TestCase
{
    private FakeMailStore $store;
    private Tools $tools;
    private string $logFile;

    protected function setUp(): void
    {
        $this->store = new FakeMailStore();
        $this->logFile = sys_get_temp_dir() . '/mailmcp-tools-' . bin2hex(random_bytes(4)) . '.log';
        $this->tools = new Tools($this->store, new AuditLog($this->logFile), 'moi@example.ch', 'Moi', 'Drafts');
    }

    public function testMailStoreHasNoDestructiveMethods(): void
    {
        $methods = array_map(fn ($m) => $m->getName(), (new \ReflectionClass(MailStore::class))->getMethods());
        $this->assertSame(['listFolders', 'search', 'getMessage', 'appendDraft'], $methods);
    }

    public function testSearchValidInputAndUntrustedWrapping(): void
    {
        $r = $this->tools->searchMessages(['folder' => 'INBOX', 'query' => 'facture', 'from' => 'alice', 'since' => '2026-01-31', 'unseen_only' => true, 'limit' => 50]);
        $this->assertSame(['search', 'INBOX', 'facture', 'alice', '2026-01-31', true, 50], $this->store->calls[0]);
        $this->assertSame(Tools::UNTRUSTED_NOTICE, $r['notice']);
        $msg = $r['messages'][0];
        $this->assertSame(42, $msg['uid']);
        $this->assertLessThanOrEqual(200, mb_strlen($msg['untrusted_content']['snippet']));
        $this->assertArrayNotHasKey('snippet', $msg);
    }

    public static function badSearch(): array
    {
        return [
            'dossier inconnu' => [['folder' => 'Inbox']],
            'dossier injection' => [['folder' => "INBOX\r\nA1 DELETE INBOX"]],
            'dossier manquant' => [[]],
            'limit 0' => [['folder' => 'INBOX', 'limit' => 0]],
            'limit 51' => [['folder' => 'INBOX', 'limit' => 51]],
            'limit chaîne' => [['folder' => 'INBOX', 'limit' => '10']],
            'date invalide' => [['folder' => 'INBOX', 'since' => '2026-02-30']],
            'date format' => [['folder' => 'INBOX', 'since' => '30.01.2026']],
            'query CRLF' => [['folder' => 'INBOX', 'query' => "a\r\nA2 LOGOUT"]],
            'query trop longue' => [['folder' => 'INBOX', 'query' => str_repeat('a', 201)]],
            'from tableau' => [['folder' => 'INBOX', 'from' => ['x']]],
            'unseen chaîne' => [['folder' => 'INBOX', 'unseen_only' => 'yes']],
        ];
    }

    #[DataProvider('badSearch')]
    public function testSearchRejectsBadInput(array $args): void
    {
        $this->expectException(ToolError::class);
        $this->tools->searchMessages($args);
    }

    public function testGetMessageConvertsHtmlTruncatesAndHidesAttachments(): void
    {
        $r = $this->tools->getMessage(['folder' => 'INBOX', 'uid' => 42]);
        $body = $r['untrusted_content']['body_text'];
        $this->assertStringStartsWith('Salut toi', $body);
        $this->assertStringNotContainsString('alert', $body);
        $this->assertStringNotContainsString('track.example', $body);
        $this->assertStringNotContainsString('<', $body);
        $this->assertTrue($r['truncated']);
        $this->assertLessThanOrEqual(50_000, strlen($body));
        $this->assertSame([['name' => 'facture.pdf', 'type' => 'application/pdf', 'size' => 12345]], $r['untrusted_content']['attachments']);
    }

    public static function badGet(): array
    {
        return [[['folder' => 'INBOX', 'uid' => 0]], [['folder' => 'INBOX', 'uid' => -3]], [['folder' => 'INBOX', 'uid' => '42']],
            [['folder' => 'INBOX', 'uid' => 1.5]], [['folder' => 'INBOX', 'uid' => 4294967296]], [['folder' => 'Nope', 'uid' => 42]],
            [['folder' => 'INBOX', 'uid' => 99]]];
    }

    #[DataProvider('badGet')]
    public function testGetMessageRejectsBadInput(array $args): void
    {
        $this->expectException(ToolError::class);
        $this->tools->getMessage($args);
    }

    public function testCreateDraftReplyHeaders(): void
    {
        $r = $this->tools->createDraft(['to' => ['bob@example.org'], 'subject' => 'Re: Bonjour', 'body_text' => "Merci !\nÀ bientôt", 'in_reply_to_uid' => 42]);
        $this->assertSame('draft_saved', $r['status']);
        [$folder, $raw] = $this->store->drafts[0];
        $this->assertSame('Drafts', $folder);
        $this->assertMatchesRegularExpression('/^In-Reply-To: <abc123@example.org>\r$/m', $raw);
        $this->assertMatchesRegularExpression('/^References: <old1@example.org> <abc123@example.org>\r$/m', $raw);
        $this->assertStringContainsString('From: Moi <moi@example.ch>', $raw);
        $this->assertStringContainsString('To: bob@example.org', $raw);
    }

    public static function badDraft(): array
    {
        $ok = ['to' => ['bob@example.org'], 'subject' => 'S', 'body_text' => 'B'];

        return [
            'to vide' => [['to' => []] + $ok],
            'to chaîne' => [['to' => 'bob@example.org'] + $ok],
            'adresse invalide' => [['to' => ['pas-une-adresse']] + $ok],
            'injection en-tête' => [['to' => ["bob@example.org\r\nBcc: x@evil.example"]] + $ok],
            'trop de destinataires' => [['to' => array_fill(0, 21, 'a@example.org')] + $ok],
            'sujet CRLF' => [['subject' => "S\r\nBcc: x@evil.example"] + $ok],
            'sujet trop long' => [['subject' => str_repeat('s', 256)] + $ok],
            'corps trop long' => [['body_text' => str_repeat('b', 100_001)] + $ok],
            'corps binaire' => [['body_text' => "a\x00b"] + $ok],
            'uid réponse invalide' => [['in_reply_to_uid' => 0] + $ok],
            'dossier réponse inconnu' => [['in_reply_to_uid' => 42, 'in_reply_to_folder' => 'X'] + $ok],
        ];
    }

    #[DataProvider('badDraft')]
    public function testCreateDraftRejectsBadInput(array $args): void
    {
        $this->expectException(ToolError::class);
        $this->tools->createDraft($args);
    }

    public function testRunReturnsGenericErrorsAndLogsWithoutBody(): void
    {
        $r = $this->tools->run('create_draft', ['to' => ['bob@example.org'], 'subject' => 'S', 'body_text' => 'CONTENU-PRIVE'],
            fn () => throw new \RuntimeException('imap password=hunter2 failed'));
        $this->assertInstanceOf(CallToolResult::class, $r);
        $this->assertTrue($r->isError);
        $this->assertSame('Erreur interne lors de l\'accès à la boîte mail.', $r->content[0]->text);
        $log = file_get_contents($this->logFile);
        $this->assertStringNotContainsString('CONTENU-PRIVE', $log);
        $this->assertStringContainsString('"tool":"create_draft"', $log);
    }
}
