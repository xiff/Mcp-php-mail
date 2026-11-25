<?php

declare(strict_types=1);

namespace MailMcp\Tests;

use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use MailMcp\App;
use MailMcp\Db;
use MailMcp\OAuth\AccessToken;
use MailMcp\OAuth\Client;
use MailMcp\OAuth\Scope;
use Nyholm\Psr7\Factory\Psr17Factory;
use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class OAuthFlowTest extends TestCase
{
    private const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
    private const RESOURCE = TestEnv::BASE . '/mcp';

    private array $cfg;
    private App $app;
    private Psr17Factory $f;
    private array $client;
    /** Valeurs secrètes vues pendant le test, à rechercher dans le journal. */
    private array $secrets = [];

    protected function setUp(): void
    {
        $this->cfg = TestEnv::config();
        $this->f = new Psr17Factory();
        $this->app = new App($this->cfg, fn () => new FakeMailStore());
        $this->client = $this->app->store->createClient('Claude', [self::REDIRECT], true);
        $this->secrets = [TestEnv::PASSWORD, $this->cfg['owner']['totp_secret'], $this->client['secret'],
            $this->cfg['imap']['password'], $this->cfg['oauth']['encryption_key']];
    }

    // ------------------------------------------------------------ helpers

    private function req(string $method, string $path, array $query = [], ?array $form = null, array $headers = [], array $cookies = [], ?string $body = null)
    {
        $r = $this->f->createServerRequest($method, TestEnv::BASE . $path . ($query ? '?' . http_build_query($query) : ''), ['REMOTE_ADDR' => '203.0.113.9'])
            ->withQueryParams($query)->withCookieParams($cookies)->withHeader('Host', 'mcp.test.example');
        foreach ($headers as $k => $v) {
            $r = $r->withHeader($k, $v);
        }
        if ($form !== null) {
            $r = $r->withParsedBody($form)->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withBody($this->f->createStream(http_build_query($form)));
        }
        if ($body !== null) {
            $r = $r->withBody($this->f->createStream($body));
        }

        return $this->app->handle($r);
    }

    private function pkce(): array
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        return [$verifier, rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')];
    }

    private function authQuery(string $challenge, array $override = []): array
    {
        return array_filter($override + [
            'response_type' => 'code', 'client_id' => $this->client['id'], 'redirect_uri' => self::REDIRECT,
            'code_challenge' => $challenge, 'code_challenge_method' => 'S256', 'state' => 'st4te-xyz',
            'scope' => 'mail', 'resource' => self::RESOURCE,
        ], fn ($v) => $v !== null);
    }

    /** @return array{0:string,1:string} cookie, csrf */
    private function openLogin(array $query): array
    {
        $res = $this->req('GET', '/authorize', $query);
        $this->assertSame(200, $res->getStatusCode(), (string) $res->getBody());
        preg_match('/' . App::COOKIE . '=([0-9a-f]+)/', $res->getHeaderLine('Set-Cookie'), $c);
        preg_match('/name="csrf" value="([0-9a-f]+)"/', (string) $res->getBody(), $t);

        return [$c[1], $t[1]];
    }

    private function totp(): string
    {
        $this->app->pdo->exec("DELETE FROM kv WHERE k = 'totp_last'"); // le test se reconnecte dans la même fenêtre de 30 s

        return TOTP::createFromSecret($this->cfg['owner']['totp_secret'])->now();
    }

    private function login(array $query, ?string $totp = null, string $password = TestEnv::PASSWORD): ResponseInterface
    {
        [$cookie, $csrf] = $this->openLogin($query);

        return $this->req('POST', '/authorize', [], ['csrf' => $csrf, 'username' => 'owner', 'password' => $password,
            'totp' => $totp ?? $this->totp(), 'action' => 'approve'], [], [App::COOKIE => $cookie]);
    }

    private function codeFrom(ResponseInterface $res): string
    {
        $this->assertSame(302, $res->getStatusCode(), (string) $res->getBody());
        $loc = $res->getHeaderLine('Location');
        $this->assertStringStartsWith(self::REDIRECT . '?', $loc);
        parse_str((string) parse_url($loc, PHP_URL_QUERY), $q);
        $this->assertSame('st4te-xyz', $q['state']);

        return $this->secrets[] = $q['code'];
    }

    private function exchange(string $code, ?string $verifier, array $override = []): ResponseInterface
    {
        return $this->req('POST', '/token', [], array_filter($override + [
            'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier,
            'client_id' => $this->client['id'], 'client_secret' => $this->client['secret'], 'resource' => self::RESOURCE,
        ], fn ($v) => $v !== null));
    }

    private function json(ResponseInterface $r): array
    {
        return json_decode((string) $r->getBody(), true) ?? [];
    }

    private function tokens(): array
    {
        [$verifier, $challenge] = $this->pkce();
        $res = $this->exchange($this->codeFrom($this->login($this->authQuery($challenge))), $verifier);
        $this->assertSame(200, $res->getStatusCode(), (string) $res->getBody());
        $t = $this->json($res);
        $this->secrets[] = $t['access_token'];
        $this->secrets[] = $t['refresh_token'];

        return $t;
    }

    private function refresh(string $rt): ResponseInterface
    {
        return $this->req('POST', '/token', [], ['grant_type' => 'refresh_token', 'refresh_token' => $rt,
            'client_id' => $this->client['id'], 'client_secret' => $this->client['secret'], 'resource' => self::RESOURCE]);
    }

    private function mcp(?string $token, string $method = 'tools/list', array $headers = [], ?array $params = null): ResponseInterface
    {
        $h = $headers + ['Content-Type' => 'application/json', 'Accept' => 'application/json, text/event-stream', 'MCP-Protocol-Version' => '2025-11-25'];
        if ($token !== null) {
            $h['Authorization'] = "Bearer $token";
        }

        return $this->req('POST', '/mcp', [], null, $h, [], json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => $params ?? new \stdClass()]));
    }

    private function signedToken(string $audience, string $expiry): string
    {
        $t = new AccessToken(TestEnv::BASE, $audience);
        $t->setIdentifier(bin2hex(random_bytes(10)));
        $t->setClient(new Client($this->client['id'], 'Claude', [self::REDIRECT], true));
        $t->setUserIdentifier('owner');
        $t->addScope(new Scope('mail'));
        $t->setExpiryDateTime(new DateTimeImmutable($expiry));
        $t->setPrivateKey(new CryptKey($this->cfg['keys_dir'] . '/private.key'));
        $this->app->store->persistNewAccessToken($t);

        return $t->toString();
    }

    // ------------------------------------------------------------ tests

    public function testMcpWithoutTokenIs401WithResourceMetadata(): void
    {
        foreach ([null, 'not-a-jwt'] as $tok) {
            $res = $this->mcp($tok);
            $this->assertSame(401, $res->getStatusCode());
            $this->assertStringContainsString('Bearer resource_metadata="' . TestEnv::BASE . '/.well-known/oauth-protected-resource/mcp"',
                $res->getHeaderLine('WWW-Authenticate'));
            $this->assertSame('no-store', $res->getHeaderLine('Cache-Control'));
        }
    }

    public function testMetadataDocuments(): void
    {
        $prm = $this->json($this->req('GET', '/.well-known/oauth-protected-resource/mcp'));
        $this->assertSame(self::RESOURCE, $prm['resource']);
        $this->assertSame([TestEnv::BASE], $prm['authorization_servers']);

        $as = $this->json($this->req('GET', '/.well-known/oauth-authorization-server'));
        $this->assertSame(TestEnv::BASE, $as['issuer']);
        $this->assertSame(['S256'], $as['code_challenge_methods_supported']);
        $this->assertSame(['authorization_code', 'refresh_token'], $as['grant_types_supported']);
        $this->assertArrayNotHasKey('registration_endpoint', $as);
        $this->assertSame(404, $this->req('POST', '/register', body: '{}')->getStatusCode());
    }

    public function testFullFlowThenMcpToolsAndRefreshRotationWithReuseDetection(): void
    {
        $t = $this->tokens();
        $this->assertSame('Bearer', $t['token_type']);
        $this->assertLessThanOrEqual(900, $t['expires_in']);

        $res = $this->mcp($t['access_token'], 'tools/list', ['Origin' => 'https://claude.ai']);
        $this->assertSame(200, $res->getStatusCode(), (string) $res->getBody());
        $tools = array_column($this->json($res)['result']['tools'], null, 'name');
        $this->assertSame(['create_draft', 'get_message', 'list_folders', 'search_messages'], array_keys(array_sort($tools)));
        $this->assertTrue($tools['get_message']['annotations']['readOnlyHint']);
        $this->assertFalse($tools['create_draft']['annotations']['destructiveHint']);

        $call = $this->json($this->mcp($t['access_token'], 'tools/call', [], ['name' => 'search_messages', 'arguments' => ['folder' => 'INBOX', 'limit' => 5]]));
        $this->assertFalse($call['result']['isError'], json_encode($call));
        $this->assertSame(42, $call['result']['structuredContent']['messages'][0]['uid']);
        $bad = $this->json($this->mcp($t['access_token'], 'tools/call', [], ['name' => 'get_message', 'arguments' => ['folder' => 'Nope', 'uid' => 1]]));
        $this->assertTrue(($bad['result']['isError'] ?? false) || isset($bad['error']), json_encode($bad));
        $none = $this->json($this->mcp($t['access_token'], 'tools/call', [], ['name' => 'delete_message', 'arguments' => []]));
        $this->assertTrue(isset($none['error']) || ($none['result']['isError'] ?? false), json_encode($none));

        // Rotation
        $r1 = $this->refresh($t['refresh_token']);
        $this->assertSame(200, $r1->getStatusCode(), (string) $r1->getBody());
        $t2 = $this->json($r1);
        $this->secrets[] = $t2['access_token'];
        $this->secrets[] = $t2['refresh_token'];
        $this->assertNotSame($t['refresh_token'], $t2['refresh_token']);
        $this->assertSame(401, $this->mcp($t['access_token'])->getStatusCode(), 'ancien access token révoqué');
        $this->assertSame(200, $this->mcp($t2['access_token'])->getStatusCode());

        // Réutilisation de l'ancien refresh token => toute la famille est révoquée
        $reuse = $this->refresh($t['refresh_token']);
        $this->assertSame(400, $reuse->getStatusCode());
        $this->assertSame('invalid_grant', $this->json($reuse)['error']);
        $this->assertSame(401, $this->mcp($t2['access_token'])->getStatusCode());
        $this->assertSame(400, $this->refresh($t2['refresh_token'])->getStatusCode());
    }

    public function testPkceMissingOrPlainIsRejected(): void
    {
        [, $challenge] = $this->pkce();
        foreach ([['code_challenge' => null, 'code_challenge_method' => null], ['code_challenge_method' => 'plain'], ['code_challenge_method' => null]] as $o) {
            $this->assertSame(400, $this->req('GET', '/authorize', $this->authQuery($challenge, $o))->getStatusCode());
        }
    }

    public function testWrongPkceVerifierIsRejected(): void
    {
        [, $challenge] = $this->pkce();
        [$otherVerifier] = $this->pkce();
        $code = $this->codeFrom($this->login($this->authQuery($challenge)));
        $res = $this->exchange($code, $otherVerifier);
        $this->assertSame(400, $res->getStatusCode());
        $this->assertSame(400, $this->exchange($code, null)->getStatusCode());
    }

    public function testRedirectUriMustMatchExactly(): void
    {
        [$verifier, $challenge] = $this->pkce();
        foreach ([self::REDIRECT . '/x', self::REDIRECT . '?a=1', 'https://claude.ai/api/mcp/', 'https://evil.example/cb', null] as $uri) {
            $res = $this->req('GET', '/authorize', $this->authQuery($challenge, ['redirect_uri' => $uri]));
            $this->assertSame(400, $res->getStatusCode(), (string) $uri);
            $this->assertFalse($res->hasHeader('Location'));
        }
        $code = $this->codeFrom($this->login($this->authQuery($challenge)));
        $this->assertSame(400, $this->exchange($code, $verifier, ['redirect_uri' => 'https://evil.example/cb'])->getStatusCode());
    }

    public function testCodeIsSingleUse(): void
    {
        [$verifier, $challenge] = $this->pkce();
        $code = $this->codeFrom($this->login($this->authQuery($challenge)));
        $this->assertSame(200, $this->exchange($code, $verifier)->getStatusCode());
        $this->assertSame(400, $this->exchange($code, $verifier)->getStatusCode());
    }

    public function testResourceParameterIsEnforced(): void
    {
        [$verifier, $challenge] = $this->pkce();
        $this->assertSame(400, $this->req('GET', '/authorize', $this->authQuery($challenge, ['resource' => 'https://evil.example/mcp']))->getStatusCode());
        $this->assertSame(400, $this->req('GET', '/authorize', $this->authQuery($challenge, ['resource' => null]))->getStatusCode());
        $code = $this->codeFrom($this->login($this->authQuery($challenge)));
        $res = $this->exchange($code, $verifier, ['resource' => 'https://evil.example/mcp']);
        $this->assertSame('invalid_target', $this->json($res)['error']);
    }

    public function testExpiredTokenAndWrongAudienceAreRejected(): void
    {
        $this->assertSame(200, $this->mcp($this->signedToken(self::RESOURCE, '+5 minutes'))->getStatusCode());
        $this->assertSame(401, $this->mcp($this->signedToken(self::RESOURCE, '-1 minute'))->getStatusCode());
        $this->assertSame(401, $this->mcp($this->signedToken('https://other.example/mcp', '+5 minutes'))->getStatusCode());
        $this->assertSame(401, $this->mcp($this->signedToken($this->client['id'], '+5 minutes'))->getStatusCode());
    }

    public function testOtherGrantTypesAreRejected(): void
    {
        foreach (['password', 'client_credentials', 'implicit'] as $g) {
            $res = $this->req('POST', '/token', [], ['grant_type' => $g, 'client_id' => $this->client['id'],
                'client_secret' => $this->client['secret'], 'username' => 'owner', 'password' => TestEnv::PASSWORD]);
            $this->assertSame(400, $res->getStatusCode());
            $this->assertSame('unsupported_grant_type', $this->json($res)['error']);
        }
        [, $challenge] = $this->pkce();
        $this->assertSame(400, $this->req('GET', '/authorize', $this->authQuery($challenge, ['response_type' => 'token']))->getStatusCode());
    }

    public function testLoginRequiresPasswordAndTotpAndCsrf(): void
    {
        [, $challenge] = $this->pkce();
        $this->assertSame(401, $this->login($this->authQuery($challenge), '000000')->getStatusCode());
        $this->app->pdo->exec('DELETE FROM login_attempts');
        $this->assertSame(401, $this->login($this->authQuery($challenge), null, 'mauvais')->getStatusCode());
        $this->app->pdo->exec('DELETE FROM login_attempts');

        [$cookie] = $this->openLogin($this->authQuery($challenge));
        $res = $this->req('POST', '/authorize', [], ['csrf' => str_repeat('0', 64), 'username' => 'owner',
            'password' => TestEnv::PASSWORD, 'totp' => $this->totp(), 'action' => 'approve'], [], [App::COOKIE => $cookie]);
        $this->assertSame(400, $res->getStatusCode());

        // TOTP rejoué
        $code = $this->totp();
        $this->codeFrom($this->login($this->authQuery($challenge), $code));
        $this->assertSame(401, $this->login($this->authQuery($challenge), $code)->getStatusCode());
    }

    public function testDenyRedirectsWithAccessDenied(): void
    {
        [, $challenge] = $this->pkce();
        [$cookie, $csrf] = $this->openLogin($this->authQuery($challenge));
        $res = $this->req('POST', '/authorize', [], ['csrf' => $csrf, 'action' => 'deny'], [], [App::COOKIE => $cookie]);
        $this->assertSame(302, $res->getStatusCode());
        $this->assertStringContainsString('error=access_denied', $res->getHeaderLine('Location'));
    }

    public function testOriginValidation(): void
    {
        $t = $this->tokens();
        $this->assertSame(403, $this->mcp($t['access_token'], 'tools/list', ['Origin' => 'https://evil.example'])->getStatusCode());
    }

    public function testKillSwitchAndRevocationEndpoint(): void
    {
        $t = $this->tokens();
        Db::revokeAll($this->app->pdo);
        $this->assertSame(401, $this->mcp($t['access_token'])->getStatusCode());
        $this->assertSame(400, $this->refresh($t['refresh_token'])->getStatusCode());

        $t = $this->tokens();
        $res = $this->req('POST', '/revoke', [], ['token' => $t['refresh_token'], 'client_id' => $this->client['id'], 'client_secret' => $this->client['secret']]);
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(401, $this->mcp($t['access_token'])->getStatusCode());
        $this->assertSame(401, $this->req('POST', '/revoke', [], ['token' => 'x', 'client_id' => $this->client['id'], 'client_secret' => 'faux'])->getStatusCode());
    }

    public function testDynamicRegistrationWhitelistAndLimit(): void
    {
        $this->cfg['oauth']['dcr_enabled'] = true;
        $this->app = new App($this->cfg, fn () => new FakeMailStore());
        $this->assertSame(400, $this->req('POST', '/register', body: json_encode(['redirect_uris' => ['https://evil.example/cb']]))->getStatusCode());
        $this->assertSame(400, $this->req('POST', '/register', body: json_encode(['redirect_uris' => [self::REDIRECT . 'x']]))->getStatusCode());
        $ok = $this->req('POST', '/register', body: json_encode(['redirect_uris' => [self::REDIRECT], 'token_endpoint_auth_method' => 'none']));
        $this->assertSame(201, $ok->getStatusCode());
        $this->assertArrayNotHasKey('client_secret', $this->json($ok));
        $this->assertSame(403, $this->req('POST', '/register', body: json_encode(['redirect_uris' => [self::REDIRECT]]))->getStatusCode());
    }

    public function testAuditLogContainsNoSecrets(): void
    {
        $t = $this->tokens();
        $this->refresh($t['refresh_token']);
        [, $challenge] = $this->pkce();
        $this->login($this->authQuery($challenge), '123456');
        $this->mcp($t['access_token']);
        $this->req('POST', '/token', [], ['grant_type' => 'password', 'password' => TestEnv::PASSWORD]);

        $log = file_get_contents($this->cfg['var_dir'] . '/log/audit.log');
        $this->assertStringContainsString('login_success', $log);
        $this->assertStringContainsString('login_failed', $log);
        $this->assertStringContainsString('access_token_issued', $log);
        foreach (array_filter($this->secrets) as $s) {
            $this->assertStringNotContainsString($s, $log);
        }
        $this->assertStringNotContainsString('$argon2id$', $log);
    }
}

function array_sort(array $a): array
{
    ksort($a);

    return $a;
}
