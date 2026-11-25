<?php

declare(strict_types=1);

namespace MailMcp;

use DateInterval;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use MailMcp\Mail\ImapMailStore;
use MailMcp\Mail\MailStore;
use MailMcp\Mcp\Tools;
use MailMcp\OAuth\OAuthStore;
use MailMcp\OAuth\Scope;
use MailMcp\OAuth\TokenValidator;
use MailMcp\OAuth\User;
use Mcp\Server\Server;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\StreamableHttpTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use OTPHP\TOTP;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class App
{
    public const COOKIE = '__Host-mcp_auth';
    private const PENDING_TTL = 600;

    public readonly PDO $pdo;
    public readonly AuditLog $log;
    public readonly OAuthStore $store;
    private readonly RateLimiter $limiter;
    private readonly Psr17Factory $http;
    private readonly string $base;
    private readonly string $resource;
    /** @var callable(): MailStore */
    private $mailFactory;

    public function __construct(private readonly array $cfg, ?callable $mailFactory = null)
    {
        $this->base = rtrim($cfg['base_url'], '/');
        $this->resource = $this->base . '/mcp';
        if (!is_dir($cfg['var_dir'] . '/log')) {
            mkdir($cfg['var_dir'] . '/log', 0700, true);
        }
        $this->pdo = Db::connect($cfg['var_dir'] . '/app.sqlite');
        $this->log = new AuditLog($cfg['var_dir'] . '/log/audit.log');
        $this->limiter = new RateLimiter($this->pdo);
        $this->store = new OAuthStore($this->pdo, $this->log, $this->base, $this->resource);
        $this->http = new Psr17Factory();
        $this->mailFactory = $mailFactory ?? fn () => new ImapMailStore($cfg['imap']);
    }

    public function handle(ServerRequestInterface $req): ResponseInterface
    {
        try {
            $res = $this->route($req);
        } catch (\Throwable $e) {
            $this->log->log('internal_error', ['path' => $req->getUri()->getPath(),
                'error' => get_class($e) . ': ' . mb_substr($e->getMessage(), 0, 300) . ' @' . basename($e->getFile()) . ':' . $e->getLine()]);
            $res = $this->json(['error' => 'server_error'], 500);
        }

        return $res
            ->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('Referrer-Policy', 'no-referrer')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }

    private function route(ServerRequestInterface $req): ResponseInterface
    {
        $path = $req->getUri()->getPath();
        $m = $req->getMethod();

        return match (true) {
            $path === '/mcp' => $this->mcp($req),
            $m === 'GET' && in_array($path, ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], true)
                => $this->json($this->resourceMetadata()),
            $m === 'GET' && $path === '/.well-known/oauth-authorization-server' => $this->json($this->asMetadata()),
            $m === 'GET' && $path === '/authorize' => $this->authorizeGet($req),
            $m === 'POST' && $path === '/authorize' => $this->authorizePost($req),
            $m === 'POST' && $path === '/token' => $this->token($req),
            $m === 'POST' && $path === '/revoke' => $this->revoke($req),
            $m === 'POST' && $path === '/register' && ($this->cfg['oauth']['dcr_enabled'] ?? false) => $this->register($req),
            default => $this->json(['error' => 'not_found'], 404),
        };
    }

    // ---------------------------------------------------------------- metadata

    public function resourceMetadata(): array
    {
        return [
            'resource' => $this->resource,
            'authorization_servers' => [$this->base],
            'scopes_supported' => [Scope::MAIL],
            'bearer_methods_supported' => ['header'],
            'resource_name' => 'Boîte mail (lecture + brouillons)',
        ];
    }

    public function asMetadata(): array
    {
        $dcr = (bool) ($this->cfg['oauth']['dcr_enabled'] ?? false);

        return array_filter([
            'issuer' => $this->base,
            'authorization_endpoint' => $this->base . '/authorize',
            'token_endpoint' => $this->base . '/token',
            'revocation_endpoint' => $this->base . '/revoke',
            'registration_endpoint' => $dcr ? $this->base . '/register' : null,
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => $dcr ? ['client_secret_post', 'client_secret_basic', 'none'] : ['client_secret_post', 'client_secret_basic'],
            'revocation_endpoint_auth_methods_supported' => $dcr ? ['client_secret_post', 'client_secret_basic', 'none'] : ['client_secret_post', 'client_secret_basic'],
            'scopes_supported' => [Scope::MAIL],
        ]);
    }

    // ---------------------------------------------------------------- /authorize

    private function authorizeGet(ServerRequestInterface $req): ResponseInterface
    {
        $q = $req->getQueryParams();
        try {
            $authReq = $this->authServer()->validateAuthorizationRequest($req); // client + redirect_uri exacte
        } catch (OAuthServerException $e) {
            $this->log->log('authorize_rejected', ['client_id' => (string) ($q['client_id'] ?? ''), 'error' => $e->getErrorType()]);

            return $this->page('Requête refusée', '<p>Requête d\'autorisation invalide.</p>', 400);
        }
        $error = match (true) {
            ($q['response_type'] ?? '') !== 'code' => 'response_type',
            ($q['code_challenge_method'] ?? '') !== 'S256' || ($q['code_challenge'] ?? '') === '' => 'pkce_s256_required',
            !isset($q['redirect_uri']) => 'redirect_uri_required',
            ($q['resource'] ?? '') !== $this->resource => 'invalid_resource',
            default => null,
        };
        if ($error !== null) {
            $this->log->log('authorize_rejected', ['client_id' => $authReq->getClient()->getIdentifier(), 'error' => $error]);

            return $this->page('Requête refusée', '<p>Requête d\'autorisation invalide (' . $this->e($error) . ').</p>', 400);
        }

        $id = bin2hex(random_bytes(32));
        $csrf = bin2hex(random_bytes(32));
        $this->pdo->prepare('DELETE FROM pending_auth WHERE expires_at < ?')->execute([time()]);
        $this->pdo->prepare('INSERT INTO pending_auth (id_hash, csrf, query, expires_at) VALUES (?, ?, ?, ?)')
            ->execute([hash('sha256', $id), $csrf, $req->getUri()->getQuery(), time() + self::PENDING_TTL]);

        return $this->loginForm($authReq->getClient()->getName(), (string) $q['redirect_uri'], $csrf)
            ->withHeader('Set-Cookie', self::COOKIE . "=$id; Path=/; Max-Age=" . self::PENDING_TTL . '; Secure; HttpOnly; SameSite=Strict');
    }

    private function authorizePost(ServerRequestInterface $req): ResponseInterface
    {
        $p = (array) $req->getParsedBody();
        $ip = $this->ip($req);
        $keys = ["login:ip:$ip", 'login:global'];

        $cookie = (string) ($req->getCookieParams()[self::COOKIE] ?? '');
        $st = $this->pdo->prepare('SELECT * FROM pending_auth WHERE id_hash = ? AND expires_at >= ?');
        $st->execute([hash('sha256', $cookie), time()]);
        $pending = $st->fetch();
        if ($pending === false || !hash_equals($pending['csrf'], (string) ($p['csrf'] ?? ''))) {
            $this->log->log('authorize_csrf_failed', ['ip' => $ip]);

            return $this->page('Session expirée', '<p>Session expirée ou invalide. Recommencez depuis Claude.</p>', 400);
        }
        parse_str($pending['query'], $query);
        $authReq = $this->authServer()->validateAuthorizationRequest($req->withQueryParams($query));
        $redirectUri = (string) $query['redirect_uri'];
        $clientName = $authReq->getClient()->getName();

        if (($p['action'] ?? '') === 'deny') {
            $this->consumePending($pending['id_hash']);
            $this->log->log('authorize_denied', ['client_id' => $authReq->getClient()->getIdentifier(), 'ip' => $ip]);
            $authReq->setUser(new User($this->cfg['owner']['username']));
            $authReq->setAuthorizationApproved(false);

            return $this->leagueResponse(fn ($r) => $this->authServer()->completeAuthorizationRequest($authReq, $r));
        }

        if (($wait = $this->limiter->loginBlockedFor(...$keys)) !== null) {
            $this->log->log('login_throttled', ['ip' => $ip, 'wait' => $wait]);

            return $this->loginForm($clientName, $redirectUri, $pending['csrf'], "Trop de tentatives. Réessayez dans $wait s.", 429);
        }

        $pwOk = password_verify((string) ($p['password'] ?? ''), (string) $this->cfg['owner']['password_hash']);
        $totpOk = $this->verifyTotp((string) ($p['totp'] ?? ''));
        $userOk = hash_equals((string) $this->cfg['owner']['username'], (string) ($p['username'] ?? ''));
        if (!($pwOk && $totpOk && $userOk)) {
            $locked = $this->limiter->loginFailed(...$keys);
            $this->log->log('login_failed', ['ip' => $ip]);
            if ($locked !== []) {
                $this->log->log('login_locked', ['ip' => $ip, 'keys' => $locked]);
            }

            return $this->loginForm($clientName, $redirectUri, $pending['csrf'], 'Identifiants invalides.', 401);
        }

        $this->limiter->loginSucceeded(...$keys);
        $this->consumePending($pending['id_hash']); // usage unique (équivaut à régénérer la session)
        $this->log->log('login_success', ['ip' => $ip, 'client_id' => $authReq->getClient()->getIdentifier()]);
        $authReq->setUser(new User($this->cfg['owner']['username']));
        $authReq->setAuthorizationApproved(true);

        return $this->leagueResponse(fn ($r) => $this->authServer()->completeAuthorizationRequest($authReq, $r))
            ->withHeader('Set-Cookie', self::COOKIE . '=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict');
    }

    private function verifyTotp(string $code): bool
    {
        $secret = (string) $this->cfg['owner']['totp_secret'];
        if ($secret === '' || !preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        $totp = TOTP::createFromSecret($secret);
        if (!$totp->verify($code, null, 15)) {
            return false;
        }
        // Anti-rejeu : un code déjà accepté ne repasse pas.
        $st = $this->pdo->prepare('SELECT v FROM kv WHERE k = ?');
        $st->execute(['totp_last']);
        [$lastCode, $lastAt] = explode(':', (string) ($st->fetchColumn() ?: ':0'));
        if (hash_equals($lastCode, $code) && time() - (int) $lastAt < 120) {
            return false;
        }
        $this->pdo->prepare('REPLACE INTO kv (k, v) VALUES (?, ?)')->execute(['totp_last', $code . ':' . time()]);

        return true;
    }

    private function consumePending(string $idHash): void
    {
        $this->pdo->prepare('DELETE FROM pending_auth WHERE id_hash = ?')->execute([$idHash]);
    }

    // ---------------------------------------------------------------- /token, /revoke, /register

    private function token(ServerRequestInterface $req): ResponseInterface
    {
        $ip = $this->ip($req);
        if (!$this->limiter->hit("token:$ip", 20, 60)) {
            $this->log->log('rate_limited', ['endpoint' => 'token', 'ip' => $ip]);

            return $this->json(['error' => 'slow_down'], 429);
        }
        $p = (array) $req->getParsedBody();
        $grant = (string) ($p['grant_type'] ?? '');
        // RFC 8707 : la ressource, obligatoire pour le code, doit être exactement la nôtre.
        if (($grant === 'authorization_code' && ($p['resource'] ?? null) !== $this->resource)
            || (isset($p['resource']) && $p['resource'] !== $this->resource)) {
            $this->log->log('token_error', ['grant' => $grant, 'error' => 'invalid_target', 'ip' => $ip]);

            return $this->json(['error' => 'invalid_target'], 400);
        }

        $res = $this->leagueResponse(fn ($r) => $this->authServer()->respondToAccessTokenRequest($req, $r), $grant);
        $this->log->log($res->getStatusCode() === 200 ? 'token_issued' : 'token_error',
            ['grant' => mb_substr($grant, 0, 40), 'status' => $res->getStatusCode(), 'ip' => $ip]);

        return $res;
    }

    private function revoke(ServerRequestInterface $req): ResponseInterface
    {
        $ip = $this->ip($req);
        if (!$this->limiter->hit("revoke:$ip", 20, 60)) {
            return $this->json(['error' => 'slow_down'], 429);
        }
        $p = (array) $req->getParsedBody();
        [$clientId, $secret] = $this->clientCredentials($req, $p);
        if ($clientId === '' || !$this->store->validateClient($clientId, $secret, 'refresh_token')) {
            return $this->json(['error' => 'invalid_client'], 401);
        }
        $token = (string) ($p['token'] ?? '');
        $family = null;
        if (substr_count($token, '.') === 2) {
            $claims = $this->validator()->validate($token);
            if ($claims !== null && $claims['client_id'] === $clientId) {
                $this->store->revokeAccessToken($claims['jti']);
                $family = $this->store->familyOfAccessToken($claims['jti']);
            }
        } elseif ($token !== '') {
            try {
                $data = json_decode(Crypto::decrypt($token, Key::loadFromAsciiSafeString($this->cfg['oauth']['encryption_key'])), true);
                if (($data['client_id'] ?? null) === $clientId) {
                    $family = $this->store->familyOfRefreshToken((string) $data['refresh_token_id']);
                }
            } catch (\Throwable) {
                // jeton inconnu : RFC 7009 impose quand même 200
            }
        }
        if ($family !== null) {
            $this->store->revokeFamily($family, 'rfc7009');
        }
        $this->log->log('token_revocation', ['client_id' => $clientId, 'matched' => $family !== null, 'ip' => $ip]);

        return $this->http->createResponse(200);
    }

    private function register(ServerRequestInterface $req): ResponseInterface
    {
        $ip = $this->ip($req);
        if (!$this->limiter->hit("register:$ip", 5, 3600)) {
            return $this->json(['error' => 'slow_down'], 429);
        }
        $d = json_decode((string) $req->getBody(), true);
        $uris = $d['redirect_uris'] ?? null;
        $allowed = $this->cfg['oauth']['dcr_redirect_uris'] ?? [];
        $method = $d['token_endpoint_auth_method'] ?? 'client_secret_basic';
        if (!is_array($uris) || $uris === [] || array_diff($uris, $allowed) !== [] || array_filter($uris, 'is_string') !== $uris) {
            $this->log->log('dcr_rejected', ['ip' => $ip, 'reason' => 'redirect_uri']);

            return $this->json(['error' => 'invalid_redirect_uri'], 400);
        }
        if (!in_array($method, ['none', 'client_secret_post', 'client_secret_basic'], true)) {
            return $this->json(['error' => 'invalid_client_metadata'], 400);
        }
        if ($this->store->countDynamicClients() >= (int) ($this->cfg['oauth']['dcr_max_clients'] ?? 2)) {
            $this->log->log('dcr_rejected', ['ip' => $ip, 'reason' => 'max_clients']);

            return $this->json(['error' => 'access_denied', 'error_description' => 'Client limit reached'], 403);
        }
        $name = mb_substr(preg_replace('/[\x00-\x1F\x7F]/', '', (string) ($d['client_name'] ?? 'Client dynamique')) ?? '', 0, 80);
        $c = $this->store->createClient($name, array_values($uris), $method !== 'none', true);

        return $this->json(array_filter([
            'client_id' => $c['id'],
            'client_secret' => $c['secret'],
            'client_id_issued_at' => time(),
            'client_secret_expires_at' => $c['secret'] ? 0 : null,
            'client_name' => $name,
            'redirect_uris' => array_values($uris),
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $method,
        ], fn ($v) => $v !== null), 201);
    }

    // ---------------------------------------------------------------- /mcp

    private function mcp(ServerRequestInterface $req): ResponseInterface
    {
        $origins = $this->cfg['oauth']['allowed_origins'] ?? [];
        if ($req->hasHeader('Origin') && !in_array($req->getHeaderLine('Origin'), $origins, true)) {
            $this->log->log('mcp_origin_rejected', ['ip' => $this->ip($req)]);

            return $this->json(['error' => 'forbidden_origin'], 403);
        }

        $auth = $req->getHeaderLine('Authorization');
        $claims = preg_match('/^Bearer ([A-Za-z0-9\-_.]+)$/', $auth, $mm) ? $this->validator()->validate($mm[1]) : null;
        if ($claims === null) {
            $challenge = 'Bearer resource_metadata="' . $this->base . '/.well-known/oauth-protected-resource/mcp", scope="' . Scope::MAIL . '"'
                . ($auth !== '' ? ', error="invalid_token"' : '');
            if ($auth !== '') {
                $this->log->log('mcp_invalid_token', ['ip' => $this->ip($req)]);
            }

            return $this->json(['error' => 'unauthorized'], 401)->withHeader('WWW-Authenticate', $challenge);
        }
        if (!$this->limiter->hit('mcp:' . $claims['jti'], 120, 60)) {
            $this->log->log('rate_limited', ['endpoint' => 'mcp', 'jti' => $claims['jti']]);

            return $this->json(['error' => 'rate_limited'], 429)->withHeader('Retry-After', '60');
        }

        $mail = ($this->mailFactory)();
        try {
            $imap = $this->cfg['imap'];
            $tools = new Tools($mail, $this->log, $imap['username'], (string) ($imap['from_name'] ?? ''), $imap['drafts_folder'] ?? 'Drafts');
            $server = $tools->register(Server::builder()->setServerInfo('mail-mcp', '1.0.0'))->build();
            $host = (string) parse_url($this->base, PHP_URL_HOST);
            $transport = new StreamableHttpTransport($req, $this->http, $this->http, null,
                [new DnsRebindingProtectionMiddleware([$host], $origins)], 1_000_000);

            return $server->run($transport);
        } finally {
            if ($mail instanceof ImapMailStore) {
                $mail->close();
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private ?AuthorizationServer $authServer = null;
    private ?TokenValidator $validator = null;

    private function authServer(): AuthorizationServer
    {
        if ($this->authServer !== null) {
            return $this->authServer;
        }
        $keys = $this->cfg['keys_dir'];
        $s = new AuthorizationServer($this->store, $this->store, $this->store,
            new CryptKey($keys . '/private.key', null, PHP_OS_FAMILY !== 'Windows'),
            Key::loadFromAsciiSafeString($this->cfg['oauth']['encryption_key']));
        $code = new AuthCodeGrant($this->store, $this->store, new DateInterval('PT60S'));
        $code->setRefreshTokenTTL(new DateInterval('P30D'));
        $s->enableGrantType($code, new DateInterval('PT15M'));
        $refresh = new RefreshTokenGrant($this->store);
        $refresh->setRefreshTokenTTL(new DateInterval('P30D'));
        $s->enableGrantType($refresh, new DateInterval('PT15M'));
        $s->setDefaultScope(Scope::MAIL);

        return $this->authServer = $s;
    }

    public function validator(): TokenValidator
    {
        return $this->validator ??= new TokenValidator($this->cfg['keys_dir'] . '/public.key', $this->base, $this->resource, $this->store);
    }

    private function leagueResponse(callable $fn, string $grant = ''): ResponseInterface
    {
        try {
            return $fn($this->http->createResponse());
        } catch (OAuthServerException $e) {
            return $e->generateHttpResponse($this->http->createResponse());
        }
    }

    /** @return array{string, ?string} */
    private function clientCredentials(ServerRequestInterface $req, array $p): array
    {
        if (preg_match('/^Basic (.+)$/', $req->getHeaderLine('Authorization'), $m)) {
            $parts = explode(':', (string) base64_decode($m[1], true), 2);

            return [urldecode($parts[0]), isset($parts[1]) ? urldecode($parts[1]) : null];
        }

        return [(string) ($p['client_id'] ?? ''), isset($p['client_secret']) ? (string) $p['client_secret'] : null];
    }

    private function ip(ServerRequestInterface $req): string
    {
        // shortcut: REMOTE_ADDR seul (X-Forwarded-For est falsifiable) ; à revoir si un proxy de confiance est ajouté.
        return (string) ($req->getServerParams()['REMOTE_ADDR'] ?? 'unknown');
    }

    private function json(array $data, int $status = 200): ResponseInterface
    {
        return $this->http->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->http->createStream(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)));
    }

    private function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private function loginForm(string $client, string $redirectUri, string $csrf, string $error = '', int $status = 200): ResponseInterface
    {
        $host = (string) parse_url($redirectUri, PHP_URL_HOST);
        $body = ($error !== '' ? '<p class="err">' . $this->e($error) . '</p>' : '')
            . '<p>L\'application <strong>' . $this->e($client) . '</strong> (retour vers <strong>' . $this->e($host) . '</strong>) demande :</p>'
            . '<ul><li>' . $this->e(Scope::DESCRIPTION) . '</li></ul>'
            . '<form method="post" action="/authorize" autocomplete="off">'
            . '<input type="hidden" name="csrf" value="' . $this->e($csrf) . '">'
            . '<label>Identifiant <input name="username" required autocomplete="username"></label>'
            . '<label>Mot de passe <input type="password" name="password" required autocomplete="current-password"></label>'
            . '<label>Code TOTP <input name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code"></label>'
            . '<button name="action" value="approve">Se connecter et autoriser</button> '
            . '<button name="action" value="deny" formnovalidate>Refuser</button></form>';
        $origin = parse_url($redirectUri, PHP_URL_SCHEME) . '://' . $host;

        return $this->page('Autoriser l\'accès à la boîte mail', $body, $status, $origin);
    }

    private function page(string $title, string $body, int $status, string $formTarget = ''): ResponseInterface
    {
        $nonce = base64_encode(random_bytes(16));
        $html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $this->e($title) . '</title><style nonce="' . $nonce . '">body{font-family:system-ui,sans-serif;max-width:28rem;margin:2rem auto;padding:0 1rem}'
            . 'label{display:block;margin:.8rem 0}input{display:block;width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}'
            . 'button{padding:.6rem 1rem;font-size:1rem;margin-top:.5rem}.err{color:#b00020}</style></head><body><h1>'
            . $this->e($title) . '</h1>' . $body . '</body></html>';
        // form-action doit aussi couvrir la redirection finale vers le client (Chrome l'applique aux redirections).
        $csp = "default-src 'none'; style-src 'nonce-$nonce'; form-action 'self'" . ($formTarget !== '' ? ' ' . $formTarget : '')
            . "; frame-ancestors 'none'; base-uri 'none'";

        return $this->http->createResponse($status)
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Content-Security-Policy', $csp)
            ->withBody($this->http->createStream($html));
    }
}
