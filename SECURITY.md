# Threat model

Protected asset: the content of one IMAP mailbox, and the ability to act on its behalf.
Principle: the server can only **read** and **save drafts**. What isn't coded can't be abused.

## Threats and mitigations

| Threat | Mitigations |
|---|---|
| **Stolen access token** | RS256 JWT valid **15 min**, audience = the exact `/mcp` URL (RFC 8707), issuer checked. Every call also checks that the `jti` isn't revoked, so the kill switch and revocation take effect immediately. No token in URLs (`Authorization` header only). `Cache-Control: no-store`. Limit: 120 req/min per token. |
| **Stolen refresh token** | Opaque and encrypted. **Rotated on every use**; reuse **revokes the whole family** (refresh and access tokens). Detection is atomic, including for two concurrent requests. Absolute lifetime of 30 days per family. RFC 7009 revocation and `bin/revoke-all.php`. Confidential client: the secret is also required at `/token`. |
| **Stolen authorization code** | Single use (atomic consumption), 60 s, **mandatory PKCE S256** (`plain` and missing challenge rejected), bound to the client and the `redirect_uri`. |
| **OAuth phishing / open redirect** | `redirect_uri` compared **exactly** with the registered one (no prefix, no wildcard), and mandatory. On error there is no redirect: an error page is shown. DCR disabled by default; if enabled: exact allowlist, client cap, rate limit. The consent screen shows the client name and **the return domain**. Only `authorization_code` and `refresh_token` are accepted (no implicit, password or client_credentials). |
| **Prompt injection via an email** | Content is returned under `untrusted_content`, with a warning in tool descriptions and server instructions. HTML is converted to text: scripts, styles, images and links removed, nothing is loaded. Above all, **no tool has an irreversible effect**: no sending, deleting, moving or flagging. The worst outcome is a draft, which the human reviews before sending it themselves. |
| **Exfiltration via a draft** (a booby-trapped email pushes Claude to write data into a draft addressed to a third party) | The draft is **never sent** by the server. Recipients are validated and headers are protected against CRLF injection. Residual risk: see below. |
| **Login brute force** | Argon2id password **and** TOTP required, compared in constant time. A TOTP code cannot be replayed. Exponential backoff (2^n s) then **15-min lockout after 5 failures**, per IP **and** globally. Everything is logged. CSRF on the form, `__Host-` cookie `Secure; HttpOnly; SameSite=Strict`. |
| **Clickjacking / XSS on the login page** | Strict CSP (`default-src 'none'`, nonce-based style, `frame-ancestors 'none'`, restricted `form-action`), `X-Frame-Options: DENY`, systematic HTML escaping. |
| **DNS rebinding / browser calls** | `Origin` checked on `/mcp` (403 if present and not allowlisted), `Host` checked by the SDK middleware. |
| **IMAP injection** | Folders compared against the real list. Bounded integer UIDs, strict ISO dates, no control characters. Strings go through the ImapEngine API, which escapes them. |
| **IMAP interception** | Implicit TLS (993) with **certificate and hostname verification**, 10 s timeout, connection closed at the end of each request. |
| **Hosting compromise** | Secrets outside the web root (600/700); `public/` holds only `index.php` and `.htaccess`, with extra deny rules. Owner password and client secret hashed (Argon2id). The mailbox is only reachable with a **revocable app password**. Emergency procedure in the README. |
| **Leaks through errors or logs** | `display_errors=Off`; clients get generic messages. Audit log without passwords, tokens, codes, secrets or mail content (draft bodies excluded), with masking of known sensitive keys as a safety net. A test checks this. |
| **Application-level DoS** | Rate limits on `/token`, `/revoke`, `/register` (per IP) and `/mcp` (per token). MCP body capped at 1 MB. `limit` ≤ 50, parts over 2 MB skipped, body truncated to 50 KB. |
| **Dependencies** | `composer.lock` committed, exact versions in `composer.json`, `composer audit` clean as of 2026-11-25. |

## Accepted residual risks

1. **Reading = possible exfiltration**: anyone who gets a valid token, or a successful prompt injection within a conversation, can **read** the mailbox through Claude. The mitigations limit the duration (15 min / kill switch), not the read scope.
2. **Booby-trapped draft**: an injection can lead Claude to create a draft containing data, addressed to a third party. It isn't sent, but a distracted user could send it. Always review drafts.
3. **Global lockout = DoS**: 5 wrong attempts, from any source, block login for 15 min. This is a deliberate restrictive choice; tokens already issued keep working.
4. **Full hosting compromise** (hosting account, SSH access): the attacker reads `config.php`, hence the IMAP app password. The only countermeasure is revoking that password at your mail provider. There is no hardware vault on shared hosting.
5. **IP address**: per-IP limits use `REMOTE_ADDR`. An attacker with many IPs bypasses the per-IP limit, but not the global one.
6. **Missing Origin accepted**: Claude calls server-to-server without `Origin`. DNS rebinding protection therefore only applies to browsers, which always send `Origin`.
7. **MCP SDK at 0.x**: the API may change; the version is pinned. Read the changelog before any upgrade.
8. **No CIMD**: clients must be pre-registered (or registered through temporary DCR).

## Reporting a vulnerability

Contact the repository owner directly (no public issue).
