# Modèle de menace

Actif protégé : le contenu d'une boîte mail Infomaniak, et la capacité d'agir en son nom.
Principe : le serveur ne sait que **lire** et **déposer des brouillons**. Ce qui n'est pas codé ne peut pas être détourné.

## Menaces et mesures

| Menace | Mesures |
|---|---|
| **Vol d'un access token** | JWT RS256 valable **15 min**, audience = l'URL exacte `/mcp` (RFC 8707), émetteur vérifié. Chaque appel vérifie aussi que le `jti` n'est pas révoqué, donc kill switch et révocation sont immédiats. Pas de jeton en URL (en-tête `Authorization` seulement). `Cache-Control: no-store`. Limite : 120 req/min par jeton. |
| **Vol d'un refresh token** | Opaque et chiffré. **Rotation à chaque usage** ; une réutilisation **révoque toute la famille** (refresh et access tokens). La détection est atomique, y compris pour deux requêtes concurrentes. Durée de vie absolue de 30 jours par famille. Révocation RFC 7009 et `bin/revoke-all.php`. Client confidentiel : le secret est en plus requis à `/token`. |
| **Vol d'un code d'autorisation** | Usage unique (consommation atomique), 60 s, PKCE **S256 obligatoire** (`plain` et absence refusés), lié au client et à la `redirect_uri`. |
| **Phishing OAuth / redirection ouverte** | `redirect_uri` comparée **exactement** à celle enregistrée (sans préfixe ni joker), et obligatoire. En cas d'erreur, aucune redirection : une page d'erreur s'affiche. DCR désactivé par défaut ; s'il est activé : liste blanche exacte, plafond de clients, limite de débit. Le consentement affiche le nom du client et **le domaine de retour**. Seuls `authorization_code` et `refresh_token` sont acceptés (pas d'implicit, de password ni de client_credentials). |
| **Injection de prompt via un mail** | Le contenu est renvoyé sous `untrusted_content`, avec un avertissement dans les descriptions d'outils et dans les instructions du serveur. Le HTML est converti en texte : scripts, styles, images et liens supprimés, rien n'est chargé. Surtout, **aucun outil n'a d'effet irréversible** : pas d'envoi, de suppression, de déplacement ni de drapeau. Le pire résultat est un brouillon, que l'humain relit avant d'envoyer lui-même. |
| **Exfiltration via brouillon** (mail piégé qui pousse Claude à écrire des données dans un brouillon adressé à un tiers) | Le brouillon n'est **jamais envoyé** par le serveur. Les destinataires sont validés, et les en-têtes sont protégés contre l'injection CRLF. Risque résiduel : voir plus bas. |
| **Force brute sur la connexion** | Mot de passe Argon2id **et** TOTP obligatoires, comparés en temps constant. Un code TOTP ne peut pas être rejoué. Backoff exponentiel (2^n s) puis **verrouillage 15 min après 5 échecs**, par IP **et** globalement. Tout est journalisé. CSRF sur le formulaire, cookie `__Host-` `Secure; HttpOnly; SameSite=Strict`. |
| **Clickjacking / XSS sur la page de connexion** | CSP stricte (`default-src 'none'`, style avec nonce, `frame-ancestors 'none'`, `form-action` limité), `X-Frame-Options: DENY`, échappement HTML systématique. |
| **DNS rebinding / appel depuis un navigateur** | `Origin` vérifié sur `/mcp` (403 s'il est présent et hors liste), `Host` vérifié par le middleware du SDK. |
| **Injection IMAP** | Les dossiers sont comparés à la liste réelle. UID entiers bornés, dates ISO strictes, pas de caractère de contrôle. Les chaînes passent par l'API d'ImapEngine, qui les échappe. |
| **Interception IMAP** | TLS implicite (993) avec **vérification du certificat et du nom d'hôte**, timeout de 10 s, connexion fermée en fin de requête. |
| **Compromission de l'hébergement** | Secrets hors racine web (600/700) ; `public/` ne contient que `index.php` et `.htaccess`, avec des règles de refus en plus. Mot de passe propriétaire haché, secret client haché (Argon2id). La boîte n'est accessible qu'avec un **mot de passe d'application révocable**. Procédure d'urgence dans le README. |
| **Fuite par les erreurs ou les journaux** | `display_errors=Off` ; client : messages génériques. Journal d'audit sans mot de passe, jeton, code, secret ni contenu de mail (le corps des brouillons est exclu), avec masquage des clés sensibles en filet de sécurité. Un test le vérifie. |
| **Déni de service applicatif** | Limites de débit sur `/token`, `/revoke`, `/register` (par IP) et `/mcp` (par jeton). Corps MCP limité à 1 Mo. `limit` ≤ 50, parties de plus de 2 Mo ignorées, corps tronqué à 50 ko. |
| **Dépendances** | `composer.lock` versionné, versions exactes dans `composer.json`, `composer audit` propre au 25/11/2026. |

## Risques résiduels assumés

1. **Lecture = exfiltration possible** : quiconque obtient un jeton valide, ou une injection de prompt qui réussit dans une conversation, peut **lire** la boîte via Claude. Les mesures limitent la durée (15 min / kill switch), pas la portée de lecture.
2. **Brouillon piégé** : une injection peut amener Claude à créer un brouillon contenant des données, adressé à un tiers. Il n'est pas envoyé, mais un utilisateur distrait pourrait l'envoyer. Relisez toujours les brouillons.
3. **Verrouillage global = DoS** : 5 tentatives fausses, quelle que soit leur origine, bloquent la connexion 15 min. C'est un choix restrictif voulu ; les jetons déjà émis continuent de fonctionner.
4. **Compromission totale de l'hébergement** (compte Infomaniak, accès SSH) : l'attaquant lit `config.php`, donc le mot de passe d'application IMAP. Seule parade : révoquer ce mot de passe chez Infomaniak. Il n'existe pas de coffre-fort matériel sur un mutualisé.
5. **Adresse IP** : les limites par IP utilisent `REMOTE_ADDR`. Un attaquant avec beaucoup d'IP contourne la limite par IP, mais pas la limite globale.
6. **Origin absent accepté** : Claude appelle de serveur à serveur sans `Origin`. La protection DNS rebinding ne vaut donc que pour les navigateurs, qui envoient toujours `Origin`.
7. **SDK MCP en 0.x** : l'API peut changer ; la version est épinglée. Relisez le changelog avant toute mise à jour.
8. **Pas de CIMD** : les clients doivent être pré-enregistrés (ou enregistrés par DCR temporaire).

## Signaler une vulnérabilité

Contactez le propriétaire du dépôt directement (pas d'issue publique).
