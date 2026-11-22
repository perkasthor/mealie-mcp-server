# Authentification OAuth et mode `reverse-proxy` — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** rendre le serveur MCP joignable par claude.ai en serveur de ressources OAuth (jetons authentik), et lui faire appeler Mealie au nom de chaque utilisateur par la route « proxy de confiance » de Mealie, sans rien changer au comportement par défaut.

**Architecture:** un paquet neuf `src/mcp_auth/` (configuration, vérificateur OIDC, lecture de l'identité de la requête) branché sur `FastMCP(token_verifier=…, auth=AuthSettings(…))` dans le chemin de `main()` ; un module neuf `src/mealie/reverse_proxy.py` (échange nom → jeton Mealie, cache de clients par utilisateur) ; `_ClientProvider` (`src/server.py`) choisit le client selon `MEALIE_AUTH_MODE`. Le SDK `mcp` monte à 1.30 (métadonnées RFC 9728 et liaison session ↔ utilisateur).

**Tech Stack:** Python 3.12, `mcp` ≥ 1.30 < 2 (`FastMCP`), `httpx`, `pyjwt[crypto]`, `pytest` + `pytest-asyncio`, `uv`, `ruff`, GitHub Actions.

**Spec:** [`../homelab/developpement/mealie-mcp-server.md`](../../../../homelab/developpement/mealie-mcp-server.md) (§ 6 et § 9 ; les essais du § 10 sont tranchés ci-dessous). Lire aussi `AGENTS.md`, `src/AGENTS.md`, `tests/AGENTS.md`.

---

## Ce que les vérifications du § 10 ont tranché (20/11/2026)

Vérifié dans le code des wheels `mcp` 1.12.0 et 1.30.0 et par un essai en conteneur (`ghcr.io/astral-sh/uv:python3.12-bookworm-slim`, serveur `FastMCP` réel, vérificateur factice, `httpx.ASGITransport`).

| Point | 1.12.0 | 1.30.0 | Conséquence pour le plan |
|---|---|---|---|
| **1. Métadonnées** | Le défi annonce `https://h/mcp/.well-known/oauth-protected-resource` → **404** ; la route est servie à la racine | Défi `https://h/.well-known/oauth-protected-resource/mcp` → **200**, `resource` = `https://h/mcp`. `AuthSettings.validate_token_resource` à poser (`False` : notre vérificateur contrôle `aud`), sinon `DeprecationWarning` | **Monter à 1.30** (tâche 1). Aucune route à servir soi-même. Suite de l'amont : 633 tests verts en 1.30.0, aussi avec `-W error::DeprecationWarning`. Le verrou ajoute `pyjwt`, `cryptography`, `cffi`, `pycparser` |
| **2. Contexte dans les outils** | Outils synchrones exécutés dans la boucle (pas de fil). **`get_access_token()` rend le jeton de la requête qui a ouvert la session**, pas celui de la requête courante ; un autre utilisateur qui connaît l'identifiant de session **agit sous le compte du premier** | Même péremption de `get_access_token()`. Mais la session est liée au principal (`client_id`, `claims["iss"]`, `subject`) : un autre utilisateur reçoit **404**. `request_context.request` porte la requête HTTP **courante** (jeton renouvelé vu) | Lire l'identité par `server.get_context().request_context.request.scope["user"]`, **jamais** par `get_access_token()` (tâche 5). Le vérificateur **doit** remplir `subject` et `claims["iss"]` : tous les utilisateurs partagent le même client OAuth, donc le même `client_id` (tâche 2). 40 appels entrelacés de deux utilisateurs : aucun mélange |
| **3. `Host`** | Aucune protection (`transport_security` nul) | Protection activée d'office **seulement** si `FastMCP(host=…)` vaut `127.0.0.1`, `localhost` ou `::1` ; alors `Host: miam-mcp.…` → **421** ; avec `0.0.0.0` → accepté | **Aucun code.** Le cluster pose `MCP_HOST=0.0.0.0` (déjà le cas). Le problème de `Host` de la procédure 04 venait du routage, pas du SDK. Effet de bord de la montée, à documenter : un `MCP_HOST` local derrière un proxy de la même machine reçoit 421 |

Vérifié aussi par essai : PyJWT 2.15.1 (`PyJWKSet.from_dict`, `jwks[kid]` → `KeyError`, `decode(…, options={"require": […]})`) rejette `alg: none`, `aud`/`iss` faux, `exp` absent ou passé, et accepte `aud` en liste contenant le client. Versions courantes des actions : `actions/checkout@v6`, `docker/login-action@v4`, `docker/setup-buildx-action@v4`, `docker/build-push-action@v7`.

**Décisions du constructeur** (§ 9 de la conception) :

- Noms des variables : ceux du § 6.2, inchangés.
- Bibliothèque JWT : `pyjwt[crypto]` (déjà tirée par `mcp` 1.30, déclarée explicitement).
- Modules : `src/mcp_auth/` (pas `src/auth/` : nom de paquet de premier niveau trop générique) et `src/mealie/reverse_proxy.py`.
- Authentification **réservée à `streamable-http`** : `stdio` refusé (spec), `sse` refusé aussi (transport déprécié par la spécification MCP, URL de ressource ambiguë, rien à tester pour claude.ai).
- Variables d'authentification orphelines (`MCP_AUTH_AUDIENCE`, `MCP_AUTH_REQUIRED_GROUP`, `MCP_AUTH_USERNAME_CLAIM`, `MCP_PUBLIC_URL` sans `MCP_AUTH_ISSUER`) : refusées, pour qu'une faute de frappe sur l'émetteur ne laisse pas le serveur ouvert.
- Cache : 256 clients au plus (LRU), marge d'expiration 300 s ; clés JWKS gardées 3 600 s, rechargement sur `kid` inconnu au plus une fois par 60 s ; tolérance d'horloge 30 s.
- Échange avec Mealie par un `httpx.Client` **neuf à chaque échange** : la réponse pose un cookie `mealie.access_token` qu'un client partagé renverrait à l'échange suivant, pour un autre utilisateur.
- Deux PR possibles vers l'amont : tâches 1 à 3 (authentification), puis 4 et 5 (mode `reverse-proxy`). La tâche 6 (publication d'image) et ce plan restent dans le fork.

## Global Constraints

- Python ≥ 3.12 ; `from mcp.server.fastmcp import FastMCP` ; `mcp[cli]>=1.30.0,<2` ; une seule dépendance directe ajoutée : `pyjwt[crypto]>=2.10.1`. `uv.lock` régénéré à chaque changement de `pyproject.toml`.
- Sans aucune des nouvelles variables, le comportement est **exactement** celui d'aujourd'hui : pas d'authentification, `MEALIE_AUTH_MODE=api-key`, `MEALIE_API_KEY` obligatoire.
- Variables (noms exacts, défauts) : `MCP_AUTH_ISSUER` (—), `MCP_AUTH_AUDIENCE` (—), `MCP_AUTH_REQUIRED_GROUP` (—), `MCP_AUTH_USERNAME_CLAIM` (`preferred_username`), `MCP_PUBLIC_URL` (—), `MEALIE_AUTH_MODE` (`api-key` | `reverse-proxy`), `MEALIE_REVERSE_PROXY_SECRET` (—), `MEALIE_REVERSE_PROXY_USER_HEADER` (`X-Forwarded-User`), `MEALIE_REVERSE_PROXY_SECRET_HEADER` (`X-Mealie-Reverse-Proxy-Secret`). Lues uniquement par `os.getenv("NOM", …)` (le test de la tâche 3 en dépend).
- Mealie : `GET /api/auth/reverse-proxy`, réponse `{"access_token", "token_type", "expires_in"}` ; `401` = compte inconnu ou secret faux.
- Journaux : jamais de jeton, secret, clé, nom d'utilisateur, `sub`, corps de requête ou de réponse, contenu de recette. Enregistrements en dictionnaire sur le logger `mealie-mcp`, comme l'amont. Refus de jeton : `{"operation": "mcp token rejected", "reason": <code>}`.
- Messages d'erreur de configuration : nomment la variable, jamais sa valeur.
- La vérification de santé de Mealie (`GET /api/app/about`, `raise_for_status()`) a lieu une fois au démarrage, dans les deux modes ; les clients par utilisateur ne la refont pas. Tout client HTTP est fermé à l'arrêt.
- L'instance construite à l'import (`mcp = create_server()`) reste sans authentification.
- Code, identifiants, messages et `README`/`CHANGELOG` en anglais (langue de l'amont) ; ce plan en français.
- Tests sans réseau ni authentik réel : `httpx.MockTransport`. Avant chaque commit : `uv run ruff check src tests` et `uv run pytest -q` verts.
- Commits ciblés, style de l'amont (`feat:`, `build:`, `docs:`, `ci:`), directement sur `main` du fork, **seulement quand le propriétaire le demande** ; terminer chaque message par la ligne `Co-Authored-By` en vigueur.

## Review Focus

1. **Jeton renouvelé dans une session ouverte** (claude.ai renouvelle toutes les 10 min) : les appels continuent, au nom du même utilisateur ; l'identité vient de la requête courante, pas de celle qui a ouvert la session. → tâche 5, `test_refreshed_token_keeps_session_and_identity`.
2. **Un autre utilisateur rejoue un identifiant de session connu** : `404`, jamais d'appel sous le compte du propriétaire de la session (repose sur `subject` + `claims["iss"]`). → tâche 3, `test_other_user_cannot_use_session`.
3. **Cookie de l'échange** : la réponse de Mealie pose `mealie.access_token` ; l'échange de bob ne doit pas porter le cookie d'alice. → tâche 4, `test_exchange_does_not_forward_cookies`.
4. **Avalanche de jetons à `kid` inconnu** : au plus un rechargement JWKS par période de 60 s, pas un par requête. → tâche 2, `test_unknown_kid_reloads_jwks_at_most_once_per_cooldown`.
5. **Instance sans authentification lancée avec `MCP_AUTH_ISSUER` défini** (`mcp run`, `mcp dev`, instance de l'import) : le démarrage échoue, le serveur ne sert jamais sans authentification. → tâche 3, `test_import_time_instance_refuses_auth_configuration`.

---

## Prérequis d'exécution (pas de commit)

Le poste n'a pas `uv` (et seulement Python 3.11). Au choix du propriétaire :

- installer `uv` : `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`, puis `uv sync --extra dev` (il télécharge Python 3.12 d'après `.python-version`) ;
- ou exécuter les commandes dans `docker run --rm -it -v "${PWD}:/work" -w /work ghcr.io/astral-sh/uv:python3.12-bookworm-slim sh`.

Puis vérifier la base : `uv run pytest -q` → `633 passed`.

## Structure des fichiers

| Fichier | Rôle |
|---|---|
| `src/mcp_auth/__init__.py` (neuf) | Exporte `AuthConfig`, `OidcTokenVerifier`, `USERNAME_KEY`, `current_username` |
| `src/mcp_auth/config.py` (neuf) | `AuthConfig` et sa lecture de l'environnement |
| `src/mcp_auth/verifier.py` (neuf) | `OidcTokenVerifier` : découverte, JWKS, `userinfo`, contrôles |
| `src/mcp_auth/identity.py` (neuf) | `current_username(server)` : nom porté par le jeton de la requête courante |
| `src/mealie/client.py` | `check_mealie_health()` extraite ; `MealieClient(..., check_health=True)` |
| `src/mealie/reverse_proxy.py` (neuf) | `ReverseProxyConfig`, `MealieToken`, `MealieAccountUnavailable`, `ReverseProxyFetcher`, `ReverseProxyClientPool` |
| `src/server.py` | `ServerConfig` étendue ; branchement de l'authentification ; `_ClientProvider` par mode |
| `tests/conftest.py` | `FakeOidc`, `FakeMealie` et leurs fixtures |
| `tests/test_token_verifier.py` (neuf) | Vérificateur |
| `tests/test_reverse_proxy.py` (neuf) | Échange et cache |
| `tests/test_auth_http.py` (neuf) | Bout en bout HTTP |
| `tests/test_server.py` | Configuration, démarrage, documentation des variables |
| `README.md`, `.env.template`, `CHANGELOG.md` | Documentation |
| `.github/workflows/publish-image.yml` (neuf, fork seul) | Publication de l'image après CI verte |

---

### Task 1: Monter le SDK `mcp` à 1.30

**Files:**
- Modify: `pyproject.toml` (dépendance `mcp[cli]`), `uv.lock`
- Modify: `README.md` (section « Remote Access »), `CHANGELOG.md` (`## Unreleased`)
- Test: `tests/test_server.py`

**Interfaces:**
- Produces: SDK ≥ 1.30 : `AccessToken.subject`, `AccessToken.claims`, `AuthSettings.validate_token_resource`, `mcp.server.auth.routes.build_resource_metadata_url`.

- [ ] **Step 1: Écrire le test qui échoue**

```python
def test_sdk_advertises_rfc9728_resource_metadata_path():
    from mcp.server.auth.routes import build_resource_metadata_url
    from pydantic import AnyHttpUrl

    url = build_resource_metadata_url(AnyHttpUrl("https://mcp.example/mcp"))
    assert str(url) == "https://mcp.example/.well-known/oauth-protected-resource/mcp"
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest -q tests/test_server.py::test_sdk_advertises_rfc9728_resource_metadata_path`
Expected: FAIL, `ImportError: cannot import name 'build_resource_metadata_url'`.

- [ ] **Step 3: Monter la dépendance**

`pyproject.toml` : `"mcp[cli]>=1.30.0,<2"`. Puis `uv lock --upgrade-package mcp` et `uv sync --extra dev`.
Expected: `Updated mcp v1.12.0 -> v1.30.0` (ou une 1.x plus récente), ajouts `pyjwt`, `cryptography`, `cffi`, `pycparser`.

- [ ] **Step 4: Vérifier**

Run: `uv run ruff check src tests && uv run pytest -q -W error::DeprecationWarning`
Expected: `All checks passed!`, `634 passed`.

- [ ] **Step 5: Documenter l'effet de bord**

`README.md`, à la fin de « Remote Access » : avec `MCP_HOST` sur une adresse locale (`127.0.0.1`, `localhost`, `::1`), le SDK active sa protection contre le DNS rebinding et répond `421 Invalid Host header` à tout autre `Host` ; derrière un proxy inverse, lier `MCP_HOST` à `0.0.0.0` ou à l'interface vue par le proxy. `CHANGELOG.md`, `### Changed` : même phrase, plus « Require `mcp` 1.30 or later ».

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock tests/test_server.py README.md CHANGELOG.md
git commit -m "build: require mcp 1.30 for RFC 9728 resource metadata"
```

---

### Task 2: Vérificateur de jetons OIDC

**Files:**
- Create: `src/mcp_auth/__init__.py`, `src/mcp_auth/config.py`, `src/mcp_auth/verifier.py`
- Modify: `pyproject.toml` (ajouter `"pyjwt[crypto]>=2.10.1"`), `uv.lock`, `tests/conftest.py`
- Test: `tests/test_token_verifier.py`

**Interfaces:**
- Produces:
  - `AuthConfig(issuer: str, audience: str, public_url: str, required_group: str | None = None, username_claim: str = "preferred_username")`, `@dataclass(frozen=True)` ; propriété `resource_url -> str` = `f"{public_url}/mcp"` (`public_url` est stocké sans `/` final). La lecture de l'environnement vient en tâche 3.
  - `USERNAME_KEY = "mealie_username"` (dans `verifier.py`).
  - `OidcTokenVerifier(config: AuthConfig, *, transport: httpx.AsyncBaseTransport | None = None, clock: Callable[[], float] = time.monotonic, jwks_ttl: float = 3600.0, jwks_refresh_cooldown: float = 60.0)` ; `async def verify_token(self, token: str) -> AccessToken | None`.
  - `AccessToken` rendu : `token` (inchangé), `client_id` = `azp` sinon `config.audience`, `scopes` = `scope.split()` sinon `[]`, `expires_at` = `exp`, `subject` = `sub`, `claims` = `{"iss": <iss>, USERNAME_KEY: <nom>}` — rien d'autre.
  - Codes `reason` : `malformed`, `unknown_key`, `invalid_token`, `discovery_failed`, `jwks_failed`, `userinfo_failed`, `group_missing`, `username_missing`.
  - Test : `FakeOidc` et fixtures `rsa_key` (portée session), `oidc` dans `tests/conftest.py` :
    - attributs `issuer = "https://auth.example/application/o/mealie-mcp/"`, `audience = "mealie-mcp-client"`, `discovery_url`, `jwks_uri`, `userinfo_endpoint`, `discovery_status = 200`, `userinfo: dict | None = None` (`None` → `401`), `requests: list[httpx.Request]`, `transport: httpx.MockTransport` ;
    - `claims(**overrides) -> dict` : réclamations par défaut `iss`, `aud`, `sub="sub-alice"`, `iat`, `exp=now+600`, `preferred_username="alice"`, `groups=["miam-contributors"]`, surchargées ; une valeur `None` retire la réclamation ;
    - `token(*, kid="k1", key=None, algorithm="RS256", **overrides) -> str` : signe `claims(**overrides)` avec la clé publiée (ou `key`), en-tête `kid` (absent si `kid=None`) ;
    - `publish_key(kid: str) -> None` (nouvelle clé publiée et utilisée par `token()`), `config(**overrides) -> AuthConfig` (`public_url="https://miam-mcp.example"`, `required_group="miam-contributors"`), `count(url: str) -> int`.

Comportement de `verify_token` : découverte `issuer.rstrip("/") + "/.well-known/openid-configuration"`, paresseuse, gardée une fois réussie, retentée après un échec, refusée si son `issuer` diffère exactement de `config.issuer` ; JWKS gardé `jwks_ttl`, rechargé sur `kid` inconnu au plus une fois par `jwks_refresh_cooldown` ; un `anyio.Lock` protège découverte et JWKS ; `kid` obligatoire ; algorithme de la clé dans `("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")` ; `jwt.decode(..., algorithms=[jwk.algorithm_name], audience=config.audience, issuer=config.issuer, leeway=30, options={"require": ["exp", "iss", "aud", "sub"]})`. Groupe : présent dans `groups` du jeton → accepté ; sinon `userinfo` (une seule requête par vérification, partagée avec le nom), dont le `sub` doit égaler celui du jeton. Nom : réclamation `username_claim` du jeton, sinon de `userinfo`, chaîne non vide après `strip()`. Requêtes sortantes : `httpx.AsyncClient(transport=self._transport, timeout=10.0)` ouvert et fermé à chaque appel. Tout refus : `None` et un `logger.warning` avec le seul code.

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_token_verifier.py` ; fixture locale `verifier` = `OidcTokenVerifier(oidc.config(), transport=oidc.transport)`, remplacée dans le test quand il en construit un autre)

```python
async def test_valid_token_returns_access_token(oidc):
    token = oidc.token()
    result = await verifier.verify_token(token)
    assert result.token == token
    assert result.subject == "sub-alice"
    assert result.client_id == oidc.audience
    assert result.claims == {"iss": oidc.issuer, USERNAME_KEY: "alice"}
    assert result.expires_at > time.time()

@pytest.mark.parametrize("claims", [
    {"iss": "https://evil.example/"}, {"aud": "other-client"},
    {"exp": int(time.time()) - 120}, {"exp": None}, {"sub": None},
])
async def test_rejects_invalid_claims(oidc, claims):
    assert await verifier.verify_token(oidc.token(**claims)) is None

async def test_rejects_foreign_signature(oidc, verifier):
    # same kid "k1", signed by a key the JWKS does not publish
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(oidc.token(key=foreign)) is None

async def test_rejects_unsigned_and_malformed_tokens(oidc, verifier):
    unsigned = jwt.encode(oidc.claims(), None, algorithm="none", headers={"kid": "k1"})
    assert await verifier.verify_token(unsigned) is None
    assert await verifier.verify_token("not-a-jwt") is None
    assert await verifier.verify_token(oidc.token(kid=None)) is None

async def test_group_found_in_userinfo_when_missing_from_token(oidc):
    oidc.userinfo = {"sub": "sub-alice", "groups": ["miam-contributors"]}
    assert await verifier.verify_token(oidc.token(groups=None)) is not None
    userinfo = [r for r in oidc.requests if str(r.url) == oidc.userinfo_endpoint]
    assert userinfo[0].headers["authorization"].startswith("Bearer ")

async def test_group_missing_everywhere_is_rejected(oidc, caplog):
    oidc.userinfo = {"sub": "sub-alice", "groups": ["someone-else"]}
    assert await verifier.verify_token(oidc.token(groups=["other"])) is None
    assert "group_missing" in caplog.text

async def test_userinfo_for_another_subject_is_rejected(oidc):
    oidc.userinfo = {"sub": "sub-bob", "groups": ["miam-contributors"]}
    assert await verifier.verify_token(oidc.token(groups=None)) is None

async def test_username_from_userinfo_then_missing(oidc):
    oidc.userinfo = {"sub": "sub-alice", "preferred_username": "alice"}
    result = await verifier.verify_token(oidc.token(preferred_username=None))
    assert result.claims[USERNAME_KEY] == "alice"
    oidc.userinfo = {"sub": "sub-alice"}
    assert await verifier.verify_token(oidc.token(preferred_username="  ")) is None

async def test_without_required_group_no_group_check(oidc):
    verifier = OidcTokenVerifier(oidc.config(required_group=None), transport=oidc.transport)
    assert await verifier.verify_token(oidc.token(groups=None)) is not None
    assert oidc.count(oidc.userinfo_endpoint) == 0

async def test_discovery_failure_is_retried_then_cached(oidc):
    oidc.discovery_status = 503
    assert await verifier.verify_token(oidc.token()) is None
    oidc.discovery_status = 200
    assert await verifier.verify_token(oidc.token()) is not None
    assert await verifier.verify_token(oidc.token()) is not None
    assert oidc.count(oidc.discovery_url) == 2
    assert oidc.count(oidc.jwks_uri) == 1

async def test_discovery_with_another_issuer_is_rejected(oidc):
    verifier = OidcTokenVerifier(oidc.config(issuer=oidc.issuer.rstrip("/")), transport=oidc.transport)
    assert await verifier.verify_token(oidc.token(iss=oidc.issuer.rstrip("/"))) is None

async def test_unknown_kid_reloads_jwks_at_most_once_per_cooldown(oidc):
    now = [1000.0]
    verifier = OidcTokenVerifier(oidc.config(), transport=oidc.transport, clock=lambda: now[0])
    assert await verifier.verify_token(oidc.token()) is not None
    oidc.publish_key("k2")
    assert await verifier.verify_token(oidc.token(kid="k2")) is not None   # reload
    for i in range(5):
        assert await verifier.verify_token(oidc.token(kid=f"random-{i}")) is None
    assert oidc.count(oidc.jwks_uri) == 2
    now[0] += 61
    assert await verifier.verify_token(oidc.token(kid="random-x")) is None
    assert oidc.count(oidc.jwks_uri) == 3

async def test_jwks_reloaded_after_ttl(oidc):
    now = [1000.0]
    verifier = OidcTokenVerifier(oidc.config(), transport=oidc.transport, clock=lambda: now[0])
    assert await verifier.verify_token(oidc.token()) is not None
    now[0] += 3601
    assert await verifier.verify_token(oidc.token()) is not None
    assert oidc.count(oidc.jwks_uri) == 2

async def test_rejection_logs_reason_only(oidc, caplog):
    token = oidc.token(aud="other-client")
    with caplog.at_level(logging.DEBUG):
        assert await verifier.verify_token(token) is None
    assert "mcp token rejected" in caplog.text and "invalid_token" in caplog.text
    assert token not in caplog.text and "sub-alice" not in caplog.text and "alice" not in caplog.text
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest -q tests/test_token_verifier.py`
Expected: FAIL, `ModuleNotFoundError: No module named 'mcp_auth'`.

- [ ] **Step 3: Implémenter** `AuthConfig` dans `src/mcp_auth/config.py`, `OidcTokenVerifier` et `USERNAME_KEY` dans `src/mcp_auth/verifier.py`, exports dans `src/mcp_auth/__init__.py` ; ajouter `pyjwt[crypto]>=2.10.1` à `pyproject.toml` puis `uv lock` et `uv sync --extra dev`.

- [ ] **Step 4: Vérifier**

Run: `uv run ruff check src tests && uv run pytest -q`
Expected: tout vert.

- [ ] **Step 5: Commit**

```bash
git add src/mcp_auth pyproject.toml uv.lock tests/conftest.py tests/test_token_verifier.py
git commit -m "feat: add OIDC bearer token verifier"
```

---

### Task 3: Authentification du serveur, désactivée par défaut

**Files:**
- Modify: `src/mcp_auth/config.py` (lecture de l'environnement), `src/server.py`
- Modify: `tests/conftest.py` (`FakeMealie`), `tests/test_server.py`
- Create: `tests/test_auth_http.py`
- Modify: `README.md`, `.env.template`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `AuthConfig`, `OidcTokenVerifier`, `FakeOidc` (tâche 2).
- Produces:
  - `AuthConfig.from_environment() -> AuthConfig | None` ; `ServerConfig.auth: AuthConfig | None = None` (champ ajouté après les existants ; `ServerConfig("http://…", "key")` reste valide).
  - `_MealieServer(config)` : si `config.auth`, passe à `FastMCP.__init__` `token_verifier=OidcTokenVerifier(config.auth)` et `auth=AuthSettings(issuer_url=config.auth.issuer, resource_server_url=config.auth.resource_url, validate_token_resource=False)`.
  - Garde : au début de `_configure_optional_tools()`, si `self.client_provider.configuration().auth` est défini et `self.settings.auth` nul → `ValueError` nommant `MCP_AUTH_ISSUER` et le point d'entrée à utiliser.
  - Test : `FakeMealie` dans `tests/conftest.py` : `transport: httpx.MockTransport`, `health_status = 200`, `requests: list[httpx.Request]`, `clients: list[httpx.Client]` ; `install(monkeypatch)` remplace `httpx.Client` par une fabrique qui injecte `transport` et garde chaque client créé. Routes : `GET /api/app/about` ; `GET /api/recipes` qui accepte `Bearer api-key-marker` (utilisateur `shared`) et répond `{"items": [{"id": "r1", "name": f"{user} recipe"}], "page": 1, "perPage": 50, "total": 1}`, sinon `401` ; toute autre route : `AssertionError`.
  - Test : fixture `http_app` dans `tests/test_auth_http.py`, fabrique de contexte asynchrone `http_app(*, mealie_health: int = 200, **env)` → objet `app` d'attributs `client`, `oidc`, `mealie`, `server` : variables de base (`MEALIE_BASE_URL=http://mealie.invalid`, `MEALIE_API_KEY=api-key-marker`, `MCP_TRANSPORT=streamable-http`, `MCP_HOST=0.0.0.0`, `MCP_AUTH_ISSUER=oidc.issuer`, `MCP_AUTH_AUDIENCE=oidc.audience`, `MCP_AUTH_REQUIRED_GROUP=miam-contributors`, `MCP_PUBLIC_URL=https://miam-mcp.example`) surchargées par `env` ; `mealie.install(monkeypatch)` ; `httpx.AsyncClient` remplacé par une fabrique qui injecte `oidc.transport` quand aucun `transport` n'est passé ; `load_dotenv` neutralisé ; `sse_starlette.sse.AppStatus.should_exit_event` remis à `None` ; serveur = `create_server(ServerConfig.from_environment())` chargé par `runpy.run_module("server")` ; durée de vie de `streamable_http_app()` ouverte ; `httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://miam-mcp.example")`.
  - Test : constante `INITIALIZE` (requête JSON-RPC `initialize`, `protocolVersion` `2025-03-26`, comme dans `test_http_sessions_initialize_list_and_call_tools`) ; `async def initialize(client, token) -> dict[str, str]` (initialize + `notifications/initialized`, rend les en-têtes avec `Mcp-Session-Id`) ; `async def call_tool(client, headers, name, arguments=None, *, token=None) -> tuple[int, dict | None]` (statut HTTP, `result` JSON-RPC lu dans la ligne `data:`).

Règles de `AuthConfig.from_environment()` : `MCP_AUTH_ISSUER` absent ou vide → `None`, mais `ValueError` si l'une de `MCP_AUTH_AUDIENCE`, `MCP_AUTH_REQUIRED_GROUP`, `MCP_AUTH_USERNAME_CLAIM`, `MCP_PUBLIC_URL` est définie ; émetteur : URL `http`/`https` avec hôte, gardée telle quelle ; `MCP_AUTH_AUDIENCE` et `MCP_PUBLIC_URL` obligatoires ; `MCP_PUBLIC_URL` : `http`/`https`, hôte, chemin vide ou `/`, ni requête ni fragment, `/` final retiré ; `MCP_AUTH_USERNAME_CLAIM` non vide ; `MCP_AUTH_REQUIRED_GROUP` vide → `None`. `ServerConfig.from_environment()` ajoute : authentification et `MCP_TRANSPORT` ≠ `streamable-http` → `ValueError` nommant `MCP_TRANSPORT`.

- [ ] **Step 1: Écrire les tests de configuration qui échouent** (`tests/test_server.py`)

La fixture `load_server` retire aussi toutes les variables des Global Constraints.

```python
AUTH_ENV = {"MCP_TRANSPORT": "streamable-http", "MCP_AUTH_ISSUER": "https://auth.example/o/app/",
            "MCP_AUTH_AUDIENCE": "client", "MCP_PUBLIC_URL": "https://mcp.example"}

@pytest.mark.parametrize(("env", "message"), [
    ({**AUTH_ENV, "MCP_AUTH_AUDIENCE": ""}, "MCP_AUTH_AUDIENCE"),
    ({**AUTH_ENV, "MCP_PUBLIC_URL": ""}, "MCP_PUBLIC_URL"),
    ({**AUTH_ENV, "MCP_PUBLIC_URL": "https://mcp.example/mcp"}, "MCP_PUBLIC_URL"),
    ({**AUTH_ENV, "MCP_PUBLIC_URL": "mcp.example"}, "MCP_PUBLIC_URL"),
    ({**AUTH_ENV, "MCP_AUTH_ISSUER": "not-a-url"}, "MCP_AUTH_ISSUER"),
    ({**AUTH_ENV, "MCP_AUTH_USERNAME_CLAIM": " "}, "MCP_AUTH_USERNAME_CLAIM"),
    ({**AUTH_ENV, "MCP_TRANSPORT": "stdio"}, "MCP_TRANSPORT"),
    ({**AUTH_ENV, "MCP_TRANSPORT": "sse"}, "MCP_TRANSPORT"),
    ({"MCP_AUTH_AUDIENCE": "client"}, "MCP_AUTH_ISSUER"),
    ({"MCP_PUBLIC_URL": "https://mcp.example"}, "MCP_AUTH_ISSUER"),
])
def test_invalid_auth_configuration_fails_before_http_allocation(load_server, monkeypatch, env, message):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    server, _, requests, factory = load_server()
    with pytest.raises(ValueError, match=message) as error:
        server["main"]()
    assert "auth.example" not in str(error.value) and "mcp.example" not in str(error.value)
    assert requests == []
    factory.assert_not_called()

def test_auth_configuration_is_parsed(load_server, monkeypatch):
    config = ServerConfig.from_environment()  # with AUTH_ENV and MCP_PUBLIC_URL="https://mcp.example/"
    assert config.auth == AuthConfig("https://auth.example/o/app/", "client", "https://mcp.example",
                                     None, "preferred_username")
    assert config.auth.resource_url == "https://mcp.example/mcp"

def test_no_auth_variables_keep_current_behaviour(load_server):
    assert ServerConfig.from_environment().auth is None

async def test_import_time_instance_refuses_auth_configuration(load_server, monkeypatch):
    # AUTH_ENV set; namespace["mcp"] was built without configuration
    with pytest.raises(ValueError, match="MCP_AUTH_ISSUER"):
        async with server_lifespan(namespace["mcp"], "streamable-http"):
            pytest.fail("must not serve without authentication")
    factory.assert_not_called()

def test_readme_documents_every_environment_variable():
    source = "\n".join(p.read_text(encoding="utf-8") for p in Path("src").rglob("*.py"))
    names = set(re.findall(r'os\.getenv\(\s*"([A-Z0-9_]+)"', source))
    readme = Path("README.md").read_text(encoding="utf-8")
    assert {"MCP_AUTH_ISSUER", "MCP_PUBLIC_URL"} <= names
    assert sorted(n for n in names if f"`{n}`" not in readme) == []
```

- [ ] **Step 2: Écrire les tests de bout en bout qui échouent** (`tests/test_auth_http.py`)

```python
async def test_missing_token_is_challenged_with_resource_metadata(http_app):
    async with http_app() as app:
        response = await app.client.post("/mcp", json={})
        assert response.status_code == 401
        assert ('resource_metadata="https://miam-mcp.example/.well-known/oauth-protected-resource/mcp"'
                in response.headers["www-authenticate"])
        metadata = await app.client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == "https://miam-mcp.example/mcp"
        assert metadata.json()["authorization_servers"] == [app.oidc.issuer]

@pytest.mark.parametrize("claims", [{"aud": "other"}, {"groups": ["other"]}, {"exp": 1}])
async def test_rejected_tokens_get_401(http_app, claims):
    async with http_app() as app:   # oidc.userinfo stays None: no group from userinfo either
        response = await app.client.post("/mcp", json=INITIALIZE, headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {app.oidc.token(**claims)}"})
        assert response.status_code == 401

async def test_valid_token_calls_mealie_with_api_key(http_app):
    async with http_app() as app:
        # Host is miam-mcp.example with MCP_HOST=0.0.0.0: pins the § 10.3 finding
        headers = await initialize(app.client, app.oidc.token())
        status, result = await call_tool(app.client, headers, "get_recipes")
        assert status == 200 and result.get("isError") is not True
        assert "shared recipe" in json.dumps(result)
        assert app.mealie.requests[-1].headers["authorization"] == "Bearer api-key-marker"

async def test_other_user_cannot_use_session(http_app):
    async with http_app() as app:
        headers = await initialize(app.client, app.oidc.token())
        bob = app.oidc.token(sub="sub-bob", preferred_username="bob")
        before = len(app.mealie.requests)
        status, _ = await call_tool(app.client, headers, "get_recipes", token=bob)
        assert status == 404
        assert len(app.mealie.requests) == before

async def test_auth_logs_contain_no_tokens(http_app, caplog):
    with caplog.at_level(logging.DEBUG):
        async with http_app() as app:
            rejected, accepted = app.oidc.token(aud="other"), app.oidc.token()
            await app.client.post("/mcp", json=INITIALIZE, headers={"Authorization": f"Bearer {rejected}"})
            await call_tool(app.client, await initialize(app.client, accepted), "get_recipes")
    for secret in (rejected, accepted, "api-key-marker", "shared recipe", "sub-alice"):
        assert secret not in caplog.text
```

- [ ] **Step 3: Vérifier l'échec**

Run: `uv run pytest -q tests/test_server.py tests/test_auth_http.py`
Expected: FAIL (`ServerConfig` sans `auth`, aucun `401`).

- [ ] **Step 4: Implémenter** `AuthConfig.from_environment()`, `ServerConfig.auth`, le contrôle de transport, le branchement dans `_MealieServer.__init__` et la garde dans `_configure_optional_tools()`.

- [ ] **Step 5: Vérifier**

Run: `uv run ruff check src tests && uv run pytest -q`
Expected: tout vert sauf `test_readme_documents_every_environment_variable` (variables pas encore documentées).

- [ ] **Step 6: Documenter**

`README.md` : nouvelle section « Authentication (OAuth resource server) » après « Remote Access » : quand l'utiliser ; tableau des cinq variables `MCP_AUTH_*`/`MCP_PUBLIC_URL` ; exemple authentik (fournisseur confidentiel, URI de retour de claude.ai, portées `openid profile offline_access`, durée courte du jeton d'accès car les groupes y sont figés) ; défi `401` et adresse des métadonnées ; `streamable-http` seulement ; le serveur ne transmet jamais le jeton à Mealie. Remplacer la phrase « HTTP transports have no built-in authentication » par un renvoi à cette section. `.env.template` : variables commentées. `CHANGELOG.md`, `### Added`.

Run: `uv run pytest -q` → tout vert.

- [ ] **Step 7: Commit**

```bash
git add src tests README.md .env.template CHANGELOG.md
git commit -m "feat: add optional OAuth resource server authentication"
```

---

### Task 4: Échange « proxy de confiance » et clients par utilisateur

**Files:**
- Modify: `src/mealie/client.py`
- Create: `src/mealie/reverse_proxy.py`
- Modify: `tests/conftest.py` (`FakeMealie`)
- Test: `tests/test_reverse_proxy.py`, `tests/test_client.py`

**Interfaces:**
- Consumes: `FakeMealie` (tâche 3).
- Produces:
  - `check_mealie_health(http: httpx.Client) -> None` (dans `client.py`) : le bloc actuel de `MealieClient.__init__` (requête, `raise_for_status()`, traduction des erreurs, journal), sans fermer le client ; `MealieClient.__init__(self, base_url: str, api_key: str, *, check_health: bool = True)` l'appelle et ferme son client en cas d'échec, comme aujourd'hui.
  - `ReverseProxyConfig(secret: str = field(repr=False), user_header: str = "X-Forwarded-User", secret_header: str = "X-Mealie-Reverse-Proxy-Secret")`, gelée.
  - `MealieToken(access_token: str = field(repr=False), expires_at: float)`, gelée ; `expires_at` sur l'horloge du pool.
  - `MealieAccountUnavailable(ValueError)`, message fixe : `"Mealie account not found; sign in to Mealie once in a browser first"`.
  - `ReverseProxyFetcher(MealieFetcher)` : `__init__(self, base_url: str, username: str, exchange: Callable[[str], MealieToken])` (échange immédiat, `check_health=False`) ; attribut `expires_at: float` ; `_handle_request` : sur `MealieApiError` 401, un nouvel échange, mise à jour de l'en-tête `Authorization` et de `expires_at`, une seule nouvelle tentative.
  - `ReverseProxyClientPool(base_url: str, config: ReverseProxyConfig, *, max_clients: int = 256, expiry_margin: float = 300.0, clock: Callable[[], float] = time.monotonic)` : vérification de santé dans `__init__` (client jetable) ; `get(username: str) -> MealieFetcher` ; `close() -> None` ; `get()` après `close()` → `RuntimeError`.

Échange : `GET {base_url}/api/auth/reverse-proxy` par un `httpx.Client(base_url=…, timeout=30.0)` ouvert et fermé à chaque échange, en-têtes `{user_header: nom, secret_header: secret}` ; `200` avec `access_token` (chaîne non vide) et `expires_in` (entier > 0) → `MealieToken(access_token, clock() + expires_in - min(expiry_margin, expires_in / 2))` ; `401` → `MealieAccountUnavailable` ; autre statut → `MealieApiError(status, "Mealie reverse-proxy sign-in failed")` sans corps ; corps inattendu → `ValueError("Mealie reverse-proxy sign-in returned an unexpected response")` ; délai → `TimeoutError` ; connexion → `ConnectionError`. Journal d'échec : `{"operation": "Exchanging Mealie reverse-proxy token", "error_type", "status_code"}`. Cache : clé `username.strip().lower()` (envoyée telle quelle à Mealie), `OrderedDict` LRU sous un `threading.Lock` qui couvre aussi l'échange ; entrée expirée (`clock() >= expires_at`) fermée puis remplacée ; au-delà de `max_clients`, la plus ancienne est fermée.

`FakeMealie` gagne : `secret = "proxy-secret-marker"`, `user_header = "X-Forwarded-User"`, `secret_header = "X-Mealie-Reverse-Proxy-Secret"`, `accounts = {"alice", "bob"}`, `expires_in = 172800`, `exchange_status: int | None = None` (force le statut de l'échange), `exchanges: list[httpx.Request]` ; `revoke(user)` invalide les jetons déjà émis pour `user` ; `reject_all(user)` fait refuser par `/api/recipes` tous les jetons de `user`, futurs compris ; `user_of(request) -> str | None` rend le propriétaire du jeton porteur. Route `GET /api/auth/reverse-proxy` : secret faux ou compte inconnu → `401`, sinon jeton neuf `f"mealie-{user}-{n}"` (`n` global croissant) et `Set-Cookie: mealie.access_token=<jeton>`. `/api/recipes` accepte aussi les jetons valides émis par l'échange.

- [ ] **Step 1: Écrire les tests qui échouent** (`tests/test_reverse_proxy.py` ; fixtures locales `mealie` = `FakeMealie` installé par `install(monkeypatch)`, `now = [0.0]`, `pool` = `ReverseProxyClientPool("http://mealie.invalid", ReverseProxyConfig(mealie.secret), clock=lambda: now[0])`, fermé en fin de test)

```python
def test_exchange_sends_user_and_secret_headers(mealie, pool):
    pool.get("alice")
    request = mealie.exchanges[0]
    assert (request.method, request.url.path) == ("GET", "/api/auth/reverse-proxy")
    assert request.headers["x-forwarded-user"] == "alice"
    assert request.headers["x-mealie-reverse-proxy-secret"] == mealie.secret

def test_exchange_uses_configured_header_names(mealie):
    # FakeMealie configured to read "X-User"/"X-Secret"; pool with ReverseProxyConfig(secret, "X-User", "X-Secret")
    # → exchange succeeds and the default header names are absent

def test_unknown_account_raises_readable_error_and_is_not_cached(mealie):
    with pytest.raises(MealieAccountUnavailable, match="sign in to Mealie once"):
        pool.get("carol")
    with pytest.raises(MealieAccountUnavailable):
        pool.get("carol")
    assert len(mealie.exchanges) == 2

def test_exchange_server_error_has_status_without_body(mealie):  # exchange route → 503
    with pytest.raises(MealieApiError) as error:
        pool.get("alice")
    assert error.value.status_code == 503 and error.value.response_text is None

def test_client_is_reused_case_insensitively(mealie):
    assert pool.get("alice") is pool.get("Alice ")
    assert len(mealie.exchanges) == 1

def test_expired_client_is_replaced_and_closed(mealie):
    first = pool.get("alice"); now[0] += 172800 - 299
    second = pool.get("alice")
    assert second is not first and first._client.is_closed and len(mealie.exchanges) == 2

def test_unauthorized_call_reexchanges_once(mealie):
    fetcher = pool.get("alice"); mealie.revoke("alice")
    assert fetcher.get_recipes()["items"][0]["name"] == "alice recipe"
    assert len(mealie.exchanges) == 2
    mealie.reject_all("alice")   # every token for alice is refused, new ones too
    with pytest.raises(MealieApiError) as error:
        fetcher.get_recipes()
    assert error.value.status_code == 401 and len(mealie.exchanges) == 3

def test_two_users_never_share_tokens(mealie):
    alice, bob = pool.get("alice"), pool.get("bob")
    for fetcher in (alice, bob, alice, bob):
        fetcher.get_recipes()
    for request in (r for r in mealie.requests if r.url.path == "/api/recipes"):
        user = mealie.user_of(request)
        assert request.headers["authorization"].startswith(f"Bearer mealie-{user}-")

def test_exchange_does_not_forward_cookies(mealie):
    pool.get("alice"); pool.get("bob")
    assert "cookie" not in mealie.exchanges[1].headers

def test_least_recently_used_client_is_evicted_and_closed(mealie):
    # max_clients=1: alice = pool.get("alice"); pool.get("bob") → alice._client.is_closed;
    # pool.get("alice") is a new client and len(mealie.exchanges) == 3

def test_close_closes_every_client(mealie, pool):
    pool.get("alice"); pool.get("bob"); pool.close()
    assert all(client.is_closed for client in mealie.clients)
    with pytest.raises(RuntimeError):
        pool.get("alice")

def test_pool_startup_fails_on_unhealthy_mealie(mealie):
    mealie.health_status = 503
    with pytest.raises(httpx.HTTPStatusError):
        ReverseProxyClientPool("http://mealie.invalid", ReverseProxyConfig(mealie.secret))
    assert mealie.exchanges == [] and all(client.is_closed for client in mealie.clients)

def test_failures_log_no_username_secret_or_token(mealie, pool, caplog):
    # DEBUG; pool.get("carol") (401), then exchange_status=503 and pool.get("alice")
    for secret in ("carol", "alice", mealie.secret, "mealie-"):
        assert secret not in caplog.text
```

Dans `tests/test_client.py` :

```python
def test_client_can_skip_health_check(monkeypatch):
    # with httpx.Client patched to a MockTransport that records requests:
    client = MealieClient("http://mealie.invalid", "token", check_health=False)
    assert recorded == []
    client.close()
```

- [ ] **Step 2: Vérifier l'échec**

Run: `uv run pytest -q tests/test_reverse_proxy.py tests/test_client.py`
Expected: FAIL, `ModuleNotFoundError: No module named 'mealie.reverse_proxy'`.

- [ ] **Step 3: Implémenter** `check_mealie_health`, le paramètre `check_health`, puis `src/mealie/reverse_proxy.py`.

- [ ] **Step 4: Vérifier**

Run: `uv run ruff check src tests && uv run pytest -q`
Expected: tout vert (dont `tests/test_client.py` inchangé pour la vérification de santé).

- [ ] **Step 5: Commit**

```bash
git add src/mealie tests/conftest.py tests/test_reverse_proxy.py tests/test_client.py
git commit -m "feat: add per-user Mealie clients through reverse-proxy sign-in"
```

---

### Task 5: Mode `MEALIE_AUTH_MODE=reverse-proxy`

**Files:**
- Create: `src/mcp_auth/identity.py` (et export dans `src/mcp_auth/__init__.py`)
- Modify: `src/server.py`
- Modify: `tests/test_server.py`, `tests/test_auth_http.py`
- Modify: `README.md`, `.env.template`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `USERNAME_KEY` (tâche 2) ; `ServerConfig.auth`, `http_app`, `initialize`, `call_tool` (tâche 3) ; `ReverseProxyConfig`, `ReverseProxyClientPool`, `FakeMealie` étendu (tâche 4).
- Produces:
  - `current_username(server: FastMCP) -> str | None` : `server.get_context().request_context.request` (`ValueError` → `None`) ; requête nulle → `None` ; `request.scope.get("user")` doit être un `AuthenticatedUser` ; rend `access_token.claims[USERNAME_KEY]` si c'est une chaîne non vide, sinon `None`. N'utilise **pas** `get_access_token()` (voir § 10, point 2).
  - `ServerConfig` : `api_key: str | None` (toujours deuxième positionnel), `mealie_auth_mode: Literal["api-key", "reverse-proxy"] = "api-key"`, `reverse_proxy: ReverseProxyConfig | None = field(default=None, repr=False)`.
  - `_ClientProvider(config, current_username: Callable[[], str | None])` ; `acquire()` construit `MealieFetcher(base_url, api_key)` en mode `api-key`, `ReverseProxyClientPool(base_url, reverse_proxy)` en mode `reverse-proxy`, et ferme l'un ou l'autre quand le dernier utilisateur sort ; `__getattr__` en mode `reverse-proxy` : nom absent → `RuntimeError("Mealie tools require an authenticated user")`, sinon `getattr(pool.get(nom), attribut)`. Jamais de repli sur un autre client.

Règles ajoutées à `ServerConfig.from_environment()` : `MEALIE_AUTH_MODE` (`strip().lower()`, défaut `api-key`) hors des deux valeurs → `ValueError` ; `api-key` : règle actuelle de `MEALIE_API_KEY` ; `reverse-proxy` : `MEALIE_API_KEY` ignorée, authentification obligatoire (`ValueError` nommant `MCP_AUTH_ISSUER`), `MEALIE_REVERSE_PROXY_SECRET` non vide obligatoire, en-têtes non vides.

- [ ] **Step 1: Écrire les tests de configuration qui échouent** (`tests/test_server.py`)

```python
RP_ENV = {**AUTH_ENV, "MEALIE_AUTH_MODE": "reverse-proxy", "MEALIE_REVERSE_PROXY_SECRET": "secret-marker"}

@pytest.mark.parametrize(("env", "message"), [
    ({"MEALIE_AUTH_MODE": "proxy"}, "MEALIE_AUTH_MODE"),
    ({"MEALIE_AUTH_MODE": "reverse-proxy", "MEALIE_REVERSE_PROXY_SECRET": "secret-marker",
      "MCP_TRANSPORT": "streamable-http"}, "MCP_AUTH_ISSUER"),
    ({**RP_ENV, "MEALIE_REVERSE_PROXY_SECRET": ""}, "MEALIE_REVERSE_PROXY_SECRET"),
    ({**RP_ENV, "MEALIE_REVERSE_PROXY_USER_HEADER": " "}, "MEALIE_REVERSE_PROXY_USER_HEADER"),
])
def test_invalid_reverse_proxy_configuration_fails_before_http_allocation(load_server, monkeypatch, env, message):
    # same body as test_invalid_auth_configuration_fails_before_http_allocation,
    # plus: assert "secret-marker" not in str(error.value)

def test_reverse_proxy_configuration_without_api_key(load_server, monkeypatch):
    # RP_ENV, MEALIE_API_KEY deleted
    config = ServerConfig.from_environment()
    assert config.mealie_auth_mode == "reverse-proxy" and config.api_key is None
    assert config.reverse_proxy == ReverseProxyConfig("secret-marker")
    assert "secret-marker" not in repr(config)

def test_api_key_mode_is_the_default(load_server):
    assert ServerConfig.from_environment().mealie_auth_mode == "api-key"
```

- [ ] **Step 2: Écrire les tests de bout en bout qui échouent** (`tests/test_auth_http.py`, `RP = {"MEALIE_AUTH_MODE": "reverse-proxy", "MEALIE_REVERSE_PROXY_SECRET": "proxy-secret-marker"}`)

```python
async def test_each_user_reaches_mealie_as_themselves(http_app):
    async with http_app(**RP) as app:
        alice = await initialize(app.client, app.oidc.token())
        bob = await initialize(app.client, app.oidc.token(sub="sub-bob", preferred_username="bob"))
        calls = [call_tool(app.client, alice if i % 2 == 0 else bob, "get_recipes") for i in range(20)]
        results = await asyncio.gather(*calls)
        for i, (status, result) in enumerate(results):
            assert status == 200
            assert ("alice recipe" if i % 2 == 0 else "bob recipe") in json.dumps(result)
        assert len(app.mealie.exchanges) == 2

async def test_refreshed_token_keeps_session_and_identity(http_app):
    async with http_app(**RP) as app:
        headers = await initialize(app.client, app.oidc.token(jti="first"))
        status, result = await call_tool(app.client, headers, "get_recipes",
                                         token=app.oidc.token(jti="second"))
        assert status == 200 and "alice recipe" in json.dumps(result)

async def test_unknown_mealie_account_gets_readable_tool_error(http_app):
    async with http_app(**RP) as app:
        headers = await initialize(app.client, app.oidc.token(sub="sub-carol", preferred_username="carol"))
        status, result = await call_tool(app.client, headers, "get_recipes")
        assert status == 200 and result["isError"] is True
        assert "sign in to Mealie once" in result["content"][0]["text"]

async def test_tools_refuse_without_authenticated_user(http_app):
    async with http_app(**RP) as app:   # call outside any HTTP request: no user
        with pytest.raises(ToolError, match="authenticated user"):
            await app.server.call_tool("get_recipes", {})
        assert app.mealie.exchanges == []

async def test_reverse_proxy_startup_rejects_failed_health_check(http_app):
    with pytest.raises(httpx.HTTPStatusError):
        async with http_app(mealie_health=503, **RP):
            pytest.fail("Unhealthy startup must not enter the running lifespan")

async def test_reverse_proxy_logs_contain_no_identity_or_secret(http_app, caplog):
    # DEBUG; alice calls get_recipes, carol (unknown in Mealie) calls get_recipes
    for secret in ("proxy-secret-marker", "mealie-alice", "alice recipe", "alice", "carol",
                   *issued_oidc_tokens):
        assert secret not in caplog.text
```

- [ ] **Step 3: Vérifier l'échec**

Run: `uv run pytest -q tests/test_server.py tests/test_auth_http.py`
Expected: FAIL (`MEALIE_AUTH_MODE` inconnu, appels faits avec la clé d'API).

- [ ] **Step 4: Implémenter** `current_username`, les champs et règles de `ServerConfig`, puis `_ClientProvider` (le constructeur de `_MealieServer` lui passe `lambda: current_username(self)`).

- [ ] **Step 5: Vérifier**

Run: `uv run ruff check src tests && uv run pytest -q`
Expected: tout vert sauf `test_readme_documents_every_environment_variable`.

- [ ] **Step 6: Documenter**

`README.md`, nouvelle sous-section « Acting as each user (Mealie reverse-proxy sign-in) » : principe (nom tiré du jeton, échange contre un jeton Mealie de l'utilisateur, jeton de l'IdP jamais transmis) ; tableau des quatre variables `MEALIE_AUTH_MODE`, `MEALIE_REVERSE_PROXY_*` ; réglages Mealie (`REVERSE_PROXY_AUTH_ENABLED=true`, `REVERSE_PROXY_AUTH_SIGNUP_ENABLED=false`, `REVERSE_PROXY_AUTH_SECRET`) ; avertissements : le secret permet d'agir au nom de n'importe quel compte, fermer `/api/auth/reverse-proxy` au proxy public, comptes Mealie créés par une première connexion au site, cache en mémoire (256 clients, renouvelé avant l'expiration). Tableau « Configuration » : `MEALIE_API_KEY` « Required in `api-key` mode ». `.env.template`, `CHANGELOG.md` (`### Added`).

Run: `uv run pytest -q` → tout vert.

- [ ] **Step 7: Commit**

```bash
git add src tests README.md .env.template CHANGELOG.md
git commit -m "feat: add reverse-proxy mode to call Mealie as each user"
```

---

### Task 6: CI du fork — publication de l'image après tests verts

**Files:**
- Create: `.github/workflows/publish-image.yml`

**Interfaces:**
- Consumes: le workflow `CI` de l'amont (`.github/workflows/ci.yml`, inchangé).
- Produces: `ghcr.io/perkasthor/mealie-mcp-server:<sha complet du commit>`, `linux/amd64`.

Contenu imposé :

- `on: workflow_run: { workflows: [CI], types: [completed], branches: [main] }` ;
- job `publish` : `if: github.repository == 'perkasthor/mealie-mcp-server' && github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'` ; `permissions: { contents: read, packages: write }` ;
- étapes : `actions/checkout@v6` avec `ref: ${{ github.event.workflow_run.head_sha }}` ; `docker/setup-buildx-action@v4` ; `docker/login-action@v4` (`registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`) ; `docker/build-push-action@v7` avec `context: .`, `platforms: linux/amd64`, `push: true`, `tags: ghcr.io/perkasthor/mealie-mcp-server:${{ github.event.workflow_run.head_sha }}`, `labels: org.opencontainers.image.source=https://github.com/perkasthor/mealie-mcp-server`.

Le `Dockerfile` de l'amont n'est pas modifié.

- [ ] **Step 1: Écrire le workflow**

- [ ] **Step 2: Le valider**

Run: `docker run --rm -v "${PWD}:/repo" -w /repo rhysd/actionlint:latest -color`
Expected: aucune sortie, code 0.

Run: `docker build --platform linux/amd64 -t mealie-mcp-server:local .`
Expected: image construite.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/publish-image.yml
git commit -m "ci: publish fork image to ghcr.io after green CI on main"
```

Gestes manuels du propriétaire, après le premier push : activer GitHub Actions sur le fork (désactivées par défaut sur un fork) ; après la première publication, passer le paquet `mealie-mcp-server` en visibilité **publique** (conception § 3).

---

## Vérification finale

- [ ] `uv run ruff check src tests` et `uv run pytest -q -W error::DeprecationWarning` : verts.
- [ ] Sans aucune variable nouvelle, `tests/test_server.py` d'origine passe sans modification de ses assertions (comportement de l'amont).
- [ ] `git grep -n "get_access_token" src` : aucun résultat.
- [ ] Revue de toute la branche (superpowers:requesting-code-review), avec les cinq points de « Review Focus ».
- [ ] Pour la PR vers l'amont, plus tard : branche dédiée depuis `main` de l'amont, commits des tâches 1 à 5 seulement (ni ce plan, ni `publish-image.yml`).
