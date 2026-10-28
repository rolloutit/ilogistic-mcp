# iLogistic MCP (Cloudflare Worker)

Remote MCP server (Streamable HTTP, stateless) az [iLogistic API](https://api.ilogistic.eu/documentation/) fölött: rendelések, termékek, bevételezés. Ingyenes Cloudflare Workers csomagon fut, Durable Object nélkül.

> **Állapot:** a kód típusellenőrzött, 23 teszt fut rajta, és a Worker élesben fut, de **valódi iLogistic tokennel még nem lett kipróbálva** (nem volt még hozzáférés a platformhoz). A token-megújítás és a boolean szűrők (`0/1`) viselkedése az első valódi hívásig ellenőrizetlen.

## Mi kell az iLogistic oldalról

1. **Aktív iLogistic fiók.** Az [iLogistic dokumentáció](https://api.ilogistic.eu/documentation/docs/intro-api) szerint regisztráció után az "Első lépések" szakaszt kell végigcsinálni, majd egy iLogistic admin aktiválja a felhasználót. Aktiválás nélkül az API nem használható.
2. **Bearer token (JWT)** a fiókhoz. A token generálását a [hivatalos auth leírás](https://api.ilogistic.eu/documentation/authentication) részletezi. Ez kerül az `ILOGISTIC_TOKEN` secretbe.
3. **Környezet:** éles `https://api.ilogistic.eu`, staging `https://devapi.ilogistic.eu` (sandbox regisztráció: <https://dev.ilogistic.eu>). A `wrangler.jsonc` `ILOGISTIC_BASE_URL` értéke dönti el, melyiket használja a Worker (alapérték: éles).
4. **Termékek előre létezzenek.** Rendelés csak már felvett, aktív `itemNumber`-ekre adható le (a `ilogistic_create_product` is felvehet újat).
5. **Token élettartam:** a JWT 7 napig érvényes, utána 120 mp-es ablakban lehet újat kérni (`GET /authentication/auth`). A Worker óránként cronnal megpróbálja megújítani, ha a token legalább `TOKEN_REFRESH_AFTER_HOURS` (alapérték 144 = 6 nap) órás, az újat KV-ban tárolja (régebbi tokennel sosem írja felül az újabbat). Upstream 401-re előbb a KV-ban lévő újabb tokennel próbálkozik, csak utána kér újat. Bármely sikertelen megújítás után 5 percig nem próbálkozik újra, így halott tokennél sincs hívásvihar. A cron minden futáskor logolja a token állapotát: `token_expiring` (24 óránál kevesebb van hátra), `token_expired`, `token_unreadable` error szinten, erre érdemes riasztást állítani a Cloudflare Workers Observability-ben. **Ellenőrizetlen:** a dokumentáció nem írja le, pontosan mikor ad az API új tokent. Ha csak a lejárat körüli rövid ablakban, az óránkénti cron kevés lehet. Ha a token a leeway után is lejárt, az `ILOGISTIC_TOKEN` secretet kézzel kell cserélni. A `ilogistic_check_connection` tool megmutatja a hátralévő időt.
6. API limit: 100 kérés/mp.

Az API OpenAPI specifikációi publikusak: `https://api.ilogistic.eu/documentation/config/{orders,products,bevetelezes,authentication}.yaml`. A fájlokat szerzői jogi okból nem tároljuk a repóban.

## Tool-ok (18)

| Scope | Tool-ok |
|---|---|
| `read` | `ilogistic_reference`, `ilogistic_check_connection`, `list_orders`, `get_order`, `get_order_status_history`, `get_resent_order`, `list_products`, `get_product`, `list_inward_handlings`, `get_inward_handling` |
| `write` | `create_order`, `update_order`, `create_product`, `update_product`, `create_inward_handling`, `update_inward_handling` |
| `delete` | `delete_order`, `delete_inward_handling` (kötelező `confirm: true`) |

(A nevek `ilogistic_` előtaggal kezdődnek.)

## Biztonsági modell

- **Auth**: `Authorization: Bearer <API key>`. A Workerben csak a kulcsok SHA-256 hash-e van (`MCP_API_KEYS` secret), konstans idejű összehasonlítással. Hibás/hiányzó konfig = minden kérés 401.
- **Scope-ok kulcsonként** (`read`/`write`/`delete`): amit a kulcs nem használhat, az a tool nem is jelenik meg a `tools/list`-ben.
- **`WRITES_ENABLED=false` az alapértelmezés**: amíg nem kapcsolod be, egyetlen write/delete tool sincs regisztrálva. Éles webshopnál először csak olvasással próbálj.
- **Rate limit** (Workers Rate Limiting binding): 10 sikertelen auth/perc/IP, 60 kérés/perc/kulcs, 20 írás/perc/kulcs.
- **Origin ellenőrzés**: böngészős `Origin` csak az `ALLOWED_ORIGINS` listából; MCP kliensek nem küldenek Origin-t.
- Csak `POST /mcp`, 256 KiB body limit (bájtban mérve, chunked body-ra is), `application/json` kötelező, szigorú zod validáció (pozitív egész ID-k, enum-ok, hossz-limitek), nincs szabad path/URL paraméter (nincs SSRF), upstream redirect nem követett (a token nem megy máshova).
- **iLogistic token** kizárólag secret/KV-ban, sosem kerül logba vagy tool-válaszba. Audit log: kulcs neve, tool, kimenet, idő; a tool argumentumokat (ügyfél PII) nem logoljuk.
- **PII-szűrés (GDPR)**: minden tool-válasz átmegy a `src/pii.ts` szűrőn. A rendelések `delivery`/`billing` blokkjából a név, telefonszám és utcacím kikerül, az e-mail maszkolva (`b*****8@gmail.com`), csak ország, irányítószám, település, futárcég és csomagpont-azonosító marad. Allowlist alapú: az ismeretlen új mezők is kiesnek.
- A tool válaszok max. 100 000 karakteresek; a szerver `instructions`-e jelzi, hogy a rendelés-mezők nem megbízható adatok (prompt injection ellen).

## Telepítés (Cloudflare)

```bash
npm install
npx wrangler login

# 1. MCP API kulcs(ok). A nyers kulcsot a kliensbe tedd, a JSON entry-t a secretbe.
npm run gen-key -- claude-code read          # csak olvasás
npm run gen-key -- admin read,write,delete   # teljes

# 2. Secretek (MCP_API_KEYS = a gen-key által kiírt entry-kből álló JSON tömb)
npx wrangler secret put MCP_API_KEYS      # pl. [{"name":"claude-code","sha256":"...","scopes":["read"]}]
npx wrangler secret put ILOGISTIC_TOKEN   # az iLogistic bearer token

# 3. Deploy (a KV namespace-t a wrangler automatikusan létrehozza)
npx wrangler deploy
```

Írás/törlés bekapcsolása: `wrangler.jsonc` → `"WRITES_ENABLED": "true"`, majd `npx wrangler deploy`. A kulcsnak emellett rendelkeznie kell a `write`/`delete` scope-pal.

A Worker címe: `https://ilogistic-mcp.<cloudflare-subdomain>.workers.dev/mcp`

## Kliensek beállítása

Az auth statikus Bearer API-kulcs, ezért ma azok a kliensek használhatják, amelyek tudnak egyedi `Authorization` fejlécet küldeni.

### Claude Code (működik)

```bash
claude mcp add --transport http ilogistic https://ilogistic-mcp.<subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <API key>"
claude mcp list        # ellenőrzés
```

Alapból csak a saját projekthez (`local` scope) kerül be; `--scope user` az összes projektre, `--scope project` a repóban lévő `.mcp.json`-ba (ide kulcsot ne írj, használd a `${ILOGISTIC_MCP_KEY}` környezeti változós formát). Claude Code-on belül a `/mcp` mutatja az állapotot.

### Claude Desktop (működik, `mcp-remote` hídon át)

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ilogistic": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://ilogistic-mcp.<subdomain>.workers.dev/mcp",
               "--header", "Authorization:${AUTH}"],
      "env": { "AUTH": "Bearer <API key>" }
    }
  }
}
```

### claude.ai (web) és ChatGPT: egyelőre nem támogatott

Mindkettő a custom connectorhoz (claude.ai: Settings → Connectors → Add custom connector; ChatGPT: Settings → Connectors → Advanced → Developer mode → új connector) **OAuth-ot vagy hitelesítés nélküli szervert** vár, statikus Bearer fejlécet nem tud küldeni (ChatGPT-nél a forrásaim szerint API-kulcsos auth nem támogatott; ezt nem teszteltem). Ezeknél a Worker jelenlegi auth modellje nem használható.

Hitelesítés nélkül **nem** érdemes megnyitni: a szerver éles rendelési és ügyféladatokhoz fér hozzá. A járható út az OAuth réteg hozzáadása (Cloudflare `workers-oauth-provider` + egy IdP, pl. GitHub vagy Google, felhasználó-allowlisttel). Ez a következő fejlesztési lépés, ha ezekből a kliensekből is kell.

## Fejlesztés

`.dev.vars` fájlba ugyanazok a secretek, majd `npm run dev` (http://localhost:8787/mcp). Tesztek: `npm test`, típusellenőrzés: `npm run typecheck`.
