# iLogistic MCP (Cloudflare Worker)

Remote MCP server (Streamable HTTP, stateless) az [iLogistic API](https://api.ilogistic.eu/documentation/) fölött: rendelések, termékek, bevételezés. Ingyenes Cloudflare Workers csomagon fut, Durable Object nélkül.

**Több bolt, egy endpoint:** minden kliens a saját iLogistic tokenjét küldi az `X-iLogistic-Token` fejlécben, a Workerben nincs bolt-specifikus token. A Worker a megújított tokent boltonként, titkosítva tárolja, és maga frissíti, így a kliens fejlécét nem kell cserélgetni (lásd [Több bolt](#több-bolt-x-ilogistic-token)).

> **Állapot:** a kód típusellenőrzött, 39 teszt fut rajta, és a Worker élesben fut, de **valódi iLogistic tokennel még nem lett kipróbálva** (nem volt még hozzáférés a platformhoz). A token-megújítás és a boolean szűrők (`0/1`) viselkedése az első valódi hívásig ellenőrizetlen.

## Mi kell az iLogistic oldalról

1. **Aktív iLogistic fiók.** Az [iLogistic dokumentáció](https://api.ilogistic.eu/documentation/docs/intro-api) szerint regisztráció után az "Első lépések" szakaszt kell végigcsinálni, majd egy iLogistic admin aktiválja a felhasználót. Aktiválás nélkül az API nem használható.
2. **Bearer token (JWT)** a fiókhoz. A token generálását a [hivatalos auth leírás](https://api.ilogistic.eu/documentation/authentication) részletezi. Ezt a token-t a kliens az `X-iLogistic-Token` fejlécben küldi (boltonként a sajátját). Egyetlen bolt esetén szerver oldalon is megadható `ILOGISTIC_TOKEN` secretként, ez a tartalék, ha a kérés nem hoz fejlécet.
3. **Környezet:** éles `https://api.ilogistic.eu`, staging `https://devapi.ilogistic.eu` (sandbox regisztráció: <https://dev.ilogistic.eu>). A `wrangler.jsonc` `ILOGISTIC_BASE_URL` értéke dönti el, melyiket használja a Worker (alapérték: éles).
4. **Termékek előre létezzenek.** Rendelés csak már felvett, aktív `itemNumber`-ekre adható le (a `ilogistic_create_product` is felvehet újat).
5. **Token élettartam:** a JWT 7 napig érvényes, utána 120 mp-es ablakban lehet újat kérni (`GET /authentication/auth`). A Worker óránként cronnal megpróbálja megújítani, ha a token legalább `TOKEN_REFRESH_AFTER_HOURS` (alapérték 144 = 6 nap) órás, az újat KV-ban tárolja (régebbi tokennel sosem írja felül az újabbat). Upstream 401-re előbb a KV-ban lévő újabb tokennel próbálkozik, csak utána kér újat. Bármely sikertelen megújítás után 5 percig nem próbálkozik újra, így halott tokennél sincs hívásvihar. A cron minden futáskor logolja a token állapotát: `token_expiring` (24 óránál kevesebb van hátra), `token_expired`, `token_unreadable` error szinten, erre érdemes riasztást állítani a Cloudflare Workers Observability-ben. **Ellenőrizetlen:** a dokumentáció nem írja le, pontosan mikor ad az API új tokent. Ha csak a lejárat körüli rövid ablakban, az óránkénti cron kevés lehet. Ha a token a leeway után is lejárt, a kliensnek új tokent kell küldeni (új `X-iLogistic-Token`, ill. egy-boltos módban az `ILOGISTIC_TOKEN` secret cseréje). A `ilogistic_check_connection` tool megmutatja a hátralévő időt.
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
- **Csak HTTPS**: titkosítatlan `http://` kérésre 403 (nincs átirányítás, hogy a rosszul beállított kliens ne küldje csendben, titkosítatlanul a kulcsot), `Strict-Transport-Security` fejléc; `wrangler dev` (localhost) kivétel.
- Csak `POST /mcp`, 256 KiB body limit (bájtban mérve, chunked body-ra is), `application/json` kötelező, szigorú zod validáció (pozitív egész ID-k, enum-ok, hossz-limitek), nincs szabad path/URL paraméter (nincs SSRF), upstream redirect nem követett (a token nem megy máshova).
- **iLogistic token** csak a kérés fejlécében érkezik, a KV-ban AES-256-GCM-mel titkosítva (`TOKEN_ENC_KEY`), sosem kerül logba vagy tool-válaszba. A bolt azonosítója `sha256(MCP kulcs neve + token)`, így egy kiszivárgott iLogistic token önmagában, MCP kulcs nélkül nem ér el semmit. Audit log: kulcs neve, tool, kimenet, idő; a tool argumentumokat (ügyfél PII) nem logoljuk.
- **PII-szűrés (GDPR)**: minden tool-válasz átmegy a `src/pii.ts` szűrőn. A rendelések `delivery`/`billing` blokkjából a név, telefonszám és utcacím kikerül, az e-mail maszkolva (`b*****8@gmail.com`), csak ország, irányítószám, település, futárcég és csomagpont-azonosító marad. Allowlist alapú: az ismeretlen új mezők is kiesnek.
- A tool válaszok max. 100 000 karakteresek; a szerver `instructions`-e jelzi, hogy a rendelés-mezők nem megbízható adatok (prompt injection ellen).

## Telepítés (Cloudflare)

```bash
npm install
npx wrangler login

# 1. MCP API kulcs(ok). A script a kulcsok hash-listáját a gitignore-olt ./mcp-keys.local fájlban vezeti,
#    a --push a TELJES listát feltölti az MCP_API_KEYS secretbe (nem kell kézzel összeállítani).
#    A nyers kulcsot egyszer írja ki: ezt add a kliensnek.
npm run gen-key -- admin read,write,delete --push
npm run gen-key -- ugyfel-neve read --push   # újabb ügyfél
npm run gen-key -- revoke ugyfel-neve --push # kizárás
npm run gen-key -- list

# 2. Secretek
head -c 32 /dev/urandom | base64 | npx wrangler secret put TOKEN_ENC_KEY   # a bolt-tokenek titkosító kulcsa
# opcionális, csak egy-boltos tartalék: npx wrangler secret put ILOGISTIC_TOKEN

# 3. Deploy (a KV namespace-t a wrangler automatikusan létrehozza)
npx wrangler deploy
```

Írás/törlés bekapcsolása: `wrangler.jsonc` → `"WRITES_ENABLED": "true"`, majd `npx wrangler deploy`. A kulcsnak emellett rendelkeznie kell a `write`/`delete` scope-pal.

A Worker címe: `https://ilogistic-mcp.<cloudflare-subdomain>.workers.dev/mcp`

## Kliensek beállítása

Az auth statikus Bearer API-kulcs, ezért ma azok a kliensek használhatják, amelyek tudnak egyedi fejléceket küldeni. Minden kliens két fejlécet ad: `Authorization: Bearer <MCP API key>` és `X-iLogistic-Token: <a bolt iLogistic tokenje>`.

### Claude Code (működik)

```bash
claude mcp add --transport http ilogistic https://ilogistic-mcp.<subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <MCP API key>" \
  --header "X-iLogistic-Token: <iLogistic token>"
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
               "--header", "Authorization:${AUTH}",
               "--header", "X-iLogistic-Token:${SHOP_TOKEN}"],
      "env": { "AUTH": "Bearer <MCP API key>", "SHOP_TOKEN": "<iLogistic token>" }
    }
  }
}
```

### ChatGPT / Codex app (működik)

Az app Plugins → **MCPs** → *Connect to a custom MCP* űrlapja egyedi fejlécet is tud (ez nem a webes ChatGPT connector):

- **Name:** `iLogistics`, **Type:** `Streamable HTTP`, **URL:** `https://ilogistic-mcp.<subdomain>.workers.dev/mcp`
- **Headers** (Add header, kétszer): `Authorization` = `Bearer <MCP API key>` és `X-iLogistic-Token` = `<a bolt iLogistic tokenje>`
- A "Bearer token env var" mezőt hagyd üresen (az egy környezeti változó *nevét* várja, amit a GUI app nem örököl a shelltől).

Ellenőrzés: egy új szálban az `ilogistic_check_connection` tool.

### claude.ai (web) és webes ChatGPT connector: egyelőre nem támogatott

Mindkettő a custom connectorhoz (claude.ai: Settings → Connectors → Add custom connector; ChatGPT: Settings → Connectors → Advanced → Developer mode → új connector) **OAuth-ot vagy hitelesítés nélküli szervert** vár, statikus Bearer fejlécet nem tud küldeni (ChatGPT-nél a forrásaim szerint API-kulcsos auth nem támogatott; ezt nem teszteltem). Ezeknél a Worker jelenlegi auth modellje nem használható.

Hitelesítés nélkül **nem** érdemes megnyitni: a szerver éles rendelési és ügyféladatokhoz fér hozzá. A járható út az OAuth réteg hozzáadása (Cloudflare `workers-oauth-provider` + egy IdP, pl. GitHub vagy Google, felhasználó-allowlisttel). Ez a következő fejlesztési lépés, ha ezekből a kliensekből is kell.

## Több bolt (`X-iLogistic-Token`)

Egy Worker, egy MCP endpoint, tetszőleges számú iLogistic bolt. Minden kliens a saját tokenjét küldi a fejlécben, a Workerben nincs bolt-specifikus beállítás.

- **Első hívás:** a Worker csak akkor tárolja el a tokent (titkosítva, `ten:<azonosító>` KV kulcs), ha az iLogistic elfogadta (sikeres válasz vagy sikeres megújítás). Kitalált vagy lejárt token nem kerül KV-ba, és `iat` nélküli token már a fejlécnél 400-at kap. Onnantól a tárolt, mindig legfrissebb tokent használja.
- **Megújítás:** óránként a cron (és upstream 401-re a kérés is) lecseréli a tokent az iLogistic `GET /authentication/auth` hívásával, a megújított tokent a bolt rekordjába írja. **A kliens fejlécét nem kell cserélni**, amíg a lánc él. A cron a lejárathoz legközelebbi tokeneket frissíti először, futásonként fix KV-kerettel (az ingyenes csomag 50 subrequest/futás limitje miatt); ami nem fér bele, a következő órában jön, `tenant_refresh_backlog` loggal.
- **Maximális élettartam:** egy lánc az első tokentől számítva `TENANT_MAX_AGE_DAYS` napig (alapérték 30) él, utána törlődik, és a kliensnek friss iLogistic tokent kell küldenie. Így egy régi, kiszivárgott token sem ad korlátlan hozzáférést.
- **Token csere = a régi visszavonása:** ha egy bolt ugyanazzal az MCP kulccsal új iLogistic tokent kezd küldeni (ugyanaz az iLogistic felhasználó, a token `email` claimje alapján), a Worker a régi lánco(ka)t törli. Kiszivárgott token esetén: kérj új tokent az iLogisticből, és tedd be a kliens fejlécébe. Ezért egy boltnál, egy MCP kulccsal minden kliensben ugyanazt a tokent használd (vagy kliensenként külön MCP kulcsot).
- **Kulcs visszavonása:** a bolt azonosítója az MCP kulcs hash-éhez kötött (nem a nevéhez). `npm run gen-key -- revoke <név> --push` után a kulcs rekordjait a következő óránkénti cron törli, és egy azonos néven újra kiadott kulcs sem éri el őket.
- **Lejárt, nem helyreállítható token** (a 120 mp-es leeway után): a rekord törlődik (`tenant_token_expired` log), a kliensnek új tokent kell küldenie. `tenant_token_expiring` jelzi, ha egy tokent 24 órán belül nem sikerült megújítani.
- **Takarítás:** 90 napja nem használt bolt rekordja törlődik (a „utoljára használt” időpont külön KV kulcsban van, így a frissítése sosem írhatja felül a tokent).
- **Tartalék token (`ILOGISTIC_TOKEN`):** fejléc nélkül csak az `--fallback` kapcsolóval létrehozott kulcsok használhatják (`npm run gen-key -- sajat read --fallback --push`). Ügyfélkulcsnak ezt ne add: az a tartalék bolt adataihoz férne hozzá.
- Hiányzó `TOKEN_ENC_KEY` esetén a fejléc használata 503, hibás formátum 400. Fejléc nélkül, tartalék nélkül a tool-ok érthető 503-at adnak.

## Fejlesztés

`.dev.vars` fájlba ugyanazok a secretek, majd `npm run dev` (http://localhost:8787/mcp). Tesztek: `npm test`, típusellenőrzés: `npm run typecheck`.
