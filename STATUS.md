# Umbra — stav vývoje

Poctivý přehled: co je **ověřené** (běží + testy) vs. **napsané, ale neověřené**.
Datum: 2026-07-25.

## ✅ Ověřeno (kód + procházející testy)

| Část | Co dělá | Důkaz |
|---|---|---|
| `core::crypto::padding` | skrývání délky (1 znak = 256 B rámec) | 9 testů |
| `core::crypto::keystore` | secrets v klidu: Argon2id + XChaCha20-Poly1305 | 8 testů |
| `core::identity` | Ed25519 účet, podepsaný odvolatelný roster, uživatelské kódy | 11 testů |
| `core::invite` | pozvánka `umbra1:` (klíč + onion + username, checksum) | 6 testů |
| `core::crypto::ratchet` | E2E Double Ratchet (vodozemac) + bajtové API | 4 testy |
| `core::store` | šifrovaná lokální SQLite (vč. skupin a jejich historie) | 8 testů |
| `core::group` | skupinový roster: verzování, přidání/odebrání, merge | 5 testů |
| `core::envelope` | rámce vč. `GROUP_TEXT` / `GROUP_INFO` (roster = pozvánka) | 7 testů |
| `transport` (session) | MITM-odolný handshake + rámcování + obousměrné zprávy | 2 testy |
| **umbra-chat (CLI)** | **dva procesy si píšou E2E-šifrovaně přes TCP** | ruční, ověřeno |
| **GUI ↔ jádro** | onboarding tvoří reálný klíč, šifrovaná perzistence, odemknutí frází | ruční, ověřeno |

**58 automatických testů, 0 fail.** Vše audited open-source crates, žádné domácí krypto.

## 👥 Skupinové chaty — napsané, end-to-end zatím neověřené

Skupina = **společný roster**, zpráva se rozešle přes existující 1:1 kanály
(každý hop plné E2E + onion). Roster (`GROUP_INFO`) je zároveň pozvánka: kdo ho
dostane pro neznámou skupinu, tím je do ní přidán.

- ✅ jádro: roster, verzování, merge, šifrované uložení skupin i historie (13 testů)
- ✅ Rust API: `create_group`, `add_group_member`, `leave_group`,
  `send_group_message`, `list_group*`; příjem ukládá přímo v Rustu
- ✅ příchozí roster se přijme **jen od člena** skupiny; zpráva jen od člena;
  vypadnutí z rosteru = skupina se lokálně smaže
- ✅ GUI: skupiny v seznamu chatů, vytvoření z kontaktů, přidání člena, odchod,
  jméno pisatele u přijatých zpráv
- ⏳ **neotestováno mezi dvěma reálnými uzly přes Tor** (potřebuje dva počítače)
- ⏳ soubory do skupiny zatím nejdou (jen text)
- ⚠️ roster je plochý — každý člen může přejmenovat/přidat/odebrat; podepsané
  a seřazené změny členství jsou plánované (viz `docs/THREAT_MODEL.md`)

## 🧅 Tor onion transport (`transport::ctor`) — částečně ověřeno

Pohání ho **oficiální `tor` démon** (přibalený `tor.exe`), stejně jako to dělá
Briar a OnionShare. Arti (Tor v Rustu) byl **zavržen**: na Windows se při
bootstrapu zablokoval (naplánované časovače přestaly běžet, consensus nikdy
nedorazil), zatímco C-Tor přes tytéž mosty naběhl na 100 %.

Ověřeno na této (cenzurované) síti — **kompletní řetěz funguje**:
- ✅ Tor **naběhne na 100 %** přes obfs4/snowflake mosty
- ✅ vlastní **v3 onion service** se vytvoří a **publikuje**
- ✅ **spojení mezi dvěma uzly** přes Tor navázáno a **handshake ověřen**
- ✅ **doručení zprávy**: GUI aplikace → Tor → onion → druhý uzel, rozšifrováno správně
  (24. 7. 2026, zpráva „hello world" prošla celým řetězem)

Opravy nalezené během testování (všechny v kódu):
- Torův stdout se musí číst po celou dobu běhu, jinak se pipe zaplní a démon zamrzne
- `__OwningControllerProcess` — Tor se ukončí s aplikací, žádní sirotci držící zámek
- protokolové magic `UMB1` od iniciátora: rendezvous stream se rozjede až po prvním
  datovém paketu od klienta, protokol „responder mluví první" jinak uvázne
- velkorysé timeouty (bootstrap 15 min, spojení 3 min) — přes mosty je vše pomalé

## 🎨 GUI (25. 7. 2026)
- **barevné motivy**: 6 hotových (Mátový, Modrý, Fialový, Jantarový, Růžový,
  Denní/světlý) + **vlastní barva** (odstín + sytost, z ní se odvodí celá paleta).
  Volba se pamatuje v `theme.txt` u dat aplikace. Paleta je runtime (`UmbraTheme`
  → `UmbraColors`), takže se překreslí celá appka.
- **Zařízení** přesunuta z levého railu do **Nastavení** (otevřou se na kliknutí).
- **Spouštět s Windows**: přepínač v Nastavení, zapisuje `HKCU\...\Run` přes
  `reg.exe` (bez admina, uživatel to umí sám zrušit). Přepínač se řídí reálným
  stavem registru — když zápis selže, skočí zpět a řekne to.

## 📦 Distribuce
`dist/Umbra.zip` (62 MB) — hotový balíček k odeslání: `umbra.exe` + knihovny,
**`tor.exe`**, `lyrebird.exe` (obfs4/snowflake), `bridges.txt` (oficiální mosty
Tor Browseru), `umbra-diagnostika.exe` a `CTI-MNE.txt` s návodem.

## ⏳ Známá omezení
- **Oba musí být online zároveň** — bez serveru neexistuje doručení „na později".
- Skupiny: jen text, plochý roster, neověřeno mezi dvěma uzly (viz výše).
- Onion adresa se do pozvánky doplní až po startu Toru (pozvánka je do té doby prázdná).
- Ověření kontaktu („safety numbers") je v UI zatím jen přepínač, ne skutečné porovnání.
- Roster zařízení je v jádře hotový a otestovaný, ale GUI ho zatím jen zobrazuje.
- Metadata lokální DB: viz `docs/THREAT_MODEL.md`.
