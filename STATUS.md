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

## 🔄 1.5.1 — aktualizace je konečně vidět
Kliknutí na „Aktualizovat" nedávalo žádnou zpětnou vazbu: stahování přes Tor
trvá minuty, dialog se zavřel a tlačítko dál nabízelo stažení, takže to vypadalo
jako rozbité. (U verzí starších než 1.1.1 navíc stahování opravdu selhávalo —
ptaly se GitHub API, které přes Tor vrací 403.)

- v nabídce je **popis změn** — release script publikuje `NOTES-<verze>.md`
  jako soubor vydání a updater si ho stáhne stejnou cestou jako archiv
  (žádné API, tedy žádný limit)
- během instalace zůstává dialog otevřený a ukazuje **pruh s procenty**
  (`Content-Length` z odpovědi) a fázi: stahuji → ověřuji podpis → restart
- chyba se zobrazí červeně přímo v dialogu a tlačítko se změní na
  „Zkusit znovu" místo tichého opakování
- banner v README je nakreslený jako SVG v repu (`docs/big-sister.svg`), takže
  se zobrazí i bez ručně přidaného obrázku

## 🔎 1.5.0 — hledání, kontakt v detailu, notifikace podle účtu
- **Hledání v chatech**: jedno pole hledá naráz **lidi, skupiny i jednotlivé
  zprávy**; nalezený text je v ukázce zvýrazněný a kliknutím se otevře rozhovor.
  Zprávy jsou šifrované, takže hledání znamená dešifrovat a porovnat v Rustu —
  cena za to, že databáze o obsahu nic neprozradí (žádný plaintextový index).
- **Detail kontaktu**: kliknutím na osobu v Kontaktech se otevře přepínač
  *Kde si píšete* (přímý rozhovor + společné skupiny) / *Co napsal* (všechny
  přijaté zprávy s filtrem Vše / Jen přímé / Ze skupin).
- **Notifikace**: defaultně říkají jen „Máte novou zprávu na @účet". Podrobná
  varianta (odesílatel → účet: text) je volitelná a **jen pro účty, které se
  přihlašují automaticky** — u ostatních je přepínač zšedlý i s vysvětlením,
  protože účet, co si pokaždé řekne o frázi, nemá svítit obsahem na obrazovce,
  u které nikdo není.
- verze aplikace zmizela z lišty, zůstává v Nastavení
- 2 nové testy jádra (hledání v obou typech konverzací, „co poslal tenhle člověk")

## 🐞 Opraveno 1.4.1 — „Tor se nepřipojil do 900 s"
Na stroji běželo **šest instancí Umbry naráz**. Každá si spouští vlastní `tor`
nad stejným adresářem účtu, ten je zamčený pro jeden proces — první ho držel,
zbytek nikdy nenaběhl a po 900 s to vzdal. Stejný důvod, proč neprošla
aktualizace: rozbalené soubory nešly přejmenovat, protože je držely ostatní
procesy.

- druhé spuštění se **ukončí a vyvolá okno té běžící** (pojmenovaný mutex přes
  `CreateMutexW`/`OpenMutexW` + lokální socket na předání „ukaž se")
- `GetLastError` přes Dart FFI nejde věřit (runtime ho stihne přepsat), takže se
  existence mutexu zjišťuje jeho otevřením
- když výměna souborů při aktualizaci selže, hláška teď říká proč („běží ještě
  jiná Umbra?"), místo holé chyby systému
- ověřeno: první instance běží, druhá skončí, `instance.log` to zapíše

## 🔐 1.4.0 — šifrování přešlo na Signal protokol
Sezení už nestaví Olm (vodozemac), ale **`libsignal-protocol` přímo od Signalu**
(AGPL-3.0, stejná licence jako Umbra). Krypto opět nepíšeme sami.

- **PQXDH** při navázání sezení: ke klasickému X25519 se přimíchá post-kvantový
  KEM (Kyber1024), takže odposlechnutý provoz neotevře ani kvantový počítač
  postavený později. Olm tohle neumí.
- Double Ratchet dál dává dopřednou bezpečnost i zotavení po kompromitaci.
- Vazba na identitu zůstala: bundle klíčů podepisuje **Ed25519 identita** a
  příjemce podpis ověřuje proti očekávané identitě z pozvánky — bez toho by
  prekey klíče mohl nabídnout kdokoli (man-in-the-middle).
- Každé spojení má vlastní účet i úložiště klíčů, takže klíče jednoho rozhovoru
  nejsou v dosahu druhého a při každém připojení proběhne nové PQXDH.
- **`WIRE_VERSION` 1 → 2**: handshake změnil tvar, takže 1.3 a 1.4 spolu
  nedomluví. Obě strany musí projít aktualizací.
- 5 nových testů (dva účty si píšou, cizí nepřečte, změněná zpráva neprojde,
  poškozený bundle neprojde, bundly se neopakují) + `protoc` v nářadí (libsignal
  si generuje protobufy)

## 📱 1.3.0 — Android APK
Android build **existuje a sestaví se**; na reálném telefonu zatím neověřený.

- `flutter build apk --release --split-per-abi` → **arm64 14,1 MB**, armv7 13,0 MB,
  x86_64 14,2 MB
- Tor uvnitř APK jako `libtor.so` (8,8 MB, balíček `info.guardianproject:tor-android`
  od lidí za Orbotem) — Android nespustí binárku zapsanou aplikací, proto knihovna;
  cesta se předá přes MethodChannel do Rustu (`set_native_dir`)
- oprávnění: `INTERNET`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`
- ⏳ **mosty (obfs4/snowflake) na Androidu nejsou** — `lyrebird` pro Android není
  jako hotová knihovna, musel by se kompilovat z Go. Android se tedy připojuje
  k Toru přímo (necenzurovaná síť ok, cenzurovaná ne)
- ⏳ běh na pozadí na Androidu není dořešený (chybí foreground service, systém
  aplikaci uspí) — proto zatím APK neber jako hotový produkt
- co bylo potřeba vyřešit: JDK 17 nespustí `Pipe.open()` v cestě s 8.3 jménem
  (`C:\Users\LUKAS~1.VIT\…`) → build musí běžet s `TMP=C:\Temp`; cargokit ještě
  volá `Project.exec()`, takže Gradle **8.12** + AGP 8.7.3 + Kotlin 2.2.20;
  `tor-android` připnutý na 0.4.8.22, protože 0.4.9.x chce compileSdk 37

## 🖥️ 1.3.0 — běh na pozadí (jako WhatsApp)
- start s Windows zapisuje `"umbra.exe" --background`; runner s tímto přepínačem
  okno **vůbec neukáže** (`Win32Window::Create(show=false)`) a appka naběhne do
  systémové lišty — Tor a onion služba běží, uživatel nic nevidí
- zavření okna appku **neukončí**, jen schová (`SetQuitOnClose(false)`); ukončit
  jde z menu ikony v liště („Ukončit — přestaneš být dostupný")
- spouštění s Windows je **defaultně zapnuté** (jednorázově při prvním startu,
  značka `autostart.configured`, takže vypnutí uživatele se už nepřebíjí)
- notifikace se ukazují jen když appka nemá fokus nebo je otevřený jiný chat
- ověřeno: `--background` → okno `hidden`, bez přepínače → `VISIBLE`

## 🎨 1.3.0 — opravené motivy a UI
- **motiv se teď propíše všude**: barvy se čtou při stavbě widgetu a Flutter
  přeskakuje přestavbu `const` podstromů, takže po přepnutí zůstávala část
  obrazovky v barvách předchozího motivu (bílé bubliny, mátový akcent ve fialovém
  motivu). `MaterialApp` má klíč odvozený z palety → strom se postaví znovu celý.
- prázdný stav seznamu chatů místo prázdné plochy
- oddělovače dnů v konverzaci (Dnes / Včera / datum)
- 2 widget testy na motivy (`flutter test`)

## 👥 1.2.0 — kontakty, nevyřízené, blokování, notifikace
- **Nevyřízené**: kdo napíše první a není v kontaktech, přistane v sekci nahoře
  v seznamu chatů. Jde si přečíst, co poslal, a pak **Přijmout** / **Zablokovat**.
  Do běžných chatů se dostane až po přijetí.
- **Blokování**: od blokovaného se všechno zahazuje už v Rustu (neuloží se,
  nezobrazí, neupozorní), zmizí ze seznamu a vyhodí se mu fronta. Odblokovat jde
  z Kontaktů. Historie zůstává na disku.
- **Kontakty (adresář)**: ikona v hlavičce chatů. Kontakt se ukládá ručně
  (menu v chatu → *Uložit do kontaktů*), pak je v seznamu k dispozici pro přidání
  do skupiny, přejmenování, blokování. Kontakt přidaný přes pozvánku se uloží sám.
- **Přejmenování**: kontaktu (jen tvůj štítek, nikam se neposílá) i skupiny
  (jméno putuje s rosterem všem členům).
- **Notifikace** (`local_notifier`): při příchozí zprávě, když appka nemá fokus
  nebo je otevřený jiný chat. U nevyřízeného kontaktu se ukáže jen „Nová zpráva"
  bez textu — cizí člověk nemá co psát uživateli na obrazovku.
- **Profil** je dole v levé liště (nahoře už není žádný pruh), nad ním tlačítko
  aktualizace.
- **Motivy**: dodělány komponenty, které braly barvy z Material defaultů —
  dialogy, snackbary, chipy, přepínače, checkboxy, slidery, tooltipy, menu,
  scrollbar, výběr textu, AppBar a značka Umbry (ta brala fixní zelenou).

## 🐞 Opraveno 1.1.1 — updater dostával od GitHubu 403
Kontrola verze šla přes **GitHub API**, které má limit dotazů na IP. Přes Tor je
tou IP výstupní uzel sdílený se všemi, takže limit bývá vyčerpaný a appka
dostávala `403` a nikdy se neaktualizovala.

- verze se teď čte z přesměrování `github.com/<repo>/releases/latest` →
  `/tag/vX.Y.Z`, což **žádný limit nemá**; API zůstalo jen jako záloha
- adresy souborů se odvodí z verze (jméno archivu určuje `tools/release.ps1`)
- při `403`/`429` se dotaz zopakuje na **jiném Tor okruhu**
  (`socks5_connect_isolated` — jiné SOCKS jméno = jiný výstupní uzel)
- ověřeno přes Tor: `/releases/latest` → 302 na `v1.1.0`, stažení `.sig` → 200

## ✉️ 1.1.0 — psaní protějšku, který je offline
Fronta zpráv byla **jen v paměti**: zavřením appky se čekající zpráva ztratila.

- nová tabulka `outbox` v šifrovaném úložišti — čekající zpráva **přežije restart**
  a odejde sama, jakmile se protějšek objeví (keep-alive ho zkouší každých 20 s)
- stavy zprávy: **čeká na protějšek → odesláno → doručeno** (`messages.state`,
  migrace přidá sloupec i do starých databází)
- `RECEIPT` (kind 8): příjemce potvrdí text zpět, odesílatel z „odesláno" udělá
  „doručeno" (dvě fajfky). Starší build potvrzení neposílá, zůstane „odesláno"
- v chatu s offline protějškem je místo točítka věta „Čeká N zpráv — odejdou,
  jakmile bude X online."
- pořád platí: doručení proběhne, až budete **oba online zároveň** (bez serveru
  to jinak nejde), ale už se o to nemusíš starat ty

## 🔔 1.1.0 — nabídka aktualizace hned
- kontrola po **20 s od startu** a pak **každých 5 min** (dřív 90 s a 30 min)
- když vyjde nová verze, **sama vyskočí nabídka** „Aktualizovat / Později";
  nic se nestahuje bez souhlasu (update mění program, který uživatel spustil)
- vlevo dole v liště je tlačítko s tečkou, dokud je co instalovat; po instalaci
  se z něj stane nabídka restartu

## 🐞 Opraveno 1.0.1 — zmizelý chat s protějškem, který napsal první
Když spojení navázal **protějšek** (my jsme si ho nepřidali přes pozvánku),
uložily se zprávy, ale **nevznikl řádek v `contacts`**. Důsledek: po restartu
appka celý rozhovor nezobrazila (seznam chatů se staví z kontaktů) a keep-alive
neměl kam volat, takže jsme pro protějšek byli trvale nedostupní.

- `store::backfill_missing_contacts` doplní kontakt ke každé historii bez
  kontaktu; volá se při odemčení účtu, takže **stará historie se vrátí sama**
- kdokoli nám napíše, dostane kontakt hned (`remember_peer`)
- nový rámec `ADDRESS` (kind 7): po navázání spojení si strany řeknou onion +
  jméno, takže i rozhovor, který začal protějšek, jde později vytočit z naší
  strany. **Musí ho umět obě strany — protějšek potřebuje aspoň 1.0.1**
- neznámý typ rámce se už jen zaloguje (dřív se uživateli hlásila chyba)
- testy: 60 v jádře (2 nové: backfill, ADDRESS roundtrip)

## 🔄 Aktualizace (25. 7. 2026)
- appka se ptá GitHubu na nejnovější vydání **přes vlastní Tor okruh** (SOCKS
  port běžícího `tor.exe`) — kontrola aktualizací tedy neprozradí IP ani to,
  že běží Umbra. TLS přes rustls + vlastní CA roots (ne systémové úložiště).
- nainstaluje se **jen archiv podepsaný Ed25519 klíčem autora**; veřejný klíč je
  zakompilovaný v `app/rust/src/updater.rs`, soukromý je mimo repo.
- kontrola 90 s po startu a pak každých 30 min; stažení → ověření podpisu →
  rozbalení vedle appky (běžící `.exe` se přejmenuje na `.old`, uklidí se při
  dalším startu). Výměna **nikdy neprobíhá pod běžícím rozhovorem** — UI nabídne
  restart (pruh nahoře + panel v Nastavení).
- vydání: `powershell -File tools\release.ps1 -Version X.Y.Z -KeyFile <klíč>`
  (přepíše verzi, pustí testy, build, zip, podpis, `gh release create`).
- repo: <https://github.com/LukasVitek67/umbra>

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
