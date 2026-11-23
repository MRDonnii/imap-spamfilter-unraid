# Konfiguration (2.3.0)

Næsten alt indstilles i WebUI'en. WebUI'en skriver ændringerne atomisk til `config/accounts.yml`, validerer dem og genstarter kun filterprocessen. Redis, Rspamd og Unbound bliver ikke genstartet. Retter du filen i hånden, logges det som `config_changed_externally` ved næste start. Den daglige brug står i [BRUGERVEJLEDNING.md](BRUGERVEJLEDNING.md).

## Konti (Administration → Konti)

**Tilføj konto** guider dig gennem fire trin. En ny konto starter altid i **Overvåg**. IMAP-adgangskoden gemmes i `state/imap-secrets/<konto>` (mode 0600) og vises aldrig igen. TLS er altid slået til.

Hver konto har sin egen side med disse kort:

| Kort | Indhold |
| --- | --- |
| **Tilstand** | Overvåg / Markér / Filtrér (se nedenfor). Det første skift til Filtrér kræver en tjekliste og en eksplicit spam-mappe. |
| **Følsomhed** | Grænsen (5–15), dvs. fra hvilken score en mail regnes som spam. |
| **Forslag til følsomhed** | Beregnet ud fra de sidste 14 dages frigivelser og egne spam-markeringer. Har knappen **Brug forslaget**. |
| **Flyttetider** | **Flyt tydelig spam med det samme**, med margin og sekunder. Grænsetilfælde venter `move_grace_seconds`. |
| **Beskyttede adresser** | Modtageradresser med kundepost og deres egen, højere grænse. |
| **Betroede videresendere** | Servere, der videresender din post. Standardlisten vises, og du kan tilføje flere. |
| **Lær af mailprogrammet** | **Tillad afsenderen automatisk**, når en mail trækkes ud af Spamfilter i mailprogrammet. |
| **Daglig kvittering** | Til/fra, klokkeslæt og **Send prøve nu**. |
| **Straks-advarsel** (2.3) | **Straks-advarsel ved farlige mails** til/fra (nøglen `threat_notice`) og **Sådan ser advarslen ud**. Sendes kun i Filtrér. Gemmes kun som denne ene nøgle og revideres som `account_threat_notice`. |
| **Nyhedsbreve** (2.6) | **Fra / Prøv / Til** (nøglen `newsletters`). Prøv viser kun, hvad der ville blive flyttet; listen ligger under **Nyhedsbreve** (`/newsletters?account=…`, også linket fra kontoens kort på Oversigt). Gemmes kun som denne ene nøgle og revideres som `account_newsletters`. |
| **Mapper** | Antal mails og ulæste i Indbakke, Spamfilter og udbyderens spam-mappe. Kun visning. |
| **Navn** | Et venligt visningsnavn, fx "Inge". Det bruges overalt i stedet for konto-id'et. |
| **Spam-mappe** | `Spamfilter` anbefales på alle konti. |
| **Server / Forbindelse** | IMAP-server, port, brugernavn og adgangskode. Ændringer gemmes først efter en vellykket **Test forbindelse**. |
| **Pause og fjernelse** | Sæt på pause, aktivér igen eller fjern kontoen. Fjernede adgangskoder flyttes til `state/removed-secrets/`. |

Står sikkerhedsbremsen på, viser siden et rødt banner med **Genoptag flytning**. Kontoens kort har også **Opret bruger til denne postkasse**.

### Tilstande

| UI | `mode` | Hvad sker der |
| --- | --- | --- |
| **Overvåg** | `shadow` | Filteret læser og scorer, men flytter, markerer og lærer intet. |
| **Markér** | `flag` | Spam får et flag i indbakken. Intet flyttes. |
| **Filtrér** | `move` | Spam flyttes til Spamfilter-mappen. Der slettes aldrig noget. |

Alle fem konti står i **Filtrér** med grænse 10.

## Indstillinger (System → Indstillinger)

| Kort | Indhold |
| --- | --- |
| **Mailserver** (2.3) | SMTP-server, port, sikkerhed (STARTTLS/SSL), login (**Brugernavn og adgangskode** eller **Brug postkassens login**), afsender og **Send testmail**. Slået fra, indtil den er sat op. Gemmes i `settings_kv.smtp` (JSON) og `settings_kv.smtp_state`. En separat adgangskode ligger i `state/smtp.password` (0600). |
| **Notifikationer** (2.3) | **Alarmer / Daglig opsummering / Ugerapport / Sikkerhed på mail**, hver med til/fra og modtagere. Gemmes i `settings_kv.mail_notify` (JSON `{kind: {on, to}}`). |
| **Ugerapport** | Rapport i indbakken hver mandag morgen (2.2). Slået fra som standard. Fuld rapport til én postkasse, valgfri kort version til de andre, forhåndsvisning og **Send nu** (mærket "[Prøve]"). |
| **Daglig opsummering** | Unraid-notifikation hver morgen efter kl. 07, med grænse-forslag om mandagen. Slået til som standard. Gemmes som `settings_kv.digest_enabled` = `1`/`0`. |
| **Adgang udefra** | Status for HTTPS, proxy og Cloudflare Access, samt feltet **Ekstern adresse** (`settings_kv.external_url`). Se [CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md). |
| **Farlige vedhæftninger** (2.3) | Listen over blokerede filtyper (højst 100). **Gendan standardlisten** sætter standarden igen. Gemmes som `defaults.attachment_block` i `accounts.yml`. |
| **Beskyttede domæner** (B22) | Domæner, hvis efterligninger stoppes (fx `pinslkbing.example` for `pinsikbing.example`): standard `pinsikbing.example gravisk.example vexar.example` plus postkassernes egne domæner (altid med). Viser den ugentlige kontrol af nyregistreringer (**Kør kontrol nu**), registrerede lignende domæner med mailserver/hjemmeside, mails fra lignende domæner de seneste 30 dage og listen **Ikke en efterligning** (tabellen `lookalike_allow`, kan fjernes igen). Kun administratorer. Gemmes som `defaults.protected_domains` i `accounts.yml`. |
| **Beskyttede navne** (2.7) | Falske afsendernavne ("direktørsvindel"): en mail, hvis afsendernavn er en af jeres egne, men hvis adresse ikke er en af personens rigtige, får `TH_NAME_SPOOF` (+5; +7, når svar går til et andet domæne – ved en gratis-mailadresse en anden adresse – som hverken er personens eller jeres, når afsenderfeltet er ugyldigt, eller når emnet er en tydelig direktørsvindel-sætning: gavekort, "Er du ved din computer?", hast sammen med en overførsel/betaling, fortrolighed sammen med en betaling. Almindelige ord som faktura, regning og betaling tæller ikke, og rspamds `TH_LURE_SUBJECT*` giver kun deres egne point). Har afsenderdomænet (ikke et gratis-maildomæne) sin egen gyldige DKIM-signatur – en platform, der sender i personens navn, fx e-conomic – er det højst +5; "<Navn> (via X)"/"<Navn> via X" underskrevet af X (Google Docs, MobilePay) giver kun +2. Et ugyldigt afsenderfelt (to From-linjer, flere adresser, komma eller affald til sidst, `ole@bynet.example@evil.example`, citeret lokaldel) læses lempeligt for navnet, giver altid +7 og er aldrig undtaget – medmindre der kun er én adresse, og den er personens med gyldig DKIM. Kun de første 256 tegn af afsendernavnet sammenlignes. Den giver aldrig fradrag for kendt kontakt/svar og er ingen trusselsklasse. **Fra / Prøv / Til**, standard **Prøv** (`TH_NAME_SPOOF_TRIAL` med 0 point og hændelsen `namespoof_trial`; efter en uge foreslår Oversigt at slå til). Hvert navn har en liste over adresser (`navn@x.dk`) og domæner (`@platform.dk`), der må bruge det; postkassernes domæner og `contact_group` er altid tilladt (aldrig et gratis-maildomæne). `owner_platform_domains` og `webshop_domains` (fx `vexar.example`) er delte platforme: dér tæller kun personens præcise adresse – hverken platformens domæne som undtagelse eller en `@platform`-linje. En gratis-mailadresse tæller kun med DKIM fra domænet, de andre undtagelser ikke ved DMARC-/SPF-fejl. Navne matches uden accenter og med æ/ø/å = ae/oe/aa, i begge rækkefølger og med forvekslelige tegn; et navn på ét ord kun ved præcis det afsendernavn. Listen fyldes automatisk (og kan rettes) med afsendernavnene fra Sendt post (`own_identities`, brugt mindst 3 gange; navne på ét ord starter slået fra; et fjernet navn kommer ikke igen). Viser mails med navnene fra andre adresser de seneste 30 dage med **Tillad adressen**. Kun administratorer. Gemmes i tabellerne `namespoof_names` og `namespoof_seed_seen` og i `engine_state.namespoof_mode`. |
| **Kontrolrum** (2.9) | Login fra husstandens dashboard Kontrolrum uden adgangskode (single sign-on). **Lav SSO-nøgle** viser nøglen én gang, **Ny nøgle** gør den gamle ugyldig med det samme, og **Slå fra** sletter den. Feltet **Kontrolrums IP-adresse** er de præcise adresser, Kontrolrum kalder fra (ingen standard, ingen net som `/24`, aldrig en betroet proxy som cloudflared). Kortet viser seneste brug og seneste afviste forsøg med afsenderens adresse. Se afsnittet [Login fra Kontrolrum](#login-fra-kontrolrum-29) nedenfor. |
| **Din konto** | Status for to-trins-login og en genvej til Min konto. |
| **Sessioner / Om spamfilteret** | Version og sessionsoplysninger. |

Brugere har deres egen side under **Administration → Brugere**. Her sættes også **Må logge ind: Overalt / Kun lokalt (hjemmenetværket)** (2.3, tabellen `ui_login_scope`) og **Må logges ind fra Kontrolrum** (2.9, tabellen `ui_kontrolrum_sso`, standard fra). Tema og to-trins-login (app og/eller kode på mail) ligger under **Min konto**.

**Drift** har et nyt kort, **Mail** (2.3): mailserverens tilstand, seneste fejl, kø og antal sendte det seneste døgn.

## Regler (Regler)

Hver regel har disse felter:

- **Type:** Tillad eller Bloker
- **Mønster:** en adresse (`navn@firma.dk`) eller et domæne (`@firma.dk`, som også dækker underdomæner)
- **Gælder for:** én postkasse eller alle konti
- **Altid igennem:** kun for Tillad, og kun administratorer kan sætte det

Knapperne **Bloker** og **Tillad** og formularen **Ny regel** spørger først: **Kun denne adresse** eller **Hele domænet** (2.3). Serveren bygger selv mønsteret ud fra feltet `scope=address|domain`. Følgende kan aldrig **blokeres** – uanset vej (vinduet, en formular uden `scope`, **Importér flere på én gang**, **Skift til Bloker** eller **Fortryd**):

- postkassernes egne adresser (`user` på hver konto),
- postkassernes domæner og domæne-agtige `contact_group` (hele domænet; andre adresser på domænet kan godt blokeres),
- `owner_platform_domains` og `webshop_domains` på alle konti, adresse eller domæne – og altid `vexar.example`, `pinsikbing.example` og `gravisk.example`, også hvis konfigurationen har tømt listerne.

Vinduet afviser desuden hele domænet for gratis mailtjenester og alt, der overlapper en **Altid igennem**-regel. Import springer beskyttede linjer over og siger hvor mange.

Reglerne gemmes i tabellen `sender_rules`. Kolonnen `force` gør reglen til Altid igennem.

Rækkefølgen:

- En regel for postkassen slår en regel for alle konti.
- En adresse slår et domæne.
- Ved lige præcise regler slår Bloker Tillad.

Spoof-værnet gør, at en almindelig Tillad-regel bliver ignoreret, når mailen fejler DMARC eller SPF, eller når udbyderen har markeret den som spam. Så afgør scoren.

En Altid igennem-regel gælder kun, når mailen kan bekræftes som ægte fra domænet. Det sker med en DKIM-signatur for domænet, eller når mailen kommer fra domænets egne servere. Ellers opfører reglen sig som en almindelig Tillad-regel.

Automatiske tilladelser, der opstår, når en mail trækkes ud af Spamfilter, er almindelige regler for den præcise adresse. De gemmes med `created_by = 'auto:flytning'`. Filteret fjerner dem selv igen, hvis en mail fra afsenderen trækkes ind i Spamfilter, eller hvis nogen trykker **Flyt til spam** eller **Det er spam**. Regler, du har lavet i hånden, bliver aldrig fjernet automatisk.

### Kendte kontakter og Vedhæftninger (2.3)

**Regler** har tre faner: **Afsenderregler**, **Kendte kontakter** og (kun administrator) **Vedhæftninger**.

- **Kendte kontakter** (`/rules/contacts`) læses fra Sendt-mapperne og gemmes i tabellen `known_contacts`. **Fjern / Gendan** og kontakten **Stol på folk, jeg har skrevet til** kræver regel-adgang til postkassen. **Opdater nu** kræver kun adgang. Kontakten skriver `known_contacts` på kontoen i `accounts.yml`.
- **Vedhæftninger** (`/rules/attachments`) er undtagelser pr. afsender: "Tillad farlige vedhæftninger fra denne afsender". De gemmes i den nye tabel `attach_rules` (ikke i `sender_rules`) og gælder kun, når afsenderen kan bekræftes med DKIM eller sin egen server. En virus undtages aldrig.

## Lokal opsætning (`config/site.yml`)

Alt, der kun gælder **denne** installation, ligger i `config/site.yml` på serveren – aldrig i programmet, i billedet eller i repoet. Det rettes i WebUI'en under **Indstillinger → Lokal opsætning** (`/settings/site`, kun administratorer). En ny installation får en tom fil ved første start (`setup_done: false`), og WebUI'en beder om at få den udfyldt (**Gør opsætningen færdig**). En opdatering eller genstart læser filen, men skriver, fletter eller nulstiller den aldrig. Den er med i backuppen (hele `config/`) og i gendannelsestesten.

| Nøgle | Betydning |
| --- | --- |
| `server_name` | Serverens navn i sidefoden, appen, to-trins-appen og mailenes underskrift. Tom = kun "Spamfilter". |
| `admin_email` | Standardadresse til DMARC-rapporter (`rua`). |
| `mail_domains` | Domænerne på jeres egne postkasser: aldrig slået op i URL-sortlister, må stå i afsendernavne (brand-reglen), aldrig et blokeringsforslag. |
| `webshop_domains` | Egne webshops og hjemmesider (`webshop_domains`-standarden for alle konti, aldrig slået op i URL-sortlister, undtaget fra phishing-feeds). |
| `platform_domains` | Platforme, hvis mail altid skal i indbakken (`owner_platform_domains`-standarden). Kun platformens rod – aldrig andre butikker på den. |
| `protected_domains` | Standardlisten under **Beskyttede domæner** (lignende domæner), når `accounts.yml` ikke har sin egen. |
| `trusted_forwarders` | Standard for `trusted_forwarders` (egne videresendere, værtsnavn eller IP). |
| `mailcheck_domains`, `mailcheck_no_mail` | Ekstra domæner til **Mailsikkerhed** og domæner, der ikke sender mail. |
| `domain_providers` | `domæne: udbyder` – navnet i Mailsikkerheds råd. |
| `imap_presets` | `domæne: {imap_host, imap_port, provider}` – udfylder mailserveren, når en postkasse tilføjes. |
| `lan_url` | Filterets LAN-adresse til Home Assistant-pakken (`SPAMFILTER_LAN_URL` vinder, hvis den er sat). |
| `dns_forwarders` | Navneserveren på hjemmenetværket. Bruges kun, når den `unbound.conf`, der er i brug, ikke har sin egen `forward-zone`, og der ikke ligger en `unbound-forward-records.conf` i app-mappen. |
| `msgid_domain`, `receipt_from`, `contacts_key_label` | Tekniske nøgler under **Avanceret**: domænet i filterets egne Message-ID'er, afsenderen på kvitteringer og mærket på kontakt-nøglen. En flyttet installation beholder sine gamle værdier, så gamle kvitteringer stadig genkendes, og kendte kontakter ikke synkroniseres forfra. |

Værdierne i `accounts.yml` (`defaults` og pr. konto) vinder stadig over standarderne herfra. Egne domæner, webshops, platforme og navneserver lægges desuden ind i de **kørende** rspamd-kort (`surbl-whitelist.inc.local`, `th_brand_domains.map`, `phishing_feed_exclusion.inc`, Phishing Army-undtagelsen i `multimap.conf`) ved hver start af containeren (`deploy/aio/aio_render.py site` + `rspamd`); filerne i repoet og i app-mappen har ingen af dem.

**Mangler filen** på en eksisterende installation (fx en opdatering installeret før flyttescriptet), kører filteret videre med tomme værdier, og administratorer ser **"Lokal opsætning mangler – egne domæner er ikke beskyttet"** øverst på hver side. Kendte kontakter slettes ikke af den grund. Kan filen ikke læses, står der **"Lokal opsætning kan ikke læses"**, og siden gemmer ikke oven i den.

Værtens egne indstillinger (bundet LAN-adresse `WEBUI_BIND`, `TRUSTED_PROXIES`, `SF_UPDATE_REPO`, off-site-målet `SF_OFFSITE_REMOTE`) står i `operations/site.env` på værten. Tom `WEBUI_BIND` = værtens egen LAN-adresse.

## `config/accounts.yml`

Filen har en `defaults:`-blok og en `accounts:`-liste. En nøgle på kontoen vinder over `defaults`. Nøgler, du ikke skriver, bruger den indbyggede standard. WebUI'en skriver kun de nøgler, du ændrer.

### Grundnøgler

| Nøgle | Standard | Betydning |
| --- | --- | --- |
| `name` | (krævet) | Konto-id, fx `molt-inge` |
| `display_name` | – | Visningsnavn i WebUI'en, fx `Inge` (2.1) |
| `user`, `imap_host`, `imap_port` | (krævet), 993 | IMAP-login. `ssl` er altid true. |
| `password_file` | – | Absolut sti til kodefilen (`/state/imap-secrets/<konto>`) |
| `enabled` | true | false = på pause |
| `mode` | shadow | `shadow` / `flag` / `move` |
| `threshold` | 8.0 | Spamgrænse. Live står den på 10 på alle konti. |
| `junk` | Junk | Skal være `Spamfilter` eksplicit på hver konto. Så kan udbyderens `\Junk` aldrig blive valgt. |
| `trash` | Trash | Bruges kun til visning og søgning |
| `bayes_user` | – | Fx `defaults.bayes_user: spamfilter` (én fælles Bayes-pulje) |
| `learn_from_moves` | true | Lær af dine egne flytninger (kun i Markér og Filtrér) |
| `provider_bonus` | true | Lægger point til, når udbyderen selv har markeret mailen som spam |
| `move_grace_seconds` | 60 | Ventetid for mails tæt på grænsen |
| `max_moves_per_hour` | 60 | Hård grænse pr. konto |
| `poll_interval`, `junk_poll_interval` | 600, 300 | Sekunder. IDLE bruges, hvor serveren kan det. |
| `junk_retention_days` | 10 | Virker kun, hvis miljøvariablen `AUTOMATIC_RETENTION_ENABLED=1`. Den er normalt `0`, så intet flyttes på grund af alder. |
| `trusted_relays`, `trusted_relay_domains` | [] | Ekstra udbyder-interne relæer |

### Nye nøgler i 2.1

| Nøgle | Standard | Betydning |
| --- | --- | --- |
| `move_grace_seconds_high` | 3 | Ventetid for tydelig spam |
| `fast_move_margin` | 5.0 | Tydelig spam = score ≥ grænse + denne margin |
| `circuit_max_moves_per_hour` | 25 | Sikkerhedsbremsen: flytninger pr. time |
| `circuit_max_ratio`, `circuit_min_moves` | 0.4, 10 | Sikkerhedsbremsen: andel flyttet af det scannede på 2 timer, og mindste antal flytninger |
| `autolearn` | true | Lær selv sikker spam og sikker ham (se nedenfor) |
| `autolearn_daily_cap` | 10 | Højst så mange automatiske læringer pr. type pr. dag |
| `trusted_forwarders` | `[mail.vexar.example, 203.0.113.109]` | Videresendere, som filteret kigger forbi |
| `protected_recipients` | [] | Beskyttede modtageradresser |
| `protected_threshold` | 18.0 | Grænse for mails til beskyttede adresser |
| `auto_allow_on_rescue` | true | Tillad afsenderen, når en mail trækkes ud af Spamfilter |
| `daily_report` | false | Daglig kvittering i indbakken |
| `report_hour` | 7 | Klokkeslæt for kvitteringen (0–23) |

Om nøglerne:

- **`trusted_forwarders`** erstatter standardlisten, når den er sat. Lad den være usat. Hvis du sætter den, skal den indeholde både `mail.vexar.example` og `203.0.113.109`.
- **`autolearn`** lærer kun i Markér og Filtrér, og kun ud fra mails, der har ligget længe nok:
  - mails, filteret selv har flyttet med score ≥ grænse + 6, og som ikke er frigivet inden for 3 dage, læres som spam
  - mails med score ≤ 0, som har ligget i indbakken i 7 dage, læres som ham
  - Over en uge holdes forholdet mellem de to inden for 1:3 og 3:1.
  - Afsendere med Altid igennem bliver aldrig lært som spam.
  - Fra 2.2 lærer autolearn aldrig ham, hvis ham-vagten siger nej (phishing-regel, blokeret afsender, eller mailen lå kun lavt pga. filterets egne bonusser).

### Nye nøgler i 2.2

| Nøgle | Standard | Betydning |
| --- | --- | --- |
| `aged_scan_hours` | 6 | Sen scanning: mails ældre end dette scannes uden SPF/DMARC og bruger udbyderens godkendelse fra modtagelsen. 0 = slået fra. En almindelig tilladelse gælder da kun, hvis udbyderen eller en gyldig signatur bekræfter afsenderen. |
| `owner_platform_domains` | `[vexar.example]` | Egen webshop-platform. Står den på rspamd's domæneliste, udlignes pointene, når der ikke er andre tegn på et farligt link. |
| `webshop_domains` | `[pinsikbing.example, gravisk.example, vexar.example]` | Egne webshops. Tæller som egne domæner ved udligningen og er "webshop-post" i ugerapporten. |

### Nye nøgler i 2.3

Alle er valgfri. Uden dem bruges standarden, som er sikker at køre med.

| Nøgle | Standard | Betydning |
| --- | --- | --- |
| `known_contacts` | true | Kendte kontakter: læs Sendt-mapperne og giv fradrag for folk, du har skrevet til, svar på dine mails og faste afsendere. Signalerne er inaktive, indtil postkassens første gennemgang er færdig. |
| `known_contact_score` | -4.0 | Fradraget for en kendt kontakt (−6 til −1). Ældre kontakter får −3 eller −2, en kontakt fra en kollega-postkasse −3. |
| `sent_folders` | [] | Pr. konto: navnene på Sendt-mapperne (højst 10). Tom = find dem selv (SPECIAL-USE `\Sent` og en liste med danske og engelske navne, også under `INBOX.`). Sæt den kun, hvis en Sendt-mappe ikke bliver fundet. |
| `contact_group` | null | Pr. konto: postkasser med samme gruppe deler kontakter (fradrag −3). Tom = postkassens domæne, så `molt`, `molt-inge`, `molt-handel` og `molt-sofie` deler `molt.example`, og `bynet` er sin egen gruppe. Tilladte tegn: `a-z 0-9 . -`, højst 100. |
| `zap` | true | Genscanning efter 45 min, 4 t og 24 t. Filtrér flytter, Markér sætter flag, Overvåg noterer kun "ville være flyttet". Læst mail flyttes kun ved en trussel. |
| `threat_notice` | true | Pr. konto (eller i `defaults`): **Straks-advarsel ved farlige mails**. Stopper filteret en virus, et phishing- eller malware-link eller en farlig vedhæftning, lægges en kort dansk advarsel i postkassens egen INBOX (APPEND, ingen SMTP). Højst én pr. postkasse hver 30. minut, højst 10 mails nævnt (resten som "… og N mere"). Uden links, vedhæftninger eller HTML fra den farlige mail. Kun i `mode: move`. `false` slår den fra. Ukendte versioner (2.2.0/2.3.0) ignorerer nøglen. |
| `attachment_block` | standardlisten | Filtyper, der altid blokeres (også i zip-filer): `exe scr com pif cpl msi msix appx bat cmd ps1 vbs vbe js jse wsf wsh hta lnk jar iso img vhd vhdx xll chm reg`. Små bogstaver, uden punktum, `[a-z0-9]{1,10}`, højst 100. Mangler nøglen = standardlisten. `[]` eller `null` = intet blokeres. |
| `protected_domains` | `[pinsikbing.example, gravisk.example, vexar.example]` | B22: domæner, hvis efterligninger stoppes. Alle postkassernes domæner beskyttes altid oven i listen. Et lignende domæne i From, Reply-To, konvolut-afsender eller DKIM-signatur giver `TH_LOOKALIKE_DOMAIN` (+6) og trusselsklassen *Efterligner jeres domæne* (flyttes altid, kun administrator kan frigive, Straks-advarsel). I et link giver det `TH_LOOKALIKE_URL` (+4, kun point). Navne under 6 tegn (bynet, vexar, molt) får kun tegn-, bindestregs- og topdomænevarianter, ikke udeladte/byttede bogstaver og nabotaster. Undtaget: domæner med mindst 3 bevarede mails, kendte kontakter, listen **Ikke en efterligning** og mail underskrevet (DKIM) af det efterlignede domæne selv. For et navn på en delt platform (fx `pinsikbingexample.onmicrosoft.com`, `pinsikbing-example.sharepoint.com`) tæller kun historik og kontakter for netop det navn, aldrig platformens domæne. Egen mail (From er det beskyttede domæne) med udbyderens standardsignatur (`d=pinsikbing-example.….gappssmtp.com`, `d=bynetexample.onmicrosoft.com`) tæller ikke (info-symbol `TH_LOOKALIKE_ALLOWED`, årsag `provider`). En gang om ugen (kl. 3–5) slås alle varianterne op via `spamfilter-unbound` (højst 5 opslag/s); kun en ny MX- eller A-post giver en alarm. En kørsel, hvor mindst halvdelen af opslagene fejler (eller 20 i træk), tæller som fejlet og prøves igen næste time inden for kl. 3–5. Højst 50. `[]`/`null` = kun postkassernes domæner. 2.3.5 ignorerer nøglen. |

### Nye nøgler i 2.6

| Nøgle | Standard | Betydning |
| --- | --- | --- |
| `newsletters` | `shadow` | Pr. konto (eller i `defaults`): nyhedsbreve og reklamer **under** spamgrænsen. `off` = de bliver i indbakken. `shadow` (**Prøv**) = intet flyttes; filteret noterer kun, hvad det ville flytte (hændelsen `newsletter_shadow`, tallet `newsletter_shadow` i `stats_daily`). `on` (**Til**) = de flyttes til `newsletter_folder` efter `move_grace_seconds` – kun når kontoen kører i `mode: move`; i Overvåg/Markér virker `on` som `shadow`. Skriv `'on'`/`'off'` i anførselstegn (YAML læser ellers et bart `on`/`off` som `true`/`false`; begge dele accepteres). Spam går altid til spam-mappen som før. Et nyhedsbrev er en mail med afmeldingslink (`List-Unsubscribe`/`List-Unsubscribe-Post`), `Precedence: bulk/list` eller rspamds `HAS_LIST_UNSUB`/`PRECEDENCE_BULK`; tegn på en masseudsender (Mailchimp, Klaviyo, SendGrid, Salesforce Marketing Cloud, MailerLite …, `Feedback-ID`, `List-Id`) noteres, men er ikke nok alene. Bliver altid i indbakken: kendte kontakter, svar på dine mails og domæner, du skriver med (`TH_KNOWN_CONTACT`, `TH_REPLY`, `TH_REPLY_THREAD`, `TH_KNOWN_DOMAIN`), tilladte afsendere (også Altid igennem), beskyttede adresser, `owner_platform_domains`/`webshop_domains`/postkassens eget domæne og altid `vexar.example` (som afsender, DKIM-signatur eller afsenderserver), stjernemarkerede og læste mails, kalenderinvitationer, `Auto-Submitted` og ordrer, fakturaer, kvitteringer, levering/pakker, adgangskoder, koder, bekræftelser, login/sikkerhed, invitationer og bookinger (ordlisten `TRANSACTIONAL_PATTERNS` i `filter/newsletters.py`). Flytningen bruger flyttejournalen (afbrudte flytninger repareres), sikkerhedsbremsen, pausen efter en opdatering og `max_moves_per_hour` (egen tæller). Flyttes et nyhedsbrev tilbage til indbakken – i mailprogrammet eller med **Tilbage til indbakken** – huskes afsenderen (tabellen `newsletter_keep`), og dens mails flyttes aldrig igen. Nyhedsbreve læres aldrig som spam (og ikke som legitime), og junk-pollen ser ikke på mappen. Ældre versioner ignorerer nøglen. |
| `newsletter_folder` | `Nyhedsbreve` | Pr. konto: mappen til nyhedsbreve. Oprettes ved den første flytning. Skal være en anden mappe end indbakke, spam-mappe, papirkurv og træningsmapperne (ellers afvises konfigurationen; er den udbyderens spam-mappe, flyttes intet, og hændelsen `newsletter_folder_invalid` logges). `/` betyder en undermappe. |

**`bayes_user` og Byg Bayes op på ny (2.3):** **Træning → Byg Bayes op på ny** (eller `sfctl bayes-rebuild`) skriver en ny pulje i `defaults.bayes_user` – `spamfilter-r2`, næste gang `spamfilter-r3` osv. – og i `bayes_user` på de konti, der har deres egen. Alle konti flyttes til den samme nye pulje. Et brugt navn genbruges aldrig. **Gendan tidligere Bayes** skriver de gamle værdier tilbage præcis som før (også en manglende nøgle). Skriv ikke selv en ny pulje i filen, mens en genopbygning kører: så nægter gendannelsen ("konfigurationen er ændret siden genopbygningen").

Trusselsklassen (virus, phishing-link, malware-link, farlig vedhæftning) har ingen nøgle. Den gælder altid. Se [BRUGERVEJLEDNING.md](BRUGERVEJLEDNING.md#trusler-virus-phishing-og-farlige-vedhæftninger).

Indstillinger for ugerapporten ligger ikke i `accounts.yml`, men under **Indstillinger → Ugerapport** (`settings_kv.weekly_enabled`, `weekly_admin_account`, `weekly_users`).

Brand-reglerne (falske afsendernavne) læser listen over ægte domæner fra `rspamd/local.d/maps.d/th_brand_domains.map`. Tilføj en ægte forhandler eller formidler der, og udrul igen.

### Eksempel (sådan skal det se ud efter 2.1)

```yaml
defaults:
  bayes_user: spamfilter
  # mode: move og threshold: 10 står som i dag (i defaults eller pr. konto)
  # auto_allow_on_rescue: true og daily_report: false er standard
accounts:
  - name: bynet
    display_name: Ole (bynet)
    user: ole@bynet.example
    imap_host: imap.gigahost.dk
    junk: Spamfilter
    password_file: /state/imap-secrets/bynet
    protected_recipients: [info@gravisk.example, info@pinsikbing.example]
  - name: molt
    display_name: Ole (molt)
    user: ole@molt.example
    imap_host: mail.scannet.dk
    junk: Spamfilter
    password_file: /state/imap-secrets/molt
    protected_recipients: [info@gravisk.example, info@pinsikbing.example]
  - name: molt-inge
    display_name: Inge
    # … junk: Spamfilter, password_file osv.
  - name: molt-handel
    display_name: Handel
  - name: molt-sofie
    display_name: Sofie
```

Eksemplet er forkortet. Ret helst via WebUI'en (kortene **Navn** og **Beskyttede adresser**), så valideringen og revisionsloggen kommer med.

## Data i SQLite, som WebUI'en bruger

Alle tabeller og kolonner fra 2.1, 2.2 og 2.3 er tilføjelser. Ældre versioner ignorerer dem, så en rollback virker stadig. Rollback fra 2.3 til 2.2.0 er testet med den rigtige 2.2.0-kode mod en 2.3-database.

| Tabel / nøgle | Indhold |
| --- | --- |
| `ui_users` | Rettigheder pr. Bruger (`release`, `rules`, `see_messages`), sidste login. En bruger uden række har alle tre rettigheder, ligesom i 2.0. |
| `ui_twofa` | Hemmelighed til to-trins-login, hashede genoprettelseskoder, om det er krævet |
| `undo_jobs`, `undo_items` | Fremdrift for Fortryd flytninger |
| `move_circuit`, `engine_state`, `move_journal` | Sikkerhedsbremsen, pausen efter opdatering og reparation af afbrudte flytninger |
| `autolearn_log`, `daily_receipts` | Automatisk læring (kan fortrydes) og sendte kvitteringer |
| `settings_kv` | `digest_enabled`, `external_url`, `spam_seen:<bruger>` (Ny-mærker) m.fl. Fra 2.3 også `smtp`, `smtp_state` og `mail_notify` (JSON). |
| `known_contacts`, `contacts_sync`, `own_identities`, `sent_threads`, `sender_history`, `contacts_seen`, `contact_recheck` (2.3) | Kendte kontakter, synkroniseringens fremdrift (rækken med mappe `*` er postkassens samlede status), egne afsenderidentiteter, tråde og afsenderhistorik. Adresser og Message-ID'er gemmes kun som nøglede hashes (HMAC-SHA256 med `state/contacts.key`) plus en maskeret visning som "a…@kunde.dk". |
| `messages.threat`, `threat_detail`, `zapped_at`, `pending_move.origin` (2.3) | Trusselsklasse og detalje, og hvornår en genscanning flyttede mailen |
| `rescan_queue`, `attach_rules` (2.3) | Kø til genscanning og undtagelser for vedhæftninger |
| `mail_outbox` (2.3) | Udbakke for mail fra filteret. Indholdet slettes, når mailen er sendt eller opgivet, og rækken efter 30 dage. Engangskoder skrives aldrig i databasen. |
| `ui_twofa_mail`, `ui_mail_codes` (2.3) | Bekræftet mailadresse til to-trins-login og saltede hashes af mailkoder |
| `ui_login_scope` (2.3) | Brugere med **Kun lokalt**. Ingen række = Overalt. |
| `ui_kontrolrum_sso`, `ui_sso_nonces` (2.9) | Brugere med **Må logges ind fra Kontrolrum** (ingen række = fra) og brugte engangsværdier fra Kontrolrum (slettes, når de ikke længere kan bruges). `settings_kv` `kontrolrum_sso` (nøglen, AES-GCM-krypteret med en nøgle afledt af `state/dashboard_secret`, plus fingeraftryk og hvem/hvornår), `kontrolrum_sso_peers` (Kontrolrums adresser), `kontrolrum_sso_used` og `kontrolrum_sso_rejected` (seneste brug og afvisning). |
| `threat_notices` (2.3) | Farlige mails, der venter på eller er nævnt i en straks-advarsel (konto, Message-ID, klasse, afsendernavn, tider). Selve advarslen registreres i `daily_receipts` med `kind = 'threat'`, så scanneren, junk-pollen og læringen springer den over. Ryddes efter 30 dage. |
| `bayes_rebuilds`, `bayes_rebuild_jobs` (2.3) | Historik for **Byg Bayes op på ny**: gammel og ny pulje, plan, forventede og lærte tal, status (`starting`, `running`, `done`, `failed`, `restored`, `restoring` = en gendannelse, der skal gøres færdig) og hvilke trænings- og lærelistejob der hører til. |
| `push_subscriptions` (2.5.0) | Enheder med beskeder: bruger, push-adresse (endpoint, unik), browserens offentlige nøgle og auth-hemmelighed, oprettet, seneste ok, antal afvisninger, kort enhedsnavn ("iPhone · app på hjemmeskærmen") og valg (JSON `{threat, review, problem}`). |
| `push_queue`, `push_marks` (2.5.0) | Kø til beskeder (én række pr. bruger og slags, mens den venter; kun antal pr. postkasse, aldrig mailindhold) og hvilke farlige mails / Tjek disse-mails der allerede er talt med. Ryddes efter 7 dage. `settings_kv` `push:review_at:<konto>` og `push:review_floor:<konto>` styrer halvtimes-samlingen af Tjek disse. `push:refused` husker den seneste afvisning fra en push-tjeneste, der gælder filteret selv (status, kort kode, tjeneste, tid – aldrig en adresse); den ryddes ved næste beskeds succes hos samme tjeneste. |
| `newsletter_pending`, `newsletter_keep` (2.6) | Nyhedsbreve, der venter på at blive flyttet (konto, UIDVALIDITY, UID, Message-ID, tidspunkt), og afsendere, der altid bliver i indbakken (konto, adresse i små bogstaver, hvornår og af hvem). `messages.our_action` er `newsletter_pending`, `newsletter_moved`, `newsletter_move_failed` eller `newsletter_kept`; `moved_to_junk_at` sættes aldrig for nyhedsbreve, så Fortryd flytninger og den automatiske læring ikke tager dem med. |
| `bayes_pool_archive` (2.3) | Den lærte tilstand pr. Bayes-pulje (`messages.learned_as`, `learn_ledger`, `autolearn_log`), gemt ved hvert skift, så **Gendan tidligere Bayes** kan hente den tilbage. `autolearn_log` ryddes ikke ved skiftet: en mail, der én gang er autolært, tilbydes aldrig igen. |

Brugerfilen `state/dashboard_users` har samme format som før: `navn:verifier:scope:gen`. En Bruger uden postkasser skrives med scope `~none`.

## Miljøvariabler (sat af `deploy/lib.sh` ud fra `deploy/versions.env`)

| Variabel | Værdi | Betydning |
| --- | --- | --- |
| `TRUSTED_PROXIES` | tom | IP'er/CIDR'er på den proxy, der må sætte klient-IP, https og Cloudflare-identitet (2.1). Tom = ingen. |
| `AUTOMATIC_RETENTION_ENABLED` | 0 | Ingen flytning til papirkurven på grund af alder |
| `DASHBOARD_COOKIE_SECURE` | – | Tvinger Secure-cookies. Det sker automatisk over HTTPS i 2.1. |
| `LOCAL_NETWORKS` | ikke sat | (2.3) Hjemmenetværket for **Kun lokalt**. Standard: `127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7, fe80::/10`. Sættes ikke af deploy-scripts. Forespørgsler gennem en proxy eller tunnel er altid "udefra". |
| `SPAMFILTER_LAN_URL` | `http://192.168.1.10:18080` | (2.3.6) Filterets LAN-adresse i Home Assistant-pakken, når Indstillinger åbnes udefra. Åbnes siden hjemmefra, bruges sidens egen adresse. Se [HOME-ASSISTANT.md](HOME-ASSISTANT.md). |
| `LOOKALIKE_DNS_PORT` | `53` | (2.4) Porten på navneserveren ovenfor. I alt-i-én-containeren sætter billedet den til `5353`. Ugyldige værdier tæller som 53. |
| `LOOKALIKE_DNS_SERVER` | `spamfilter-unbound` | (2.3.6) Navneserveren, den ugentlige kontrol af lignende domæner spørger (UDP, TCP ved trunkering, port `LOOKALIKE_DNS_PORT`). Tom tæller som ikke sat. I alt-i-én-containeren (2.4) sætter billedet den til `127.0.0.1`. |
| `SPAMFILTER_AIO` | (tom) | (2.4) Sættes af alt-i-én-billedet til `1`. Så viser `sfctl doctor` også Redis, Unbound og det samlede sundhedstjek, og rettelserne nævner `supervisorctl` i stedet for de gamle containere. |
| `PUSH_VAPID_SUBJECT` | ikke sat | (2.5.0) Kontaktadressen i beskedernes VAPID-nøgle (`mailto:navn@domæne.dk` eller `https://…`). Ikke sat: afsenderen under **Indstillinger → Mailserver**, ellers den første postkasse i `accounts.yml`. Apple afviser `.local`, `.invalid`, `.test` og lignende. |
| `SF_CLAMAV` | `1` | (2.7) Virusscanning med ClamAV i alt-i-én-containeren. `0` slår clamd og freshclam fra (fx på en server med lidt RAM); så lades rspamds antivirus også være. Sættes i Unraid-skabelonen (**Antivirus (ClamAV)**) eller i `operations/site.env`, som deploy-scripts sender med til containeren. Se **Virusscanning (2.7)** nedenfor. |
| `SF_AIO_MEMORY` | `4g` | (2.7, deploy-scripts) Containerens RAM-grænse. Var `3g` før 2.7; med `SF_CLAMAV=0` er `3g` nok. |
| `TRUSTED_PROXY` | – | Forældet (2.0). `1` betyder nu kun private net, og der logges en advarsel. Brug `TRUSTED_PROXIES`. |
| `STATE_DIR`, `CONFIG_PATH`, `RSPAMD_*`, `TZ` | faste | Sat af deploy-scripts |

## Login fra Kontrolrum (2.9)

Kontrolrum viser spamfilteret inde i sig selv og holder sessionen på sin server. I stedet for at gemme en adgangskode signerer Kontrolrum en kort påstand ("log ind som `kontrolrum`") med en delt nøgle – samme håndtryk som FleetDeck.

- **`POST /login/kontrolrum`** med JSON `{v: 1, aud: "spamfilter", sub, iat, exp, nonce, sig}`. `sig` = hex HMAC-SHA256 med nøglen (den viste hex-tekst som UTF-8) over linjerne `kontrolrum-sso`, `v`, `aud`, `sub`, `iat`, `exp`, `nonce` adskilt af `\n`.
- Kun når **TCP-afsenderen er en af Kontrolrums adresser** og forespørgslen ikke har proxy-headere (`X-Forwarded-For`, `CF-Connecting-IP`, `CF-Ray`, `Forwarded`, `X-Real-IP`). Alle andre får 404. Derefter tjekkes: SSO slået til (403 `sso_disabled`), formatet (400 `bad_request`), signaturen i konstant tid (401 `bad_signature`), version og modtager (401 `bad_version`/`bad_audience`), tiden (højst 120 s levetid, 60 s urforskel, ellers 401 `expired`), engangsværdien (gemt i databasen, 401 `replay`) og at brugeren har fluebenet (401 `unknown_user`). Højst 10 forsøg pr. afsender pr. 5 minutter (429).
- Ved succes: en almindelig session (12 timer, 2 timers inaktivitet), hvor to-trins-login regnes som opfyldt, fordi Kontrolrum selv kræver login. Revisionsloggen får `login_kontrolrum`, loginhistorikken metoden "Kontrolrum", og første login fra Kontrolrum giver en advarsel om ny enhed som andre logins.
- **Sessionen er bundet til Kontrolrums adresse.** Den tæller som tilladt for en *Kun lokalt*-bruger, også når Kontrolrum selv blev åbnet gennem Cloudflare-tunnellen – men kun så længe hvert kald kommer fra den samme Kontrolrum-adresse. En kopieret cookie, der bruges direkte på tunnel-adressen, fra LAN'et eller fra en anden container, logges ud med det samme (`login_kontrolrum` · *session afvist*). Det samme sker, når nøglen skiftes eller slås fra, når adressen fjernes, og når fluebenet tages af.
- **Adgangskoder ændres ikke:** en *Kun lokalt*-brugers adgangskode virker stadig kun hjemme, også hvis login-siden åbnes gennem Kontrolrum.

**Sådan slås det til (én gang):**

1. **Konti og adgang → Adgang for programmer → Login fra Kontrolrum (SSO) → Lav SSO-nøgle** (før 2.11.0: Indstillinger → Kontrolrum). Kopiér nøglen (den vises kun én gang).
2. Skriv **Kontrolrums IP-adresse** på samme kort (under "Kontrolrums adresse og brugere"). Kender du den ikke, så sæt nøglen ind i Kontrolrum først: kortet viser derefter "Seneste afviste forsøg … fra *adresse*". Er adressen en betroet proxy (TRUSTED_PROXIES), kan den ikke bruges.
3. **Brugere → kontrolrum → Kontrolrum → Må logges ind fra Kontrolrum**, og tryk **Gem**.
4. I Kontrolrum: Spamfilter-tjenesten → **Automatisk login → SSO-nøgle**. Adgangskoden kan derefter fjernes i Kontrolrum.

En rollback til 2.8 ignorerer tabellerne og nøglerne; Kontrolrum logger så ind med adgangskoden igen, hvis den stadig er gemt.

## Beskeder på telefonen (2.5.0)

Ingen nøgler i `accounts.yml`. Hver bruger slår beskeder til pr. enhed under **Min konto → Beskeder på denne enhed** (se [BRUGERVEJLEDNING.md](BRUGERVEJLEDNING.md#beskeder-på-telefonen)).

- **Kræver** den sikre adresse (https via Cloudflare Tunnel, fx `https://spamfilter.example.org`), en service worker og Push API. På iPhone kun i appen på hjemmeskærmen og fra iOS 16.4. Den lokale `http://192.168.1.10:18080` kan ikke (ingen sikker kontekst); kortet forklarer det.
- **Hændelser:** farlig mail flyttet (samme øjeblik som Straks-advarslen, kun Filtrér), nye Tjek disse-mails (Markér og Filtrér, højst hver halve time pr. postkasse) og problemer (de samme som alarmmailen: login afvist, sikkerhedsbremse, sikkerhedstilstand og nedetid over 10 minutter). Uafhængigt af mailserveren.
- **Nøgle:** `state/vapid_private.pem` laves automatisk. `sfctl push-reset` skifter den (alle enheder skal slå beskeder til igen).
- **Python-pakke:** `cryptography` (fast version i `filter/requirements.txt`, installeres i billedet).
- **sfctl:** `push-status`, `push-test BRUGER`, `push-reset`; `doctor` viser beskedernes tilstand.

## DMARC-rapporter (2.6)

Siden **Sikkerhed → DMARC** (kun administratorer) viser for hvert af jeres domæner de seneste 30 dage: antal mails, hvor mange procent der består DMARC, de største afsendere (IP og navn, "godkendt"/"fejler") og en anbefaling på almindeligt dansk, fx "Klar til p=quarantine" (mindst 98 % består i 14 dage, og der er ingen ukendte kilder med SPF/DKIM for et andet domæne).

- **Adresse (rua):** standard `ole@bynet.example`; ændres på siden. Den skal stå i DMARC-posten: `_dmarc.<domæne> TXT "v=DMARC1; p=none; rua=mailto:<adresse>"`. Ligger adressen i et andet domæne end det rapporterede, skal adressens domæne give lov: `<domæne>._report._dmarc.<adressens domæne> TXT "v=DMARC1"` (RFC 7489, afsnit 7.1). Siden viser de præcise poster.
- **Pr. postkasse:** *Automatisk* (standard: til for den postkasse, der har rua-adressen), *Til* eller *Fra*. Gemmes i databasen (`settings_kv` → `dmarc`), ikke i `accounts.yml`.
- **Hvad filteret gør:** Hver rapport scannes først helt normalt (rspamd og virusscanner). Kun en rapport, der ikke er spam, ikke er farlig og har gyldig DKIM-signatur for afsenderens eget domæne fra en kendt rapportør (Google, Microsoft, Yahoo m.fl., eller en afsender, hvis rapport selv nævner afsenderens domæne), og som er en gyldig rapport (emne "Report domain: … Submitter: …", vedhæftet `.xml`, `.xml.gz` eller `.zip`) for et af jeres domæner – eller sendt til rua-adressen – gemmes og flyttes til mappen **DMARC-rapporter** (oprettes selv; kun i tilstanden Filtrér). Flytningen bruger filterets almindelige flytte-journal, så en afbrudt flytning gøres færdig. Bliver den ikke flyttet (Overvåg, Markér, timeloft, fejl), behandles den som al anden mail. En flyttet rapport bliver aldrig lært. Flytter du en rapport tilbage til indbakken, bliver den der (genkendt på Message-ID og selve indholdet – Message-ID alene er ikke nok).
- **Sikkerhed:** Vedhæftningerne pakkes højst ud til 20 MB, zip-filer med højst 10 filer og uden kryptering, XML uden DOCTYPE/entiteter og med grænser for dybde og antal. Alt, der ikke er en gyldig rapport for jer, scannes helt normalt.
- **Data:** tabellerne `dmarc_reports`, `dmarc_records`, `dmarc_mail` og `dmarc_ptr` (navne fra filterets egen Unbound, slået op når siden åbnes – højst 10 nye pr. visning – og gemt i 14 dage). Rapporter ældre end 400 dage slettes. Fra 2.7 gemmes også DKIM-selectoren (`dkim_selector`), så Mailsikkerhed kan tjekke nøglen.

## Mailsikkerhed (2.7)

Siden **Sikkerhed → Mailsikkerhed** (kun administratorer) tjekker jeres egne domæner og mailservere – som MXToolbox, men automatisk hver nat (kl. 05) og når du trykker **Tjek nu** (starter inden for et minut). Hvert tjek får OK, Info, Advarsel, Fejl eller *Ikke testet* og en forklaring med, hvordan det rettes – med udbyderens navn, når det kendes.

- **Domæner:** postkassernes domæner, platform- og webshop-domænerne fra `accounts.yml`, domænerne på siden DMARC og listen **Flere domæner** på siden. **Sender ikke mail** (standard: `example.org`) betyder, at SPF skal være `v=spf1 -all`, DMARC `p=reject`, og at der ikke kræves DKIM. **Spring over** fjerner et automatisk fundet domæne. Gemmes i `settings_kv` → `mailcheck`.
- **Pr. domæne:** MX (og at serverne har en adresse, omvendt DNS), SPF (én post, syntaks, `-all`, højst 10 DNS-opslag – hver include/a/mx/ptr/exists/redirect tæller, også når samme include står flere steder – og højst 2 tomme opslag; en løkke er kun en henvisning tilbage til et domæne på samme vej), DKIM, DMARC (politik, `rua`, og tilladelsesposten `<domæne>._report._dmarc.<rua-domæne>` når rapporterne går til et andet domæne), MTA-STS og TLS-RPT (valgfrit, kun info), DNSSEC (SERVFAIL tæller kun som ødelagt DNSSEC, når samme opslag svarer med validering slået fra – ellers *Ikke testet*) og jokertegn (`*.domæne`), der svarer for `_dmarc`, `_domainkey` og `_mta-sts`.
- **DKIM:** selectors læres kun af gyldige signaturer – jeres egne leverede mails (rspamd `R_DKIM_ALLOW` – "domæne:s=selector") og DMARC-rapporternes rækker med `dkim=pass`. De huskes mellem tjekkene og glemmes, når de ikke er set i 60 dage (gemmes i `mailcheck_state` → `selectors`); dem, I selv skriver på siden (`domæne selector` pr. linje), bliver. Mangler nøglen til en selector, der ikke er set i over 14 dage, er det kun info (udbyderen har sikkert skiftet nøgle). Nøglen skal findes og være mindst 1024 bit (2048 anbefales). Har filteret set jeres egne mails fra domænet de seneste 30 dage (SPF eller DKIM bestået, ikke spam), og var ingen af dem signeret med domænet, er det en **Fejl**.
- **Mailservere:** hver MX (port 25, STARTTLS), afsenderserveren fra Indstillinger → Mail og postkassernes IMAP-servere: forbindelse, kryptering, certifikat for navnet, dage til udløb (advarsel under 21, fejl under 7) og TLS 1.2 eller nyere. Blokerer internetudbyderen port 25, vises MX som *Ikke testet (port 25 blokeret)*. Afviser serveren testforbindelsen (554-hilsen, afvist EHLO, nulstillet forbindelse – normalt fra en hjemme-IP), er det også *Ikke testet*. Servernavne slås op via filterets egen Unbound, og der forbindes kun til offentlige adresser (en intern adresse vises som *intern adresse – ikke testet*); certifikatet tjekkes mod navnet. EHLO-navnet er `MAILCHECK_HELO`, ellers værten fra den eksterne adresse, ellers maskinens fulde navn. Hver test har højst 20 sekunder, hele tjekket højst 10 minutter.
- **Blokeringslister:** udbydernes udgående servere, som jeres mail faktisk sendes fra – afsender-IP på jeres egne mails, hvor SPF bestod for domænet, og som domænets SPF-post tillader (aldrig jeres egen IP ved indlogget afsendelse, aldrig en afsender, der kun har DKIM), og kilder i DMARC-rapporterne, hvor SPF bestod for domænet – og MX-adresserne slås op i Spamhaus ZEN, SpamCop, Barracuda og PSBL – med pause mellem opslagene og sin egen andel af opslagsgrænsen. Svarer Spamhaus 127.255.255.x (afvist opslag), vises det som "kunne ikke slås op", ikke som opført; Spamhaus PBL (127.0.0.10/11) er info ("dynamisk IP – normalt").
- **Intern tilstand:** samme side viser filterets egne dele (sundhedstjek, livstegn, backup og kopi ud af huset, DMARC-rapporternes alder) med link til Drift.
- **DNS:** via filterets egen validerende Unbound (`127.0.0.1:5353` i den samlede container). `MAILCHECK_DNS_SERVER` / `MAILCHECK_DNS_PORT` kan pege et andet sted hen (ellers `LOOKALIKE_DNS_SERVER`/`_PORT`). `MAILCHECK_DISABLED=1` slår det natlige tjek fra. Python-pakken `dnspython` (fast version i `filter/requirements.txt`).
- **Advarsler:** mail og push (Problemer med filteret) kun ved en forværring i forhold til sidst kendte tilstand (OK → Advarsel/Fejl, Advarsel → Fejl), der ses i to tjek i træk – med det samme ved en ny opførelse af en afsenderadresse på en blokeringsliste eller et certifikat med under 7 dage tilbage. Samme problem sendes kun én gang – igen først, når det har været rettet imellem eller bliver værre, og ikke igen inden for 7 dage, hvis det blot kommer og går. Et problem regnes først som sendt, når beskeden er sendt (ellers prøves igen ved de næste tjek, højst 3 gange). "Ikke testet" tæller hverken som rettet eller fejl. Første tjek er udgangspunktet.
- **Offline:** svarer DNS ikke på kontrolopslagene, eller fejler de fleste opslag, står hele tjekket som *Ikke testet*, og der sendes ingen beskeder. Svarer ingen af serverne, er forbindelsesfejl *Ikke testet*, ikke fejl.
- **Kendt – ignorér:** ved hver advarsel og fejl i det nyeste tjek. Punktet vises så som info, giver ingen beskeder og tæller ikke med i Home Assistant og `sfctl doctor`, før det ændrer sig (bundet til punktets status og tekst; tal i teksten tæller ikke). **Ikke længere kendt** fortryder. Gemmes i `mailcheck_state` → `acks`; intet markeres automatisk.
- **Planlægning:** kun det natlige tjek flytter det natlige tjek – **Tjek nu** eller `sfctl mailcheck` om dagen springer ikke natten over. Et tjek, der er gået ned, blokerer ikke **Tjek nu** (ryddes ved start og ignoreres efter tidsgrænsen). Opslagsgrænsen vokser med antallet af domæner; nås den alligevel, står de berørte punkter som *Ikke testet (grænse nået)*.
- **Data:** `mailcheck_runs` (de seneste 60 tjek som JSON; siden viser 30 og "Siden sidst"), `mailcheck_state`, `mailcheck_alerted`.
- **sfctl:** `mailcheck` (kør nu og vis resultatet; `--problems` kun problemer, `--last` seneste gemte uden netværk). `doctor` viser én linje fra det seneste tjek (problemer i DNS er advarsler, ikke fejl i installationen).
- **Home Assistant:** `/api/v1/ha` har `mailcheck: {status, errors, warnings, last_run}` – `status` er `ok`, `warn`, `bad` eller `unknown` (tjekket kunne ikke gennemføres); punkter markeret *Kendt – ignorér* tæller ikke med.

## Virusscanning (2.7)

- **Hvad:** rspamds antivirus-modul (`rspamd/local.d/antivirus.conf`, installeres af `update.sh`) sender hver vedhæftning til ClamAV (`clamd`) i containeren. Tekst og billeder sendes ikke; arkiver pakkes ud af ClamAV. Resultater gemmes i Redis, så en genscanning ikke spørger igen.
- **Grænse:** Mails over 5 MB i alt (`MAX_FETCH_BYTES` i `filter/filter.py`) hentes og scannes slet ikke – heller ikke af ClamAV; de bliver i indbakken som før. rspamds egen grænse pr. vedhæftning (20 MB) nås derfor aldrig.
- **Kun i alt-i-én-containeren:** Den gamle opsætning med fire containere har ingen clamd. Dér installerer `deploy/lib.sh` den slåede-fra `antivirus.conf.legacy` som `antivirus.conf` (så rspamd ikke venter på en socket, der ikke findes); alt-i-én-containeren bruger sin egen kopi, også efter en migrering.
- **Et fund** giver `CLAM_VIRUS` med signaturens navn (0 point i rspamd). Filteret gør det til trusselsklassen **Virus**: altid til Spamfilter uanset grænse, tilladte afsendere og "Altid igennem"; kun en administrator kan frigive; Straks-advarsel og telefonbesked som ved andre trusler. Der afvises intet ved SMTP – filteret arbejder efter levering.
- **Heuristik og ekstra signaturlister er ingen virusdom:** Er alle signaturerne heuristiske eller fra tredjepartslister – navne, der begynder med `Heuristics.` (også `Heuristics.Limits.Exceeded`), `PUA.`, `Sanesecurity.`, `SecuriteInfo.`, `winnow.`, `MiscreantPunch.`, `foxhole.` eller `Porcupine.`, ender på `.UNOFFICIAL` eller indeholder `Phishing` – bliver det ikke trusselsklassen Virus, men `TH_CLAM_HEURISTIC` (+4 point). Brugeren kan frigive mailen, "Altid igennem" og kendte kontakter virker som normalt. Alle andre signaturer (og et fund uden navn) er stadig Virus.
- **Fejl giver ingen point:** svarer ClamAV ikke (genstart, første download, for langsom), får mailen `CLAM_VIRUS_FAIL` (0 point, ingen dom), og resten af scoringen afgør sagen.
- **Virus-genscanning:** En mail med vedhæftninger, der fik `CLAM_VIRUS_FAIL` og blev i indbakken, scannes igen efter 10 min, 1 t og 6 t (tabellen `av_rescan_queue`, fundet på UID). Det sker uanset `zap` og dens undtagelser (kendte kontakter, svar, tilladte afsendere). Kun et nyt `CLAM_VIRUS` med en rigtig virussignatur gør noget: så den normale virusbehandling (til Spamfilter, Straks-advarsel; i Overvåg kun noteret). Ren, heuristisk eller stadig ingen svar ændrer intet; efter 3 forsøg opgives den (hændelserne `av_rescan_clean` / `av_rescan_skipped`). En mail, brugeren har afgjort, eller som er flyttet, røres ikke. Den almindelige genscanning (`zap`, 45 min / 4 t / 24 t) kan også finde virus, men springer kendte kontakter, svar og tilladte afsendere over.
- **Ved start** venter filteret højst 120 s på clamd (en testscanning gennem rspamd uden `CLAM_VIRUS_FAIL`), når ClamAV er slået til, og signaturerne allerede ligger der – så de første mails efter en genstart bliver virusscannet. Ved allerførste download ventes der ikke.
- **Signaturer:** `freshclam` henter dem fra `database.clamav.net` ved start og derefter 4 gange i døgnet til `<app-mappe>/clamav` (uid/gid 3310, mode 0750, ca. 300 MB, oprettes af containeren). Første start tager nogle minutter; `clamd` starter først, når signaturerne er der. Mappen er ikke med i backuppen (den hentes bare igen). DNS går her via containerens normale navneserver (Dockers), ikke via den interne Unbound.
- **Indstillinger:** `deploy/aio/clamav/clamd.conf` og `freshclam.conf` (i billedet under `/etc/spamfilter/clamav`). Ingen PUA- eller URL-heuristik. `ConcurrentDatabaseReload no`: en opdatering pauser scanningen i ca. et halvt minut i stedet for at fordoble RAM-forbruget. `MaxThreads 8` (signaturerne deles af alle tråde; hver tråd koster kun få MB). `MaxScanTime 5000` (5 s – clamd stopper selv en for langsom scanning, før rspamds grænse på 6 s). `AlertExceedsMax yes`: en fil over grænserne (arkivbombe, for dyb, for mange filer, for langsom) meldes som `Heuristics.Limits.Exceeded.*` i stedet for at gå igennem som ren – det giver `TH_CLAM_HEURISTIC` (+4), aldrig trusselsklassen Virus.
- **RAM:** ca. 1-1,5 GB til signaturerne, kortvarigt det dobbelte, mens freshclam tester en ny database. Derfor er containerens grænse 4 GB. `SF_CLAMAV=0` slår det hele fra.
- **Status:** `docker exec spamfilter sf-health clamav`, `sfctl doctor` (linjen "antivirus (ClamAV)"), sundhedstjekkets `health.json` (delen `clamav`, kun som advarsel) og Home Assistant (`antivirus`). Der advares, når ClamAV ikke svarer, eller når signaturerne er over 3 dage gamle.

## Lokal AI-vurdering (2.7)

Siden **Filtrering → AI-vurdering** (`/ai`, kun administratorer). Ingen nøgler i `accounts.yml`: indstillingen er fælles for alle postkasser og gemmes i databasen (`settings_kv` → `ai`, JSON). Ændringer revideres som `ai_settings`.

| Felt | Standard | Betydning |
| --- | --- | --- |
| **AI-vurdering** (`mode`) | `shadow` | `off` (Fra), `shadow` (**Prøv**: vurdér og gem, men ændr intet) eller `on` (**Til**). Til virker kun i postkasser i `mode: move`; ellers som Prøv. Uden en gemt Ollama-adresse kører intet (siden viser "Ikke sat op – angiv Ollama-adressen"). |
| **Ollama-adresse** (`url`) | ingen | Intet sendes, før en administrator har gemt en adresse (fx `http://192.168.1.10:11434`). Kun `http(s)://` til en IP-adresse på hjemmenetværket (10/8, 172.16/12, 192.168/16, fc00::/7) – aldrig loopback (127/8, `::1`, `localhost`: selve containeren) eller link-local (169.254/16, fe80::/10), ingen værtsnavne, sti eller login. Proxy-variabler ignoreres, og omdirigeringer følges ikke. |
| **Model** (`model`) | `qwen2.5:7b` | Som navnet står i Ollama, fx `qwen3:8b` eller `gemma3:4b`. |
| **Fra / Til score** (`band_low`, `band_high`) | 3 / grænsen | Kun mails med en score i [fra, til) vurderes. Til er højst postkassens (effektive) grænse. |
| **Højst pr. time** (`max_per_hour`) | 120 | Alle postkasser tilsammen. |
| **Ventetid** (`timeout`) | 25 s | Svarer modellen ikke inden da, vurderes mailen uden AI. |

- **Hvilke mails:** Kun indbakke-mails, som den almindelige vurdering lader ligge, ulæste og uden stjerne. Aldrig kendte kontakter, svar, kendte domæner og faste afsendere (`TH_KNOWN_CONTACT`, `TH_REPLY`, `TH_REPLY_THREAD`, `TH_KNOWN_DOMAIN`, `TH_ESTABLISHED`), regler (også tilladte afsendere), brugerens dom, beskyttede adresser, trusler, falske afsendernavne (`TH_NAME_SPOOF`/`TH_NAME_SPOOF_TRIAL` – en kollega med en ny adresse må ikke skubbes over grænsen af AI'en), nyhedsbreve på vej til mappen og sene scanninger.
- **Hvad sendes:** Afsenderens navn og adresse, Reply-To, emne, dato, rspamds standard-regelnavne (aldrig filterets egne `TH_*`), link-domæner, vedhæftningernes navne og typer og de første 2000 tegn tekst (HTML fjernet). Mailen står mellem tilfældige markører, og modellen får besked på, at teksten er data og ikke instrukser. Kald: `POST /api/chat` med `format: json`, `temperature: 0`, `keep_alive: 10m`.
- **Point (Til):** `TH_AI_SPAM` +3 ved spam/phishing med sikkerhed ≥ 0,8 og +1,5 ved ≥ 0,6. Aldrig minuspoint. Når grænsen nås, flyttes mailen efter den normale `move_grace_seconds`, regnet fra scanningen. Et svar, der kommer senere, gør ingenting – heller ikke et rettidigt svar, som først bliver brugt mere end `move_grace_seconds` + 5 minutter efter scanningen (travl tråd, genstart). Prøv-tallet "Ville være flyttet med Til" bruger samme frist. Læste mails flyttes ikke for AI'ens skyld. Kun administratorer ser modellens begrundelse; en bruger ser "Den lokale AI-vurdering mente, at mailen var spam".
- **Fejl:** Timeout, fejl og ugyldigt svar betyder ingen virkning. Efter en fejl holder filteret pause i 1 → 2 → 4 … højst 15 minutter. Tilstanden står i `engine_state` → `ai_status` og vises i `sfctl doctor` (kun en advarsel).
- **Data:** tabellen `ai_verdicts` (postkasse, Message-ID, score før, dom, sikkerhed, begrundelse, model, svartid, tidspunkt, om den blev brugt). Ingen mailtekst. Ryddes efter 180 dage.

## Forbindelser og scoring

- Filteret bruger IMAP IDLE, hvor udbyderen kan det. Ellers spørger det ved polling.
- **Fejl hos udbyderen:**
  - Begrænser udbyderen forbindelserne (`[LIMIT]`, "Too many connections", timeout), venter filteret 5 → 10 → 20 → 30 minutter. Det tæller ikke som login-fejl.
  - Rigtige login-fejl stopper efter 3 forsøg og prøves igen efter 30 minutter, eller så snart adgangskoden skiftes.
- **Første start på en konto:** eksisterende mail scores ikke. Kun mail, der kommer efter UID-bogmærket, scores.
- **Afsenderkontekst:** `mailctx` finder den rigtige afsender bag udbydernes egne servere (Gigahost, Scannet, SpamExperts) og bag betroede videresendere. SRS fra videresendelse bliver pakket ud. Det er derfor, Rspamd vurderer den rigtige afsender-IP med SPF, DKIM og DMARC.
- **Rspamd-tilpasninger:**
  - `HIDDEN_TEXT` er begrænset til 2,0 point (`rspamd/local.d/groups.conf`), fordi nyhedsbreve ofte har skjult forhåndstekst.
  - Nyhedsbreve med `List-Unsubscribe`, gyldig DKIM og en kendt udsender får −1,5 (`TH_NEWSLETTER`), når de ellers ikke ligner spam.
- Fuzzy-opslag (skrivebeskyttede fællesfingeraftryk) er slået til med `ENABLE_FUZZY=1`.
- **2.3:** `MIME_BAD_ATTACHMENT` er sat ned fra 2,0 til 1,0 point i `groups.conf`, fordi filteret nu selv blokerer de farlige filtyper (`TH_ATTACH_BLOCK`, +20 og trusselsklassen "attachment"). Krypterede arkiver fra ukendte afsendere giver `TH_ENCRYPTED_ARCHIVE` +4.
- **2.3.6 lignende domæner:** `TH_LOOKALIKE_DOMAIN` (+6, trusselsklassen *lookalike*) for afsender, svar-til, konvolut og DKIM, `TH_LOOKALIKE_URL` (+4, kun point) for links og `TH_LOOKALIKE_ALLOWED` (0, info) når et fund er undtaget. Se `protected_domains` ovenfor.
- **2.3.6 Home Assistant:** `GET /api/v1/ha` (kun hjemmenetværket + bearer-nøgle, ellers 404 for alle metoder). Nøglen oprettes under **Indstillinger → Home Assistant** eller med `sfctl ha-token`; kun dens sha256 gemmes (`settings_kv`). Se [HOME-ASSISTANT.md](HOME-ASSISTANT.md) og [SECURITY.md](SECURITY.md).
- **2.11.0 API-nøgler:** flere navngivne nøgler til programmer under **Konti og adgang → Adgang for programmer** (eller `sfctl api-key`), gemt som sha256 i tabellen `ui_api_keys`. Den gamle Home Assistant-nøgle flyttes automatisk og virker videre. Login fra Kontrolrum (SSO) er flyttet til samme side.
- **2.3 tillid:** `TH_KNOWN_CONTACT` (−4/−3/−2), `TH_KNOWN_DOMAIN` (−1), `TH_REPLY` (−5), `TH_REPLY_THREAD` (−2), `TH_REPLY_UNVERIFIED` (0), `TH_ESTABLISHED` (−2) og `TH_FIRST_CONTACT` (+1). Kun det stærkeste kontaktsignal tæller, og al tillid (inkl. `TH_NEWSLETTER`) er tilsammen højst −6. `SCORE_VERSION` er uændret.


## Scanningdækning og lokal evaluering (2.15)

**Drift → Scanningens dækning** viser 14 kalenderdages hændelser pr. postkasse: scannet, læst før første kontrol, for stor, fejlede forsøg, opgivet scanning og mappeindhold, der ikke kunne bekræftes. En spam-mappeobservation uden body (fx oversize) ændrer ingen afgørelse eller læring. Et fejlet forsøg kan senere lykkes. Genscanninger, udbyderspam og læste mails har forskellige nævnere, så der vises ingen samlet scanningsprocent. Visningen er kun for administratorer og ændrer ingen mail eller træning.

Første normale scanning gemmes i `scan_observations` med score, effektiv grænse, beslutning, filterversion og tidspunkt. Senere AI-vurderinger overskriver ikke observationen. Den nye evaluering måler derfor **første scanning før AI**, ikke kvaliteten af en AI-model eller dens confidence. AI-model og prompt indgår ikke i dette mål; sammenlign kun observationer med samme grundlag og versionsgruppe.

Kør som ejer lokalt i containeren:

```sh
docker exec spamfilter sfctl quality-export --to /state/quality-sample.jsonl
docker exec spamfilter sfctl quality-evaluate /state/quality-sample.jsonl
```

Eksporten indeholder kun scorer, versioner, interne mail-/konto-ID'er og eksplicitte brugerafgørelser, ingen mailtekst, emner eller adresser. ID'er kan stadig identificere personer: filen oprettes som 0600, en eksisterende fil overskrives ikke, og filen skal blive lokalt. Den kræver observationer fra efter opgraderingen. Automatisk Bayes-læring bruges ikke som facit.

Hver linje er et JSON-objekt, eksempel:

```json
{"account":"mailbox-a","id":"sample-001","split":"holdout","label":"ham","score":2.0,"threshold":8.0,"prediction":"ham","version":"2.15.0"}
```

`label` er menneskets vurdering (`ham`/`spam`). `prediction` er filterbeslutningen inklusive regler; udelades den ved manuel import, bruges score >= threshold. Brug `split=train` for træningsmateriale og `split=holdout` for særskilt prøvemateriale. Identiske konto/ID-par, også på tværs af split, afvises. `train` tæller ikke med; værktøjet træner aldrig, kontakter ikke IMAP og flytter ingen mail. Maksimal inputfil er 10 MiB.

Resultatet viser TP/TN/FP/FN, precision, recall, falsk-positiv-rate, falsk-negativ-rate og prøvestørrelse pr. postkasse. Manglende nævnere giver `null`. Eksport af brugerrettelser er et **skævt udvalgt prøveudvalg** og ikke dokumentation for samlet træfsikkerhed eller et uafhængigt holdout. For en reel før/efter-måling skal ejeren udtage og menneskeligt mærke et repræsentativt, på forhånd reserveret udvalg, holde det ude af al træning og bruge samme scorergrundlag. Familiepost er ikke testet eller uploadet med denne udgivelse.

### Sammenlign baseline og kandidat (under udvikling)

Den næste udviklingsversion tilføjer en parret sammenligning. Den indgår ikke i
den oprindeligt publicerede 2.15.0-beta fra commit `108134d`.

```sh
docker exec spamfilter sfctl quality-compare /state/baseline.jsonl /state/candidate.jsonl
```

Begge filer følger JSONL-formatet ovenfor. Brug præcis de samme mails og
menneskelige labels. Kandidatens `score`, `threshold`, `prediction` og `version`
kommer fra en separat, kontrolleret afprøvning. Kommandoen kører ikke en kandidat
eller genscanner mails. Angiv `prediction`, når regler indgår i afgørelsen;
ellers bruges alene scoregrænsen.

Ændrede konto/ID-par, labels, train/holdout-placering, `basis` eller `selection`
afvises. Træningsrækker tælles ikke med. Rapporten viser før/efter pr. postkasse,
nye og rettede falske positiver/negativer samt SHA-256 for holdout-udvalget og
hver sides afgørelser. Rapporten indeholder ingen mail-ID'er, men kontonavne
kan stadig være personoplysninger. Hold både input og rapport lokalt.

En fanget rigtig mail vægtes som standard til 10 og en overset spam til 1.
`--false-positive-cost N` ændrer denne prioritering, ikke filterets regler.
Prisen er en valgt vægt, ikke en målt økonomisk omkostning.

`status` betyder:

- `regression_in_sample`: mindst én ny falsk positiv eller flere falske
  negativer i en postkasse. Rettelser i andre postkasser skjuler ikke problemet.
  En ny falsk positiv tæller også, når en anden falsk positiv samtidig rettes.
- `insufficient_sample`: ingen sådan tilbagegang fundet, men en postkasse
  mangler mindst 20 ham og 20 spam, eller holdout er tomt.
- `no_regression_in_sample`: ingen sådan tilbagegang i det leverede udvalg,
  og alle postkasser opfylder minimum. Nye og rettede falske negativer vises
  stadig hver for sig, også når det samlede antal er uændret.

`--min-per-class N` ændrer minimum. Grænsen er en praktisk datamængdekontrol,
**ingen statistisk garanti**. Resultatet beviser hverken repræsentativitet,
fravær af træningslækage eller en forbedring på fremtidig post. Eksport af
brugerrettelser beholder sin selektionsbias. Intet aktiveres automatisk.
CLI-exitkode 0 betyder, at sammenligningen kunne udføres; læs `status` i JSON,
hvis rapporten bruges i et script.

### Beslutningspolitik (under udvikling)

`decisionpolicy.py` samler den eksisterende prioritering for første scanning og
genkontrol før ventende flytninger i en ren funktion uden SQL, netværk eller
læring. Motoren vælger fortsat den aktuelle kontos afsenderregel og kontrollerer
mailidentitet og flag omkring kaldet. Resultatet har `policy_version=1` og en
stabil `reason`, fx `virus`, `sender_block`, `allow_distrusted` eller `score`.
`decision_traces` gemmer nu forbrugt policy-input og resultat ved første scan,
ved aktive genscanningsafgørelser og ved genkontrol af almindelige tilladelser
før flytning. Identiske spor for samme konto/mail/stadie deduplikeres, og
forældreløse spor slettes med kontoens normale oprydning af mailposter.
Sporene indeholder scorer, komplette symbolnavne, den valgte afsenderregel,
autentificeringsdomæner og relevante tidligere brugerafgørelser; ingen body
eller emne. De er lokale driftsdata og skal beskyttes sammen med databasen.

En lokal, skrivebeskyttet prøve kan bruge de seneste gemte første-scannings-input:

```sh
docker exec spamfilter sfctl policy-preview mailbox-a --threshold 10 --limit 100
```

Dette prøver den rene politik med en anden scoregrænse. Ingen indstilling gemmes,
og der scannes, flyttes eller trænes ingen mail. Trusselsprioritet, sticky
frigivelser og regelbeslutninger bevares. Uden `--threshold` kontrolleres, om den
nuværende politik kan reproducere de gemte afgørelser. Resultatet viser
antal ændrede afgørelser, afgørelsesgrunde, politikversioner og eventuelle ugyldige
spor. Der udskrives interne spor-ID'er, ikke mail-ID'er eller fulde regelinput.

Prøven bruger **de daværende regler og signaler**. Den er ikke en genscanning,
en måling mod menneskeligt facit eller en baggrundsprøve på levende trafik.
Asynkrone AI-/kampagneafgørelser og de omkringliggende IMAP-/ZAP-værn er endnu
ikke en komplet samlet beslutningshistorik. Udskillelsen og sporene ændrer ikke
beslutningsrækkefølgen, herunder at en allerede eksplicit frigivet mail bevarer
sin sticky brugerafgørelse.

### Reservér prøvemateriale mod fremtidig læring (under udvikling)

For en lokal `.eml`, der er udtaget til evaluering, kan ejeren reservere
indholdet **før** det bruges til træning:

```sh
docker exec spamfilter sfctl quality-reserve /state/evaluation/sample-001.eml --sample-id sample-001
```

Registret `quality_holdout` gemmer kun indholdsfingerprint, neutralt sample-ID
og tidspunkt i den eksisterende database. Mailteksten forbliver i ejerens lokale
fil. Hold den i en privat mappe og brug 0600 på mail- og facitfiler. Brug neutrale
sample-ID'er uden navne, adresser eller emner. Samme reservation kan gentages;
et ID kan ikke genbruges til andet indhold.

Matchende indhold bliver fremover sprunget over ved appens Bayes-læring og
tilføjelse til lokal fuzzy-genkendelse. Det gælder på tværs af postkasser og
Bayes-puljer, også ved import uden Message-ID, genopbygning og eksplicitte
læringshandlinger. Status er `held_out`, på dansk **Reserveret til evaluering –
ikke trænet**. Det giver ingen læringstæller eller falsk `learned_as`-registrering.
En allerede eksisterende fuzzy-post kan stadig fjernes ved en frigivelse.
Almindelig mailbehandling og ejerens handlinger er fortsat aktive; reservationen
er en afgrænsning af læring, ikke en beskyttelse mod flytning.

Reservation og lærings-POST deler en proceslås. En reservation venter på en
igangværende lærings-POST; efter reservationen er gemt, kan næste matchende POST
ikke starte. Et optaget eller utilgængeligt register giver en fejl frem for at
ignorere beskyttelsen. Hvis databasen er optaget af en skriver, afvises selve
reservationen uden ændringer; prøv igen senere.

**Det er ingen garanti for et uafhængigt holdout:** Kendt tidligere Bayes-læring
af samme fingerprint afvises, også fra en anden konto. Fravær af en lokal
registrering beviser ikke fravær af tidligere læring. Funktionen tilbagefører
hverken tidligere Bayes/fuzzy-læring eller træning uden for denne app. Fingerprint
ignorerer kendte transportheadere og linjeskift, men ændrede øvrige headere eller
indhold kan give et andet fingerprint. Ensartede eller videresendte varianter
skal derfor udtages samlet og vurderes særskilt.

Gem evalueringslabels i det lokale facitdatasæt. Brugerrettelser i WebUI kan
stadig ændre brugerafgørelser, kontakter og øvrige tilstande og skal ikke bruges
som en blind mærkningsproces. Der er endnu ingen automatisk repræsentativ
udtagning eller fuld kontrol af labels' påvirkning på alle tillidssignaler.
Databasen skal gendannes sammen med reservationerne ved backup/rollback;
ældre kode respekterer ikke den nye reservation.
