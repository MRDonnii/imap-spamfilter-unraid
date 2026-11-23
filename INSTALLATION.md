# Installation og drift (2.4.0)

Fra 2.4 kører hele spamfilteret i **én container**, `spamfilter`. Filteret og WebUI'en, rspamd, Redis og Unbound kører indeni som hver sin proces med hver sin bruger. De fire containere fra 2.0–2.3 bruges kun til tilbagerulning, indtil de ryddes op.

## Placering

- **Server:** en Unraid-server, her i eksemplerne `192.168.1.10`.
- **Container:** `spamfilter` på Docker-netværket `bridge`. Netværket `spamnet` bruges kun af de gamle containere og fjernes ved oprydningen.
- **Appdata:** `/mnt/user/appdata/spamfilter/` (de samme data ligger også under `/mnt/user/appdata/spamfilter/`). Containeren ser mappen som `/appdata`.
- **Kildetræ på serveren:** `source/`. Det ejes af root, og kun root kan skrive i det, fordi root kører koden derfra.
- **WebUI:** `http://192.168.1.10:18080` (host-binding `192.168.1.10:18080 → 8080`, kun IPv4). Adgang udefra er valgfri og kun via Cloudflare Tunnel ([CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md)).
- **Unraid-skabelon:** `/boot/config/plugins/dockerMan/templates-user/my-spamfilter.xml`. Docker-fanen viser derfor ikon, WebUI-link og "Edit" i stedet for "3rd Party".

## Indhold af containeren

| Del | Kører som | Lytter på | Data i app-mappen |
| --- | --- | --- | --- |
| Filter + WebUI | uid 10099 | `0.0.0.0:8080` (den eneste åbne port) | `state/`, `config/` |
| rspamd 4.2.2 | uid 11333 | `127.0.0.1:11333/11334` | `rspamd/local.d/`, `rspamd/data/` |
| Redis 8.10.2 (Bayes) | uid 999, gid 1000 | `127.0.0.1:6379`, med adgangskode | `redis/`, `redis-config/redis.conf` |
| Unbound 1.22 (DNS) | brugeren `unbound` | `127.0.0.1:5353` | `unbound.conf` (ellers billedets egen) |

- **tini** er PID 1 og starter **supervisord**. Rækkefølgen er Redis → Unbound → rspamd → filteret. rspamd venter på Redis og Unbound, og filteret venter på rspamd.
- **Selvreparation:** Går en del ned, genstarter supervisord den med stigende pause (2 s op til 60 s), mens resten kører videre. Kan en del slet ikke starte, stopper containeren, og Docker starter den igen.
- **Stop:** Filteret stopper først og får 40 sekunder til at gøre sit arbejde færdigt. Redis stopper sidst og gemmer.
- **Log:** `docker logs spamfilter` viser alle fire dele. Hver linje starter med `[filter]`, `[rspamd]`, `[redis]`, `[unbound]` eller `[init]`. supervisords egne linjer om start og stop af delene står uden præfiks.
- **Samme ejere som før:** Containeren genbruger app-mappen **uændret** med de samme uid'er som de fire containere. Ingen fil skal have ny ejer. Filer, der nævner de gamle værtsnavne (`spamfilter-redis`, `spamfilter-unbound`), bliver aldrig rettet. Ved hver start skrives en kopi med `127.0.0.1` i `/run/spamfilter` (tmpfs). Derfor kan de fire gamle containere altid startes igen.
- **rspamds styring kræver altid adgangskoden** i den ene container. Med fire containere slap rspamds egen container for adgangskoden (127.0.0.1). Nu deler alle fire dele samme 127.0.0.1, så ingen del slipper. Filteret har altid sendt adgangskoden.
- **Unbound bruger port 5353** (en almindelig port). Containeren har derfor ikke brug for en særlig `sysctl`, og ingen anden del kan overtage en DNS-port.
- **Stierne fra før** findes stadig i containeren (`/state`, `/config`, `/data`, `/usr/local/etc/redis`) som links ind i `/appdata`. `accounts.yml`, backup og `docker exec -it spamfilter sfctl ...` virker som før.

## Billeder

Alt står i `deploy/versions.env`, som er den eneste kilde for versioner:

| Billede | Reference |
| --- | --- |
| **Spamfilter (alt-i-én, bygges lokalt)** | `imap-spamfilter-unraid:2.4.0` fra `deploy/aio/Dockerfile` |
| rspamd-base (den samme som før) | `rspamd/rspamd@sha256:8cf5758773a9b4b2510243c4e3c38930f0e51a12937bdb4891519591bd37b5e5` |
| Filter-base (Python 3.14) | `ghcr.io/marcelverdult/imap-spamfilter@sha256:11b10295f03a7eb503c7cf40a370334f33a902ca3470b28ce1a344a2bed85f7c` |
| Redis-binære filer | `redis:8.10.2-trixie@sha256:97ec8815…` (låst i `REDIS_AIO_DIGEST`; Redis' medfølgende moduler indlæses ikke, og Bayes-dataene har ikke brug for dem) |
| Unbound, tini, supervisor | Debian 13-pakker i rspamd-basen. De præcise versioner står i billedet i `/usr/local/share/spamfilter-aio/packages.txt` |
| Kun til tilbagerulning | `imap-spamfilter-unraid:2.4.0-filter` (filter-billedet til de fire containere) og de gamle Redis- og Unbound-billeder |

Billedet bygges med `deploy/aio/build.sh`. Byggeriet stopper, hvis noget ikke stemmer:

- rspamds egne filer skal være uændrede efter kopieringen af Python og Redis.
- Versionerne skal passe.
- Alle delte biblioteker skal findes.
- Brugerne 10099, 11333, 999:1000 og `unbound` skal findes.
- En prøvekonfiguration skal bestå `rspamadm configtest` og `unbound-checkconf`. Alle rspamd-workere skal lytte på 127.0.0.1, og rspamds styring må ikke lade nogen slippe for adgangskoden.

GitHub bygger og tester det samme billede ved hver ændring. Ved en release bygges billedet én gang, det prøvekøres, og præcis det testede billede lægges i den private pakke `ghcr.io/mrdonnii/imap-spamfilter-unraid` som `:<version>` og `:beta`.

## Ressourcer

| Container | RAM | CPU | PIDs | Healthcheck |
| --- | ---: | ---: | ---: | --- |
| `spamfilter` | 3 GiB | 4 | 512 | Alle fire dele: heartbeat og `/healthz`, rspamd svarer "pong", Redis svarer PONG med adgangskoden, Unbound svarer |

- logrotation `10m × 3`
- restart-politikken `unless-stopped` og Unraids autostart-liste
- `--cap-drop ALL`, kun `CHOWN`, `SETUID`, `SETGID` og `KILL` tilbage (supervisord skifter bruger pr. del), og `no-new-privileges`
- Kun port 8080 er udgivet, bundet til `192.168.1.10:18080`

## Flytning fra fire containere til én (én gang)

Den præcise opskrift med kontrol og tilbagerulning står i [.build/RELEASE-2.4.0.md](.build/RELEASE-2.4.0.md). Kort fortalt, som root på serveren i `source/`:

1. `./deploy/aio/build.sh` bygger billedet `imap-spamfilter-unraid:2.4.0`, og `./deploy/install-user-scripts.sh` lægger de nye backup- og monitorjob ind. De virker med både fire containere og én, så de skal ind **før** flytningen.
2. `./deploy/aio/smoke-test.sh` starter en **prøvecontainer** på `127.0.0.1:18090` med en kopi af nattens backup. I kopien kan ingen konto logge ind: alle er slået fra, peger på `127.0.0.1` port 1 og har ingen adgangskode, uanset hvor koden lå før. Ventende fortryd- og træningsjob fra backuppen annulleres, IMAP- og mailkoderne fjernes, og mail slås fra. Mailserverne peger desuden på containeren selv. Ingen postkasse bliver rørt. Kopiens Redis læser backuppens `dump.rdb` (AOF er slået fra i kopien). Testen tjekker de fire dele, Bayes-tallene og login-siden. Bagefter slettes prøvecontaineren og kopien.
3. `./deploy/aio/migrate.sh --dry-run` viser planen, og `./deploy/aio/migrate.sh` udfører den. Kør den i `tmux` eller `screen`. Ctrl-C eller en afbrudt SSH-forbindelse ruller stadig tilbage, men så mister du ikke skærmen:
   - Først tages en backup.
   - Tallene noteres: version, kontiernes tilstand, Bayes og antal Redis-nøgler.
   - De fire containere stoppes. De slettes **ikke**, og `spamfilter` omdøbes til `spamfilter-legacy`.
   - Unraid-skabelonen lægges ind, og den nye `spamfilter` startes.
   - Kontrol: alle fire dele er sunde, version 2.4.0, de samme konti er forbundet, og Bayes og Redis har de samme data (et par mails, der læres om undervejs, er tilladt). Home Assistant-endpointet svarer 404 uden nøgle eller 200 med `SF_HA_TOKEN`.
   - Fejler noget, rulles der automatisk tilbage til de fire containere.
4. Efter nogle gode dage: `./deploy/aio/cleanup.sh --dry-run` og derefter `./deploy/aio/cleanup.sh --yes`. Det fjerner de stoppede gamle containere, netværket `spamnet` og de gamle billeder. Andre containere og billeder bliver aldrig rørt.

**Tilbage til de fire containere**, så længe oprydningen ikke er kørt: `./deploy/aio/rollback.sh --yes`. Den nye container stoppes først, så to Redis-servere aldrig bruger de samme data. Derefter startes de fire igen i den rigtige rækkefølge, også i Unraids autostart-liste. Alt, hvad den nye container har lært, er med, fordi de bruger de samme filer. `rollback.sh` reparerer også, hvis en flytning blev afbrudt, før noget var omdøbt.

**Start aldrig de gamle, stoppede containere i hånden** (`spamfilter-redis`, `-rspamd`, `-unbound`, `spamfilter-legacy`), mens den nye kører, heller ikke med "Start all" eller autostart-knappen. Den gamle Redis ville bruge de samme Redis-data som den nye og ødelægge Bayes-dataene. Overvågningen (2.4) giver straks en alarm og stopper en gammel Redis, den finder kørende ved siden af den nye container. Vejen tilbage er altid `rollback.sh`.

## Opdatering til en ny version (efter flytningen)

1. Tag en kopi af det nuværende `source/`, og kopiér det nye kildetræ ind. Sæt derefter `root:root` og `go-w` på det. Lokale indstillinger (fx `TRUSTED_PROXIES=192.168.1.10`) står i `operations/site.env` og overlever kopieringen.
2. `./deploy/aio/update.sh --build` gør resten:
   - bygger billedet og tager backup
   - stopper `spamfilter` og gemmer den som `spamfilter-rollback`
   - starter den nye version med de samme parametre og tjekker de fire dele
   - starter den forrige igen, hvis tjekket fejler
3. Efter et bestået tjek opdateres skabelonen, `spamfilter-rollback` fjernes (behold den med `--keep-rollback`), og billeder ældre end den forrige version slettes. Det kørende og det forrige billede bevares altid.
4. Er `deploy/host-monitor.sh`, `deploy/backup-and-verify.sh` eller `deploy/update-runner.sh` ændret, så kør `./deploy/install-user-scripts.sh`.

Alle scripts kan køres med `--dry-run` først. Se [deploy/README.md](deploy/README.md).

### Opdatering fra WebUI'en (2.10)

Siden **System → Opdateringer** viser den kørende version, den nyeste udgivelse på GitHub (kanal Beta eller Stabil) og ændringerne i de nyere versioner. **Opdatér nu** gør det samme som trin 1–3 ovenfor, men containeren kan ikke selv bygge eller skifte sig ud. Den skriver kun en lille, signeret anmodning med versionsnummeret i `state/update/`. Værtens hjælper, User Script **Spamfilter-update** (hvert minut), henter anmodningen, tjekker den felt for felt, henter kildepakken `spamfilter-X.Y.Z-source.tar.gz` for netop den version fra GitHub, tjekker kontrolsummen mod både udgivelsens `.sha256`-fil og GitHubs egen, tager backup af `source/` (`operations/source-backups/`, de tre nyeste gemmes), lægger det nye træ i `source/` og kører `deploy/aio/update.sh --build`. Fejler det, lægges det gamle `source/` tilbage, og den hidtidige container kører videre (eller er rullet tilbage). Status og de sidste loglinjer vises på siden; hele loggen ligger i `operations/update-runner-<tid>.log`.

Opsætning én gang på værten:

1. Skriv repoet i `operations/site.env`: `SF_UPDATE_REPO=ejer/navn`.
2. Er repoet privat, så gem en GitHub-token med læseadgang (fine-grained, *Contents: Read* på repoet) under **Indstillinger** på siden. Den gemmes krypteret, og fra 2.11.2 gives den med til hjælperen, når du trykker **Opdatér nu** (bundet til netop den anmodning, kun brugt mod repoet fra `site.env`, slettet når pakken er hentet, aldrig i log eller backup). Vil du hellere have tokenen på værten, så læg den i `operations/github-token` (`root:root`, `0600`); den går altid forud for sidens.
3. `./deploy/install-user-scripts.sh` lægger **Spamfilter-update** ind.
4. `./deploy/aio/update.sh --build` én gang, så containeren kender `SF_UPDATE_REPO`.

`deploy/aio/update.sh` installerer User Scripts igen efter hver vellykket opdatering (fra 2.11.2), så hjælperen altid passer til den version, der kører.

**Fra 2.11.0/2.11.1 til 2.11.2 (én gang):** Den gamle hjælper kender ikke tokenen fra siden, men den bruger en token-fil på værten og kører den nye versions `deploy/aio/update.sh`, som installerer den nye hjælper. Så:

1. Som root på værten: `umask 077; read -rs T; printf '%s\n' "$T" > /mnt/user/appdata/spamfilter/operations/github-token; unset T` (indsæt tokenen, Enter). Tjek med `stat -c '%U %a' …/operations/github-token` → `root 600`.
2. Tryk **Opdatér nu** ved 2.11.2 på siden (kanal **Beta**, hvis 2.11.2 er en Beta-udgivelse). Vent til "Opdateret til v2.11.2".
3. Slet værtsfilen igen: `rm -f /mnt/user/appdata/spamfilter/operations/github-token`. Ellers går den altid forud for sidens token, også når den udløber.
4. Efter et minut viser rækken **Hjælperens GitHub-adgang** "WebUI'ens token". Fremover er **Opdatér nu** nok.

Virker det ikke, så installér 2.11.2 manuelt som en almindelig opdatering (kildepakken pakket ud i `source/`, derefter `./deploy/aio/update.sh --build`). Kun udgivelser med kildepakke (fra 2.10.0, lavet af release-workflowet) kan installeres herfra, og kun nyere versioner end den, der kører. `./deploy/update-runner.sh --dry-run` tjekker en ventende anmodning uden at installere noget.

**Efter opdateringen** flytter filteret kun tydelig spam (grænsen + 5) i de første 30 minutter. Resten venter i køen.

**Ret ikke containeren under Docker → Edit** uden grund. Skabelonen svarer præcist til scriptets parametre. Porten er bundet til `192.168.1.10` under *Extra Parameters*, og stien *rspamd-data* skal pege på `rspamd/data` i app-mappen.

## Ny installation fra bunden

Det er kun nødvendigt ved genetablering:

1. Læg `my-spamfilter.xml` (fra `deploy/aio/unraid-template.xml`) i `/boot/config/plugins/dockerMan/templates-user/`, byg billedet med `deploy/aio/build.sh`, og opret containeren fra skabelonen. Alternativt: hent `ghcr.io/mrdonnii/imap-spamfilter-unraid:<version>` med en læsenøgle fra GitHub.
2. Er app-mappen tom, opretter den første start selv mappestrukturen og de samme ejere. Den laver også adgangskoderne til Redis og rspamd, som gemmes med mode 0600 og aldrig vises. En eksisterende eller halv installation bliver aldrig ændret.
3. Første login: `docker exec -it spamfilter sfctl create-admin admin --generate`.
4. Log ind og udfyld **Indstillinger → Lokal opsætning** (servernavn, egne domæner, webshops, administratorens mailadresse). Sæt `WEBUI_BIND=<serverens LAN-IP>` i `operations/site.env` på værten.
5. `./deploy/install-user-scripts.sh` for backup og monitor.

## Datamapper

| Sti | Indhold | Ejer / mode |
| --- | --- | --- |
| `config/accounts.yml` | Kontoindstillinger uden koder | 10099, 0600 (mappe 0700) |
| `config/site.yml` | Lokal opsætning: servernavn, egne domæner, webshops, platforme, adresser (se CONFIGURATION.md). Skrives kun fra WebUI'en, aldrig af en opdatering | 10099, 0600 |
| `state/imap-secrets/` | Én IMAP-kode pr. konto | 10099, 0600 |
| `state/spamfilter.db` | SQLite (WAL): mails, regler, statistik, brugerrettigheder, to-trins-login, Fortryd-jobs | 10099, 0600 |
| `state/dashboard_users`, `dashboard_secret`, `controller.password`, `redis.password`, `admin-audit.jsonl` | Fortrolige filer | 0600 |
| `state/contacts.key` | Nøgle til hashing af kendte kontakter | 10099, 0600 |
| `state/smtp.password` | Mailserverens adgangskode, kun hvis den er gemt separat | 10099, 0600 |
| `state/heartbeat`, `host-status.json`, `backup-status.json` | Status, skrevet af filteret og af værtens cron | 0644 |
| `redis/`, `redis-config/redis.conf` | Bayes-data (AOF/RDB) og Redis' konfiguration med adgangskode | 999:1000 |
| `rspamd/data/`, `rspamd/local.d/` | Rspamds tilstand og konfiguration | 11333 |
| `unbound.conf` | Unbound-konfigurationen (findes den ikke, bruges billedets) | root, 0644 |
| `operations/` | Backups, logs fra flytning og opdatering (`aio-*.log`), monitorens tilstand | kun root |

Kun i containeren (tmpfs, forsvinder ved genstart): `/run/spamfilter/` med de genererede kopier af rspamd- og Unbound-konfigurationen, supervisords socket og `health.json` (seneste samlede sundhedstjek).

## Værtsjob (Unraid User Scripts)

| Job | Tid | Gør |
| --- | --- | --- |
| `Spamfilter-backup` | 03:00 | Konsistent backup og gendannelsestest ([BACKUP.md](BACKUP.md)). Finder selv ud af, om det er én eller fire containere. |
| `Spamfilter-monitor` | hvert 5. min | Skriver `host-status.json` til siden Drift og sender Unraid-alarmer (se nedenfor). Hver morgen efter 07:00 sender det også den daglige opsummering. Med én container viser det delenes tilstand og nævner den del, der fejler, i alarmen. |

Monitoren sender en alarm, når:

- en konto **Svarer ikke** (bekræftet ved to kørsler)
- **Nødbremsen** slår til (med det samme)
- **Udbyder begrænser** har varet over 30 minutter
- **Login fejler** har varet over 15 minutter
- containeren er **usund** i over 5 minutter (med navnet på den del, der fejler)

Når problemet er væk, kommer der en "OK igen"-besked.

Scriptenes indhold kopieres direkte ind i User Scripts, så de kører ikke fra appdata. Kør derfor `install-user-scripts.sh` igen, hver gang de to scripts ændres. Ved flytningen til 2.4 skal det ske før `migrate.sh`.

## Fejlsøgning

| Tjek | Kommando |
| --- | --- |
| Kører containeren, og er den sund? | `docker ps --filter name=spamfilter` |
| Hvilken del fejler? | `docker exec spamfilter sf-health check` |
| Delene i supervisord | `docker exec spamfilter supervisorctl status` |
| Genstart én del | `docker exec spamfilter supervisorctl restart rspamd` (eller `redis`, `unbound`, `filter`) |
| Alt på én gang | `docker exec -it spamfilter sfctl doctor` |
| Version og liveness | `curl -fsS http://192.168.1.10:18080/healthz` |
| Tilstand pr. konto | `curl -fsS http://192.168.1.10:18080/api/health` |
| Er alle konti indlæst? | `docker logs spamfilter 2>&1 \| grep "loaded"` |
| Kun rspamds linjer | `docker logs --since 1h spamfilter 2>&1 \| grep '^\[rspamd\]'` |
| Lytter kun WebUI'en udadtil? | `docker exec spamfilter sf-health listeners` |

## 2.18.0 beta: installation og kontrol

Denne udgivelse leveres som signeret kildepakke til den eksisterende WebUI-opdatering. Vælg **System → Opdateringer → Beta**, kontroller version 2.18.0 og brug **Opdatér nu**, når du vil installere. Værtshjælperen verificerer pakken og bygger containeren lokalt som beskrevet ovenfor. Der publiceres ikke et nyt GHCR-image i denne kildebaserede udgivelse; CI bygger og prøver begge images, og all-in-one-prøven bruger en tom testinstallation.

Tag en aktuel backup før installation. Efter opdateringen: kontroller versionsnummer, `sfctl doctor`, kontoernes forbindelser og **Drift → Scanningens dækning**. Dækningstabellen kræver nye hændelser; gamle brugerrettelser uden en ny første-scanningsobservation kan ikke indgå i den nye evaluering. En ældre frigivelse uden indholdsfingerprint kan kræve genfrigivelse, hvis mailen leveres til indbakken på ny.

Den eksisterende opdateringsmekanisme bevarer det tidligere image og kildebackup til teknisk rollback. Skemaændringerne er additive, men gammel kode har igen de ID-fejl, som 2.15 retter. Brug derfor ikke en rollback som en vedvarende sikkerhedsløsning. Ved fuld datagendannelse skal kode, state og Redis passe sammen; følg BACKUP.md. Denne udgivelses arbejde ændrer ikke i sig selv din server eller dine postkasser.


**Ældre beskeder:** Hvis en handling på en gammel post siger, at mailen ikke findes, brug **Find en mail** på afsender/emne og vælg den konkrete kopi. Gamle ID'er uden indholdsbinding bruges ikke til at genfinde post til læring eller reparation. Dette kan også efterlade gamle afbrudte kopiflytninger til manuel kontrol. Eksisterende virusmarkeringer mister ikke administratorkravet ved denne genfinding.


**Nyt i 2.16:** Sammenligning/reservation af lokale prøver, beslutningsspor,
read-only grænsepreview, parallel kandidatgrænse pr. konto, AI-proveniens,
rettelse af forsinkede AI-grænser og historiske forklaringer. Drift viser
antivirus/alder og ventende arbejde; manglende målinger er ukendte. Ingen
kandidat aktiveres automatisk, og ingen ny familietræfsikkerhed er målt.

Den separate gendannelsesprøve startes bevidst på værten med
`deploy/aio/restore-stack-drill.sh`, som beskrevet i BACKUP.md. Den bruger en
privat kontoløs kopi uden netværk eller publicerede porte. App/Rspamd/Redis/
Unbound kontrolleres; ClamAV-signaturer og udbyderlogin er undtaget. Den
månedlige eksisterende app/Redis-prøve erstattes ikke automatisk.

Ved rollback til kode før 2.16 håndhæves hverken de nye læringsreservationer
eller rettelsen af forsinkede AI-grænser. De additive tabeller kan blive
liggende, men gamle programmer kan lære af reserveret materiale. Gem derfor
vurderingsgrundlaget separat, og planlæg rollback bevidst.

**Nyt i 2.17:** Personlige valg om legitime nyhedsbreve starter ikke længere
kampagner på andre postkasser. AI- og kampagnefaser kan gengives fra lokale
beslutningsspor med `sfctl policy-preview --stage`. Kampagner respekterer også
frigivelser, nye tilladelser, hævede scoregulve og stop under IMAP-kontrollen.
De nye AI-angrebsprøver bruger syntetiske data; reel modelkvalitet og kalibrering
kræver fortsat ejerens lokale, menneskeligt mærkede udvalg.

**Nyt i 2.18:** **Husk gentagen spam automatisk** er slået til som standard pr.
konto. Kun tre nye, forskellige og afsenderbekræftede brugerrettelser inden
for 30 dage tæller; gammel historik udløser ingen blokering ved installation.
Slå eventuelt fra under kontoen før de nye rettelser. Højst fem nye regler
pr. konto pr. døgn. Se CONFIGURATION.md for præcis afgrænsning og fortrydelse.
