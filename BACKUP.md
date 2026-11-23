# Backup og gendannelse (2.4.0, krypteret backup ud af huset fra 2.6)

## Hvad bliver taget med

`deploy/backup-and-verify.sh` kører hver nat kl. 03:00 som Unraid User Script `Spamfilter-backup`. Arkivet hedder `operations/backups/spamfilter-<UTC>.tar.gz` (mode 0600) og indeholder:

- **SQLite-databasen**, taget med SQLites online-backup, så den er konsistent, mens filteret kører. Den rummer:
  - mailmetadata, regler og statistik
  - Brugeres rettigheder (`ui_users`)
  - to-trins-login (`ui_twofa`)
  - Fortryd-jobs, automatisk læring og kvitteringer
- **Redis' Bayes-data** som et frisk RDB-snapshot (BGSAVE)
- **`config/`**, dvs. `accounts.yml`
- **Hemmeligheder:**
  - IMAP-koder og `removed-secrets/`
  - `dashboard_users` og `dashboard_secret`
  - Rspamd- og Redis-koder
  - `contacts.key` (nøglen til Kendte kontakter) og `smtp.password` (mailserverens adgangskode, kun hvis den er gemt separat) – fra 2.3.0-opfølgningen, begge 0600 i arkivet
- **Revisionsloggen** `admin-audit.jsonl`
- **Konfiguration:** `rspamd/local.d`, `redis.conf` og `unbound.conf`
- **`versions.env`**, så du kan se, hvilken version backuppen er fra

**Nye hemmeligheder (2.3):** `state/contacts.key` og `state/smtp.password` kommer med i arkivet, når User Scriptet er opdateret (`./deploy/install-user-scripts.sh` – scriptets indhold kopieres ind i User Scriptet, så det skal køres igen efter opdateringen). Den isolerede gendannelsestest tjekker sha256, mode 0600 og ejer, og at `contacts.key` er præcis 32 byte. En hemmelighed, der er et symlink, følges aldrig: den springes over med en advarsel i loggen. Har du et arkiv fra før opdateringen, mangler de to filer: så laver filteret selv en ny nøgle og gennemgår Sendt igen (kontakter, du har fjernet i hånden, bliver aktive igen), og adgangskoden til mailserveren skal skrives igen under Indstillinger → Mailserver. Kopia tager dem altid med, fordi den tager hele `appdata`. Databasen har også de nye 2.3-tabeller (kendte kontakter, genscanning, udbakke, to-trins-login på mail, straks-advarsler og Bayes-genopbygningens arkiv pr. pulje).

**Én eller fire containere (2.4):** Scriptet finder selv ud af, om filteret kører i én container (2.4) eller i fire (2.0–2.3). I den ene container tages databasen som filterets bruger (10099) og Redis-snapshottet som Redis' bruger (999), og kontrollen bruger det samme billede. Arkivet har filen `meta/layout` med `aio` eller `legacy`.

**Kontrol:** Bagefter pakkes arkivet ud i en isoleret mappe og tjekkes i engangscontainere uden netværk. Der køres SQLite `integrity_check` og `redis-check-rdb`, med de samme billeder som de kørende containere. Live-mail og live-Redis bliver ikke rørt.

**Resultat:** Status skrives i `state/backup-status.json`. Siden **Drift → Backup** viser alderen. Går noget galt, kommer der en Unraid-notifikation.

**Oprydning:** Arkiver ældre end 14 dage slettes, men kun efter en vellykket kørsel.

**Off-site:** Den eksisterende Kopia-backup tager hele `/mnt/user/appdata`, også arkiverne, kl. 03:30 og krypterer den. Tjek i Kopia en gang imellem, at det seneste arkiv faktisk er med. Et lokalt arkiv beskytter ikke mod tab af NVMe-poolen.

Kør backuppen i hånden som root:

```sh
/mnt/user/appdata/spamfilter/source/deploy/backup-and-verify.sh
```

`recreate-filter.sh` og `recreate-infra.sh` tager selv en verificeret backup, før de skifter noget ud.

> **Arkiverne indeholder alle hemmeligheder:** IMAP-koder, sessionsnøglen og TOTP-hemmelighederne til to-trins-login. Kopiér dem kun til krypterede steder med begrænset adgang, og vis aldrig indholdet i chat eller logs.

## Krypteret backup ud af huset (2.6)

Ud over arkivet ovenfor (som ligger på nvme-disken i app-mappen) laver filteret selv **hver nat fra kl. 02:30** en krypteret backup på **Unraid-arrayet**, dvs. en anden disk. Kører containeren ikke kl. 02:30, tages backuppen, så snart den kører igen. Fejler den, prøves der igen hver time (højst 4 gange om dagen).

**Placering:** Containerens sti `/backup` = `/mnt/user/backup/spamfilter` på værten (Unraid-skabelonen: *Backup-placering*). `deploy/aio/update.sh` opretter mappen (ejer 10099, mode 0700) og tilføjer stien ved næste opdatering – **men kun hvis sharen `backup` findes**. Sharen skal ligge på en anden disk end app-mappen (her: `backup` på poolen nvme_data, mens app-mappen ligger på user), og den krypterede kopi sendes desuden til skyen (se *Kopi ud af huset*). Uden stien laver filteret ingen krypteret backup og skriver aldrig noget i app-mappen i stedet; Drift og `sfctl doctor` advarer.

**Indhold:** alt, der skal til en gendannelse:

- hele `state/`: databasen (taget med SQLites online-backup), brugere, to-trins-login, passkeys, indstillinger, `contacts.key`, `vapid_private.pem`, `smtp.password`, IMAP-koder, `removed-secrets/` og revisionsloggen
- `config/accounts.yml`
- de læsbare filer fra `rspamd/local.d`, `unbound.conf` og `unbound-forward-records.conf`
- Bayes-dataene som et frisk Redis-snapshot (`redis/dump.rdb`, taget med `redis-cli --rdb`)

Ikke med: midlertidige filer (heartbeat, `-wal`/`-shm`), status-filer og **selve backupnøglen**. `redis-config/redis.conf` og rspamds kodefiler kan filteret ikke læse; de står som "ikke med" i backuppen og laves igen ud fra `state/redis.password` og `state/controller.password`.

**Kryptering:** Hver fil `spamfilter-<UTC-tid>.sfbak` (mode 0600) er krypteret med AES-256-GCM med en tilfældig datanøgle. Datanøglen er pakket ind med en nøgle afledt (HKDF-SHA256) af backupnøglen. Headeren (format, tidspunkt, nøgle-id) og indholdslisten (alle filer med størrelse og sha256) er beskyttet, så enhver ændring, afkortning eller forkert nøgle opdages.

**Backupnøglen** er 32 tilfældige byte i `state/backup.key` (0600). Den laves ved første backup. **Vis den én gang, og gem den i din kode-manager:**

```sh
docker exec -it spamfilter sfctl backup-key show     # kun første gang; --again hvis den er mistet
docker exec -it spamfilter sfctl backup-key status   # findes den, nøgle-id, hvornår den blev vist
```

Uden nøglen kan ingen backup gendannes. Mister du app-mappen, er kode-manageren det eneste sted, nøglen findes.

**Opbevaring:** 14 daglige og 8 ugentlige backups (den nyeste pr. dag og pr. uge). Ældre slettes kun efter en vellykket backup, og kun filer med backupnavnet.

**Overvågning:** Drift → *Krypteret backup* viser seneste forsøg, seneste vellykkede backup, antal backups, nøglen og kopien ud af huset. `sfctl doctor` viser det samme. Er der ikke lavet en vellykket backup i 48 timer, kommer der en alarm på mail og telefon (samme vej som de andre alarmer). Mangler Bayes-dataene, gemmes backuppen, men den tæller ikke som vellykket.

**Kommandoer** (`docker exec -it spamfilter sfctl …`):

| Kommando | Hvad den gør |
|---|---|
| `backup-now` | laver en backup nu (`--if-older 20` = kun hvis den seneste er ældre end 20 timer) |
| `backup-list` | viser backupperne i `/backup` |
| `backup-verify FIL` | dekrypterer hele filen og tjekker alle kontrolsummer – skriver intet |
| `backup-restore FIL --to MAPPE` | gendanner til en **ny, tom** mappe; den kørende installation røres aldrig |
| `backup-key show` / `status` | se ovenfor |

`--ask-key` på `backup-verify` og `backup-restore` spørger efter nøglen fra kode-manageren (fx på en ny maskine, hvor `state/backup.key` er en anden).

### Kopi ud af huset (rclone)

User Scriptet **Spamfilter-offsite** (kl. 03:45, `deploy/backup-offsite.sh`, installeres med `./deploy/install-user-scripts.sh`) kopierer de krypterede backups fra de seneste 72 timer til rclone-målet `offsite:Backup/Spamfilter`:

- Rækkefølge: containerens egen backup kl. 02:30 → `backup-and-verify.sh` kl. 03:00 → kopien kl. 03:45. Finder scriptet ingen backup fra det seneste døgn, beder det først containeren om en (`sfctl backup-now --if-older 20`).
- Kun krypterede filer: navnet skal være `spamfilter-*.sfbak`, og filen skal starte med `SFBACKUP`. De ukrypterede `operations/backups/*.tar.gz` sendes aldrig.
- Altid via `rclone copy` til remoten – aldrig via FUSE-mountet `/mnt/disks/offsite_rclone`, så et hængende mount ikke kan fylde RAM'en. Alle kald har timeouts.
- Oprydning: filer med backupnavnet, der er ældre end 60 dage, slettes på remoten (`rclone delete --min-age 60d`).
- Status står i `state/offsite-status.json` og vises på Drift og i `sfctl doctor`. Fejl giver en Unraid-notifikation og en alarm-mail.
- Indstillinger (miljøvariabler i User Scriptet): `SF_OFFSITE_REMOTE` (tom = slået fra), `SF_OFFSITE_KEEP_DAYS`, `SF_RCLONE_CONFIG` (standard: rclone-pluginets `/boot/config/plugins/rclone/.rclone.conf`, hvis den findes).

Prøv det i hånden som root: `deploy/backup-offsite.sh --dry-run` viser, hvilke filer der ville blive kopieret.

**Overvågning og gendannelsesøvelse (2.12):** Host-monitoren advarer, når kopien ud af huset er ældre end 48 timer eller er fejlet. Hver 30. dag (og dagen efter en fejlet øvelse) henter `backup-offsite.sh` den nyeste krypterede backup fra remoten til en midlertidig mappe i backup-sharet, tjekker den med `sfctl backup-verify` (dekrypterer til ingenting og tjekker alle kontrolsummer, skriver intet) og sletter mappen igen. Resultatet står i `state/restore-drill.json` og på Drift → Krypteret backup. `SF_RESTORE_DRILL_DAYS=0` slår øvelsen fra.

### Gendan fra krypteret backup

1. Tjek backuppen: `docker exec -it spamfilter sfctl backup-verify spamfilter-<tid>.sfbak` (på en ny maskine med `--ask-key`). Hent den evt. først fra remoten med `rclone copy offsite:Backup/Spamfilter/spamfilter-<tid>.sfbak /mnt/user/backup/spamfilter/`.
2. Gendan til en ny mappe i containerens `/tmp` (ikke under `/backup` – de gendannede filer ligger i klar tekst, og backup-sharet kopieres måske videre): `docker exec -it spamfilter sfctl backup-restore spamfilter-<tid>.sfbak --to /tmp/gendan-<dato>`. Hent den ud på værten med `docker cp spamfilter:/tmp/gendan-<dato> /root/gendan-<dato>`; den har mapperne `state/`, `config/`, `appdata/` og `redis/`.
3. Byt filerne som under *Gendannelse* nedenfor (stop containeren, gem de nuværende `state/` og `config/` til side, kopiér de gendannede ind med ejer 10099:10099; `redis/dump.rdb` med AOF slået fra første gang). Behold `state/backup.key` fra den kørende installation, eller skriv nøglen fra kode-manageren ind i `state/backup.key` med en editor (ikke med `echo`, så havner den i shell-historikken), ejer 10099, mode 0600.
4. Slet gendannelsesmappen bagefter – både på værten og `/tmp/gendan-<dato>` i containeren. Den indeholder alle hemmeligheder i klar tekst.

## Det er ikke med i backuppen

- **Selve mailene.** De ligger hos mailudbyderen, og filteret sletter aldrig noget.
- **`operations/dashboard.initial-password`** (den første WebUI-kode). Den skal alligevel slettes.
- **Cloudflare-opsætningen** (tunnel og Access). Den ligger hos Cloudflare. Tunnel-tokenen ligger i `cloudflared`-containerens opsætning.

## Gendannelse

1. Stop kun spamfilteret, og lad andre containere være:
   - **Én container (2.4):** `docker stop -t 90 spamfilter`. Redis gemmer, når containeren stopper.
   - **Fire containere:** `spamfilter`, `spamfilter-rspamd` og `spamfilter-redis`.
2. Vælg et arkiv, og pak det ud i en **ny** root-only mappe. Tjek SQLite og Redis-snapshot på samme måde som backupscriptet gør. Udskriv aldrig hemmeligheder.
3. Tag en kopi af de nuværende `config/`, `state/`, `redis/` og `rspamd/local.d/`. Kopiér derefter arkivets filer tilbage med ejer 10099:10099 og mode 0600 (mapper 0700).
   - Gendan `spamfilter.db`, mens filteret er stoppet.
   - **Redis (Bayes-data):** Arkivet har kun `dump.rdb`. Redis kører med `appendonly yes`, og så læser Redis ved opstart **kun** AOF-filerne i `redis/appendonlydir/` og ser bort fra `dump.rdb`. Mangler AOF-filerne, starter Redis helt tomt og gemmer bagefter et tomt `dump.rdb` oven i det gendannede. Derfor skal Redis første gang starte med AOF slået fra:
     1. Flyt `redis/appendonlydir/` til side (fx `redis/appendonlydir.foer-gendannelse`), og læg arkivets `dump.rdb` i `redis/` med ejer 999:1000 og mode 0600.
     2. Ret linjen `appendonly yes` til `appendonly no` i `redis-config/redis.conf`. Ejer 999:1000 og mode 0600 skal bevares; tjek med `ls -ln`.
4. Start Redis, så Rspamd, så filteret. Med én container: `docker start spamfilter`, som selv starter delene i den rækkefølge.
5. Tjek, at Bayes-dataene er indlæst, og slå AOF til igen, mens Redis kører. Adgangskoden læses inde i containeren og gives videre via `REDISCLI_AUTH`, så den aldrig står på kommandolinjen eller i en log. Med fire containere hedder containeren `spamfilter-redis` og har ikke brug for `-u 999:1000`.

   ```sh
   R='export REDISCLI_AUTH="$(sed -n "s/^requirepass \"\(.*\)\"/\1/p" /usr/local/etc/redis/redis.conf)";'
   docker exec -u 999:1000 spamfilter sh -c "$R redis-cli DBSIZE"                    # skal være større end 0
   docker exec -u 999:1000 spamfilter sh -c "$R redis-cli CONFIG SET appendonly yes"
   docker exec -u 999:1000 spamfilter sh -c "$R redis-cli INFO persistence" | grep -E 'aof_enabled|aof_rewrite_in_progress'
   ```

   Vent, til den sidste kommando viser `aof_enabled:1` og `aof_rewrite_in_progress:0`. Redis har så skrevet nye AOF-filer ud fra de gendannede data. Sæt derefter `appendonly yes` tilbage i `redis-config/redis.conf`, så næste genstart bruger AOF igen.
6. Kontrollér:
   - helbred, login (også to-trins-login) og IMAP-login
   - UID-bogmærker og Rspamd-statistik
7. Vil du være ekstra forsigtig, så sæt konti i **Overvåg**, indtil du har set, at alt ser rigtigt ud. Gå derefter tilbage til **Filtrér**.

**Rollback af koden** (ikke data) står i [deploy/README.md](deploy/README.md):

- Hver `recreate` gemmer den forrige container som `<navn>-rollback`.
- 2.1 har kun tilføjet tabeller og kolonner, så 2.0.3 kan køre direkte på en database, der er migreret til 2.1.
- Ved rollback til 2.0.3 får Brugere igen alle tre rettigheder, og to-trins-login slås fra. Det er sådan 2.0 virkede.

Gendannelse på en anden maskine kræver de samme container-digests og kildetræet under `source/`. Hvis host-IP eller DNS er anderledes, skal WebUI-bindingen og Unbound-forwarderen tilpasses. Der er ikke lavet en destruktiv gendannelse på live-data. Dette dokument er en runbook.


## Gendannet opstart af app og Bayes (2.15)

Arkivverifikation og opstart er forskellige prøver. Den månedlige off-site-kontrol i den opdaterede `deploy/backup-offsite.sh` downloader fortsat arkivet og kontrollerer det. Den kører derefter `sfctl backup-drill`: dekryptering til en ny privat, midlertidig mappe, SQLite `quick_check`, indlæsning af den gendannede Redis RDB og HTTP-opstart af appen med den gendannede database. Status godkendes først efter begge trin. Et gammelt positivt resultat fra før 2.15 dokumenterer kun arkivkontrol. Allerede installerede Unraid User Scripts skal opdateres efter den normale installationsvej for at få scriptændringen med.

Manuel prøve i all-in-one-containeren, med et eksisterende krypteret arkiv:

```sh
docker exec spamfilter sfctl backup-drill /backup/spamfilter-YYYYMMDDTHHMMSSZ.sfbak
```

Brug arkivets faktiske navn; `--ask-key` spørger interaktivt efter en anden backupnøgle. Nøglen må ikke indgå i kommandolinjen. Prøven kræver både `spamfilter.db` og Redis/Bayes-dumpen. Den oprindelige installation og arkivet ændres ikke. Midlertidige processer stoppes og filerne slettes efter prøven. Der bruges ingen aktive konti eller mail-, SMTP-, trænings- eller push-arbejdere; Redis og HTTP lytter kun på private Unix-sockets. App-processen afviser udgående IP-forbindelser.

Dette bekræfter, at SQLite, applikationen og Redis-data kan indlæses. Det er ikke en fuld gendannelse af udbyderadgang, Rspamd/Bayes-scoring eller ClamAV-signaturer. Containerens særskilte `smoke-test.sh --learn-test` kontrollerer også rigtig Rspamd-scanning, læring og data efter genstart og udfører herefter denne backup/opstart-prøve på den tomme testinstallation. Mailudbydere og live-installation skal fortsat kontrolleres ved ejerens installation. En tom Bayes-base er tilladt ved manuel prøve; JSON-resultatet viser `redis_keys`.

### Ressourcegrænser i opstartsprøven (2.16)

De to prøve-underprocesser (Redis og HTTP-appen) får hver højst 1024 MiB
**virtuelt adresserum**, 30 CPU-sekunder og 128 åbne filer. Core dumps er slået
fra. En frisk Python-bootstrap sætter kernelgrænserne og erstatter sig selv
med den faktiske proces; der bruges ikke `preexec_fn` i den flertrådede app.
Prøvebørnene bruger `PYTHONMALLOC=malloc`, så store virtuelle allocator-arenaer
ikke optager budgettet før app-importerne. Den almindelige filterproces ændres ikke.

Et stort Bayes-dump kan kræve et andet budget, fx:

```sh
docker exec spamfilter sfctl backup-drill BACKUPFIL --memory-mib 2048
```

Grænsen skal være 128–4096 MiB pr. barn; vælg inden for containerens tilgængelige
ressourcer. Strengere, allerede arvede kernelgrænser bevares. JSON-resultatets
`child_limits` viser de anvendte maksimumsbudgetter. Fejlet indlæsning eller et
overskredet budget giver fejl; en gyldig arkivkontrol alene godkender ikke opstarten.
Begge børn stoppes ved afslutning eller fejl, og prøvens midlertidige kopi fjernes.

Budgetterne gælder **underprocesserne**. Dekryptering, udpakning og SQLite-
integritetskontrol kører fortsat i den kaldende proces under containerens
almindelige grænser. Der oprettes ingen ny container/cgroup. Rspamd, ClamAV,
eksterne tjenester og login på mailudbyderen er stadig uden for denne prøve.

### Separat offlineprøve af den gendannede AIO-stak (2.16)

Kør fra kildetræet på Docker-værten som root, med et lokalt bygget AIO-billede
som indeholder `stackrestore.py`:

```sh
deploy/aio/restore-stack-drill.sh --archive /sti/backup.sfbak \
  --key-file /privat/backup.key --image imap-spamfilter-unraid:VERSION
```

Nøglen læses fra en fil; selve nøgleværdien må ikke stå i kommandoen. Scriptet
ændrer ikke den oprindelige nøgle, backup eller kørende containere. Det kontrollerer fri diskplads før inputkopiering og igen før udpakning. Det opretter
sin egen private mappe under `operations/restore-drills`, dekrypterer kopien og
kontrollerer SQLite. Alle konti, ventende job, IMAP-/SMTP-hemmeligheder,
udbakke, push-abonnementer og AI-indstillinger fjernes eller deaktiveres i
kopien før opstart. Historik og databaseindhold er stadig private data.

Forberedelse og runtime kører i hver sin nye container med `--network none`,
ingen publicerede porte, skrivebeskyttet rodfilsystem og grænser for CPU,
hukommelse og processer. Scriptet kontrollerer Docker-daemonens faktiske
netværk, porte, mounts og ressourcegrænser **før** hver container startes.
Runtime får kun den nye appdata-kopi, hverken original installation,
backuparkiv eller nøgle. Standardbudgettet er 2048 MiB pr. container; vælg
512–4096 med `--memory-mib`. OOM, timeout eller manglende helbred giver fejl.

Prøven kræver grønt helbred for app, Rspamd, Redis og Unbound samt login-side
og scanning af en neutral mail. En tilfældig, neutral markør skrives til
**kopiens** RDB før runtime starter og læses derfra bagefter. Derved opdages
bl.a. en tom Redis-start, selv om HTTP og processer ellers svarer. Markøren
fjernes efter kontrollen. Læsbare Rspamd-/Unbound-konfigurationer fra backupen
bevares; manglende private servicekonfigurationer får billedets skabeloner med
de gendannede backendnøgler. RDB indlæses med AOF slået fra i kopien.

Det er en offlineprøve af disse fire dele. ClamAV startes bevidst ikke, fordi
signaturbasen ikke indgår i backupen; scriptet kontrollerer, at antivirus er
slået fra. Mailudbyderlogin, udgående DNS/SMTP, download af virusdefinitioner,
alle historiske custom-konfigurationer og faktisk træfsikkerhed godkendes
ikke af prøven. Oprydning fjerner kun containere med ID'er oprettet af denne
kørsel og dens egen mappe. Hvis Docker ikke kan fjerne en prøvecontainer,
bevares kopien, og scriptet returnerer fejl. Der installeres eller aktiveres
intet i produktion.
