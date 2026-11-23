# Sikkerhed og databeskyttelse (2.3.0, opdateret 2.4.0)

## Eksponering

- **Kun WebUI'en har en host-port.** Den er bundet til `192.168.1.10:18080`, kun IPv4 og kun LAN.
- **Ingen offentlig port.** MX og SMTP er uændret, og filteret har ingen egen mailserver. Fra 2.3 kan filteret **sende** mail som en almindelig klient gennem udbyderens SMTP-server (udgående forbindelse, se **Mail fra filteret**). Det lytter aldrig selv efter mail.
- **Interne tjenester (2.4: én container).** Redis, Rspamd og Unbound kører i samme container som filteret og lytter kun på `127.0.0.1`. Udefra, og fra andre containere, kan kun WebUI'ens port 8080 nås. `docker exec spamfilter sf-health listeners` tjekker det. Med de fire gamle containere (2.0–2.3) lå de kun på Docker-netværket `spamnet`.
- **Rspamds styring (2.4).** Med fire containere slap kun processer i rspamds egen container for styringens adgangskode. I den ene container deler alle dele samme `127.0.0.1`, så ingen slipper længere (`secure_ip` sættes til en adresse, ingen bruger, i kopien i `/run/spamfilter` og i billedet). Ellers kunne en del, der blev overtaget, fx Unbound, lære spam og ham uden kode og forgifte Bayes. Byggetjekket stopper, hvis rspamd stadig lader 127.0.0.1 slippe. Filteret og scripts sender altid adgangskoden, og den forlader aldrig containeren.
- **ClamAV (2.7).** `clamd` lytter ikke på nogen IP-adresse, kun på en unix-socket i `/run/spamfilter/clamav`. Mappen ejes af clamav (uid 3310) med gruppen rspamd (11333) og mode 0750, så kun clamd selv og rspamd kan bruge den – ikke filteret, Redis eller Unbound. clamd får mailens dele som datastrøm og læser ingen filer i app-mappen. `clamd` og `freshclam` kører som uid 3310; signaturerne ligger i `<app-mappe>/clamav` (0750). `freshclam` henter over https fra ClamAVs officielle spejl og tester en ny database, før clamd bruger den. Fejler ClamAV, bliver mailen scannet uden virustjek (ingen point), og der advares – det er et bevidst valg, så en nedetid hos ClamAV aldrig stopper filteret.
- **Unbound på port 5353 (2.4).** Unbound lytter på en almindelig port. Containeren behøver derfor ingen `sysctl` til lave porte, og ingen anden del kan tage en DNS-port, mens Unbound genstarter.
- **Containeren er låst ned:**
  - grundbillederne er låst til digests, og rspamd er det samme billede som før
  - der er CPU-, RAM-, proces- og loggrænser, `--cap-drop ALL` og `no-new-privileges`
  - kun `CHOWN`, `SETUID`, `SETGID` og `KILL` er tilbage. Dem bruger supervisord til at give hver del sin egen bruger (10099, 11333, 999, `unbound` og fra 2.7 3310 til ClamAV) og til at stoppe dem
  - root i containeren har ikke `DAC_OVERRIDE` og kan derfor ikke læse delenes filer. Sundhedstjek, backup og `sfctl` skifter til den rigtige bruger
- **Adgang udefra er valgfri** og kun via Cloudflare Tunnel med Cloudflare Access foran ([CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md)). Der åbnes ingen router-port. Uden tunnel skal WebUI'en kun bruges fra LAN eller via en eksisterende VPN.

## Adgangsstyring

- **Roller:**
  - **Administrator** ser alt.
  - **Bruger** ser kun de postkasser, administratoren har valgt, og har kun de rettigheder, der er givet: frigive og flytte post, tillade og blokere afsendere for egne postkasser, se alle beskeder.
- **Én central politik.** Hver rute har præcis én adgangsregel (`public`, `login_required`, `admin_required` eller `permission_required`). Den kontrolleres for hver forespørgsel, før CSRF-tjekket. En rute uden regel svarer 404 (fail closed). `tests/test_ui_access.py` afprøver hele matricen for administrator, Brugere med og uden rettigheder og anonyme.
- **Fremmede data svarer 404.** Det gælder sider, JSON, fragmenter, søgninger, Fortryd-jobs og massehandlinger. Tal, grafer, badges og søgeresultater filtreres til Brugerens egne postkasser.
- **Kun for administratorer:** Konti, Træning, Drift, Indstillinger, Brugere, fælles regler og Altid igennem. En Bruger kan ikke lave en regel, der overlapper en Altid igennem-regel.
- **Se som bruger** (`/users/<navn>/preview`):
  - kun for administratorer, og ikke på en anden administrator
  - visningen er skrivebeskyttet: ingen CSRF-nøgle, alle formularer er slået fra, POST giver 405, og der gemmes intet for Brugeren
  - hver visning revisionslogges (`user_preview`)
- **Kun lokalt (2.3).** En bruger kan sættes til **Kun lokalt (hjemmenetværket)** (tabellen `ui_login_scope`, ingen række = Overalt):
  - En forespørgsel er kun lokal, når den direkte afsender ligger i `LOCAL_NETWORKS` (standard: de private net, loopback og link-local) **og** ikke kommer fra en betroet proxy **og** ikke har nogen videresendings-header (`X-Forwarded-For`, `CF-Connecting-IP`, `CF-Ray`, `Forwarded`, `X-Real-IP`, `True-Client-IP`). Headere kan altså kun gøre en forespørgsel til "udefra", aldrig til "lokal". Alt gennem Cloudflare Tunnel er udefra.
  - Det håndhæves ved login (før adgangskoden tjekkes, med samme fejlside og samme pbkdf2-arbejde som en forkert kode, og det tæller i spærringen), ved to-trins-trinnet og ved hver forespørgsel i en eksisterende session, også Husk mig (sessionen ryddes).
  - Hver blokering skrives i revisionsloggen som `login_blocked_external`. Kan tabellen ikke læses, behandles brugeren som Kun lokalt (fail closed).
  - En administrator kan ikke sætte sig selv til Kun lokalt fra en forespørgsel udefra. Er alle administratorer Kun lokalt, vises en advarsel.
- **Farlig post (2.3).** Mails med en trusselsklasse (virus, phishing-link, malware-link, farlig vedhæftning) kan kun lægges tilbage af en administrator, efter en eksplicit bekræftelse. Kald uden administrator-flag behandles som Bruger (fail closed). En frigivet trussel læres aldrig som legitim, og afsenderen tillades aldrig automatisk. Filnavne og virusnavne fra mailen renses for styretegn (RTLO, zero-width) og escapes, før de vises.
- **Home Assistant-API'en (2.3.6).** `GET /api/v1/ha` har sin egen centrale politik, `ha_token`, i samme kontrol som alle andre ruter:
  - Den svarer kun, når forespørgslen kommer **direkte fra hjemmenetværket** (samme regel som Kun lokalt: aldrig via betroet proxy eller tunnel, og aldrig med en videresendings-header) **og** har den rigtige `Authorization: Bearer`-nøgle. Alt andet får præcis samme 404-side som en adresse, der ikke findes, også en indlogget administrator uden nøgle.
  - Alle metoder er routet til stien, så POST, PUT, PATCH, DELETE og OPTIONS også svarer 404 (aldrig 405, der ville afsløre ruten). Med nøglen svarer kun GET og HEAD. Ruten har ingen session og er derfor undtaget fra CSRF-tjekket; den ændrer intet.
  - Forkerte forsøg tælles pr. IP i login-spærringen (nøgle `ha:<ip>`, 5 på 15 minutter, nulstilles ved succes). Forespørgsler udefra afvises, før spærringen røres. Bemærk: deler Home Assistant kilde-IP med andre klienter (fx hvis filteret kun ser Docker-gatewayen), kan 5 forkerte forsøg fra dem også spærre Home Assistant i 15 minutter. `sfctl unlock --ip IP` ophæver det.
  - Svaret indeholder kun konto-id, visningsnavn, tal og tilstande. Ingen adresser, emner, afsendere eller nøglen. Et lignende domæne nævnes kun ved det beskyttede domæne, det efterligner, aldrig ved sit eget navn.
  - Kun læsning: der findes ingen styrings-endpoints.
- **Login fra Kontrolrum (2.9).** `POST /login/kontrolrum` er et server-til-server-håndtryk med en signeret engangspåstand (HMAC-SHA256 med en delt nøgle, som FleetDeck). Detaljer i [CONFIGURATION.md](CONFIGURATION.md#login-fra-kontrolrum-29):
  - Ruten svarer kun, når **TCP-afsenderen er en af de præcise Kontrolrum-adresser** (ingen standard, ingen net, aldrig en betroet proxy) og forespørgslen ikke har en videresendings-header. Alt andet, og alle andre metoder end POST, får samme 404 som en ukendt adresse. Ruten har ingen session endnu og er derfor undtaget fra CSRF-tjekket.
  - Signaturen sammenlignes i konstant tid; `aud` skal være `spamfilter`, levetiden højst 120 s (60 s urforskel), og engangsværdien gemmes i databasen (genafspilning afvises, også efter en genstart). Højst 10 forsøg pr. afsender pr. 5 minutter. Kun brugere med fluebenet **Må logges ind fra Kontrolrum** (standard fra).
  - Nøglen vises én gang og gemmes AES-GCM-krypteret med en nøgle afledt af `state/dashboard_secret`; databasen alene afslører den ikke.
  - Sessionen får `kr = {afsender, nøglens fingeraftryk}` og er **bundet til Kontrolrums adresse**: ved hver forespørgsel skal afsenderen være den samme Kontrolrum-adresse, nøglen den samme, adressen stadig sat og fluebenet stadig på – ellers logges sessionen ud (`login_kontrolrum` · session afvist). Kun den session tæller som tilladt for en *Kun lokalt*-bruger udefra. Adgangskode, to-trins-kode og passkey følger uændret reglerne for Kun lokalt.
  - **Den rigtige person (2.12).** Kontrolrum 1.104.0 sender Kontrolrum-brugerens eget brugernavn i `sub` (op til 128 tegn; et navn, der ikke findes, giver `unknown_user`). Der logges kun ind, når brugeren findes og har fluebenet, præcis som før. Alle linjer i ændringsloggen fra sådan en session har `via: kontrolrum`, og siden viser **via Kontrolrum**, så man kan se, hvem der gjorde hvad.
- **Ændringer slår igennem med det samme.** Rettigheder læses ved hver forespørgsel. Skift af adgangskode, **Log ud overalt** og sletning tæller sessionsgenerationen op, så alle sessioner afsluttes med det samme, også dem med Husk mig.

## Login og sessioner

- **Adgangskoder** gemmes som PBKDF2-SHA256 med unik salt og 600.000 iterationer. Nye koder skal være mindst 12 tegn.
- **Spærring:** Fem fejlslagne forsøg låser login i 15 minutter, både pr. IP og pr. brugernavn fra den IP (fra 2.12: `user:<navn>@<ip>`, så gæt udefra aldrig spærrer ejeren hjemme eller fra en anden adresse). `sfctl unlock <bruger>` ophæver alle brugerens spærringer. Skift af egen kode (`/me/password`) har sin egen spærring og kræver den nuværende kode.
- **Sessioner** ligger i en signeret cookie. Den er `HttpOnly` og `SameSite=Strict` og får `Secure` automatisk over HTTPS:

  | | Maksimalt | Inaktivitet |
  | --- | --- | --- |
  | Normal session | 12 timer | 2 timer |
  | **Husk mig** | 30 dage | 7 dage |

- **To-trins-login (TOTP, RFC 6238):**
  - 6 cifre, 30 sekunder, ±1 trin, og hver kode kan kun bruges én gang
  - kan kræves pr. bruger (**Kræv to-trins-login**). Indtil appen er sat op, kan brugeren kun nå Min konto.
  - Efter adgangskoden har man 5 minutter og 5 forsøg til koden. Derudover gælder en spærring på 5 fejl pr. 15 minutter pr. bruger og pr. IP.
  - 8 genoprettelseskoder pr. bruger. Der gemmes kun saltede SHA-256-hashes.
  - TOTP-hemmeligheden ligger i databasen (mode 0600), fordi den skal kunne læses for at tjekke koder.
  - **Mistet telefon:** en administrator trykker **Nulstil** under Brugere (rydder både app og mail). Er det den sidste administrator, kører du som root:

    ```sh
    docker exec -it spamfilter sfctl disable-2fa <navn>
    ```

- **To-trins-login med kode på mail (2.3):**
  - Kan kun vælges, når en mailserver er sat op. Hver bruger kan have app, mail eller begge. Genoprettelseskoderne er fælles. **Kræv to-trins-login** opfyldes af begge metoder.
  - Koden er 6 cifre, gælder 10 minutter, tåler 5 forkerte forsøg og kan kun bruges én gang. Kun den nyeste kode gælder. Højst 3 koder pr. 15 minutter pr. bruger, mindst 60 sekunder imellem.
  - Databasen (`ui_mail_codes`) gemmer kun en saltet SHA-256 af koden. Selve koden findes kun i hukommelsen, indtil mailen er sendt, og skrives aldrig i databasen, udbakken eller loggen. Kontrollen tager lige lang tid, uanset om brugeren findes, og svaret er det samme, også ved SMTP-fejl.
  - Mailadressen bekræftes med en kode ved opsætning (`ui_twofa_mail`).
  - **App eller mail:** En kode på mail er kun så sikker som mailkontoen. Den, der kan læse brugerens mail, kan også logge ind med adgangskoden + koden. Appen (TOTP) er bundet til telefonen og anbefales til alle administratorer. Mail er et alternativ eller en reserve for andre brugere.
- **Bekræft, at det er dig (2.3):** Har en bruger allerede to-trins-login, kræver det frisk bevis at tilføje appen, tilføje en mailadresse eller skifte adresse: en kode fra appen, en kode til den nuværende bekræftede adresse eller en genoprettelseskode. Beviset gælder 10 minutter, er bundet til brugeren og kun til faste returadresser. Et to-trins-login inden for de sidste 10 minutter tæller som bevis. En stjålet Husk mig-session kan altså ikke skifte metoden ud.
- **Sikkerhedsmails (2.3):** Når to-trins-login eller adgangskoden ændres (af brugeren selv, af en administrator eller med `sfctl`), får brugeren en mail på sin bekræftede adresse (og en fjernet gammel adresse), når en mailserver er sat op. Højst 6 pr. bruger pr. time og højst 5 egne skift af adgangskode pr. time. Tællerne ligger i hukommelsen og nulstilles ved genstart. Selve ændringen står altid i revisionsloggen.
- **Passkeys (WebAuthn, 2.6):**
  - Egen, lille verifikation i `filter/webauthn.py` (ingen ny afhængighed, kun `cryptography`): attestation `none` (andre formater afvises), nøgler ES256 og RS256 (mindst 2048 bit), en streng CBOR-læser (ingen tags, floats eller ubestemte længder, ingen dubletter, ingen overskydende bytes). Der tjekkes type, challenge (konstant tid), nøjagtig origin og `crossOrigin` i clientDataJSON, rpIdHash, flagene UP og **UV** (brugerbekræftelse er påkrævet), at tælleren vokser, og selve signaturen.
  - RP ID er værtsnavnet i **Ekstern adresse** (kun `https://`) eller `localhost`. På den lokale http-adresse er knappen skjult, og serveren afviser alle passkey-kald.
  - Challenges er 32 tilfældige byte, gælder 5 minutter, er bundet til sessionen og gemmes kun som sha256 (`ui_webauthn_challenges`). De slettes ved første brug, så en genafspilning (også med en gammel cookie) afvises. Højst 20 login-challenges pr. IP pr. 5 minutter og 500 udestående i alt.
  - Login med passkey (opdagelig nøgle + UV) tæller som adgangskode **og** to-trins-login. Det følger samme regler: spærring pr. IP og pr. bruger (5 fejl pr. 15 min), **Kun lokalt** (samme fejlsvar), ny session med nyt CSRF-token og sessionsgeneration, **Husk mig**, revisionslog (`login` med `passkey`).
  - At tilføje eller fjerne en passkey kræver frisk bevis (10 minutter): en kode fra to-trins-login eller – uden to-trins-login – adgangskoden. Et login med kode eller passkey inden for 10 minutter tæller. Ændringer revisionslogges (`passkey_add`, `passkey_remove`, `passkey_reset`) og giver en sikkerhedsmail.
  - Databasen (`ui_passkeys`) gemmer kun den offentlige nøgle, credential-id, en tilfældig bruger-id (aldrig brugernavnet), tæller, navn og tidspunkter. Ingen hemmeligheder. Højst 10 pr. bruger. Slettes en bruger, slettes vedkommendes passkeys.
  - Mistet telefon: fjern passkeyen under Min konto eller kør `sfctl passkeys-reset <navn>`.
- **Besked ved login (2.6):**
  - Login-siden giver browseren en tilfældig enheds-cookie (`sf_device`, 256 bit, `HttpOnly`, `SameSite=Strict`, `Secure` over https, 400 dage). En enhed er sha256 af cookien og en grov browser/system-betegnelse ("Safari på iPhone"). Der laves ikke andet fingeraftryk. Cookien giver ingen adgang.
  - Login fra en ny enhed giver brugeren en sikkerhedsmail (bekræftet adresse) og en besked på alle brugerens enheder med beskeder; modtagerne under **Sikkerhed** får en kopi. Beskeden nævner browser/system, tid og IP (og land fra Cloudflare, kun via betroet proxy). Højst 5 pr. bruger pr. time. Brugerens første enhed efter opdateringen registreres uden besked.
  - De seneste 20 login (90 dage) vises under Min konto (`ui_login_history`), sammen med **Log ud overalt**.
  - 5 fejl på 15 minutter for ét brugernavn eller én IP (adgangskode, kode efter rigtig adgangskode eller passkey) giver én advarsel til administratorerne: mail under **Sikkerhed** og besked under **Problemer med filteret**. Højst én pr. time pr. brugernavn og pr. IP (`ui_login_alerts`) og 10 i timen i alt. Et brugernavn, der ikke findes, gentages aldrig i beskeden.
  - Adgangskoder, koder, tokens og cookies står aldrig i mails, beskeder, logs eller revisionsloggen.

- **Formularer:** Alle POST kræver et CSRF-token. Origin og Referer tjekkes også, så kun den lokale adresse og den gemte **Ekstern adresse** godtages.
- **Browser-sikkerhed:** CSP er strikt, uden inline JavaScript eller CSS, og med `frame-ancestors 'none'`. HSTS (`max-age=31536000`) sendes kun over HTTPS.

## Proxy og Cloudflare

- **Ingen proxy er betroet som standard.** `CF-Connecting-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` og `Cf-Access-Authenticated-User-Email` bruges kun, når den direkte afsender står i `TRUSTED_PROXIES`. Standarden er tom.
- **Hold listen smal.** Sæt den til præcis den adresse, **Indstillinger → Adgang udefra** viser, og aldrig til hele LAN'et.
- **Står en anden proxy end Cloudflare foran** (fx nginx), skal den fjerne en `CF-Connecting-IP`, som klienten selv har sendt.
- **Forældet indstilling:** `TRUSTED_PROXY=1` fra 2.0 betyder nu kun private net, og der logges en advarsel.
- **Revisionsloggen** gemmer proxy-adressen og Cloudflare Access-identiteten for betroede forespørgsler.
- **Web-appen** har en service worker, der kun cacher `/static/*` og offline-siden. Indloggede sider og JSON caches aldrig på telefonen.

## Mailhandlinger og sikkerhed for mails

- **Intet slettes.** Filteret flytter kun:
  - Kan serveren IMAP MOVE, bruges MOVE.
  - Kan den ikke (fx Gigahost), bruges COPY, `\Deleted` og UID EXPUNGE af præcis den ene UID.
  - En flytning, der bliver afbrudt, gøres færdig ved næste forbindelse ud fra en journal.
- **Præcis den rigtige mail.** Frigiv, Flyt til spam, Find en mail og Fortryd flytninger bruger altid det præcise Message-ID, som tjekkes mod headeren. Er der flere forskellige mails med samme ID, flyttes ingen af dem.
- **Engangs-id.** Hver mailhandling har et engangs-id, så den ikke kan udføres to gange.
- **Find en mail** søger skrivebeskyttet (EXAMINE). Den kigger aldrig i Sendt, Kladder, Arkiv eller brugerens egne mapper. Man kan søge live højst én gang hvert 10. sekund pr. postkasse.
- **Sikkerhedsbremsen** stopper flytninger ved unormal aktivitet, og efter en opdatering flyttes kun tydelig spam i 30 minutter.
- **Altid igennem** kræver, at mailen kan bekræftes som ægte. Automatiske tilladelser oprettes aldrig, når en Altid igennem-regel allerede dækker afsenderen.
- **Trusler (2.3)** flyttes uanset score og regler. Ved phishing-link, malware-link og farlig vedhæftning slipper kun en DKIM-bekræftet Altid igennem-regel igennem (hændelsen `threat_force_pass`). En virus slipper aldrig igennem.
- **Genscanning (2.3)** finder mailen igen ud fra det præcise Message-ID i Indbakken, springer den over, hvis den er væk, har flag, er rørt af brugeren eller ændret, og flytter kun ulæst mail (læst mail kun ved en trussel). Den bruger den samme flyttesti, ventetid og sikkerhedsbremse som en normal scanning. Der er ingen nye sletninger: Gigahost-flytningen er stadig COPY + UID EXPUNGE af præcis den ene UID.
- **Kendte kontakter (2.3)** læser Sendt og de øvrige mapper skrivebeskyttet (EXAMINE, kun headere med BODY.PEEK) i den eksisterende forbindelse. Der skrives aldrig noget i postkassen.
- **Straks-advarslen (2.3)** er filterets eneste nye skrivning i postkassen: en kort tekst- og HTML-mail, der lægges med APPEND i postkassens egen INBOX. Den bærer **intet farligt indhold**:
  - ingen URL'er, ingen vedhæftninger og ingen HTML fra den farlige mail – kun afsendernavn, adresse, emne, type og tidspunkt;
  - afsendernavn, emne og filnavn renses for kontrol- og formattegn (bidi, nulbredde, linjeskift) og forkortes; skemaer (`http:`, `javascript:`, `data:` …) og `www.` bliver til "[link fjernet]", og punktummer mellem bogstaver (også de asiatiske og fuldbredde-punktummer U+3002, U+FF0E og U+FF61) byttes ud med U+2024, så værtsnavne ikke bliver klikbare;
  - HTML-delen escapes, og overskriften (`Subject`, `To`) er fast eller postkassens egen adresse, så der ikke kan injiceres headere;
  - Message-ID'et indeholder en tilfældig uuid4 og registreres i `daily_receipts`, så scanneren, junk-pollen og læringen springer netop den mail over. En forfalsket "advarsel" uden registreringen scannes som al anden post;
  - højst én pr. postkasse hver 30. minut og kun i Filtrér. Administratorens alarm går gennem mailerens kø med de-duplikering og grænse pr. time.
- **Byg Bayes op på ny (2.3)** læser mails skrivebeskyttet (som den øvrige træning) og ændrer intet i postkasserne. Der slettes intet i Redis: den gamle pulje ligger urørt og kan gendannes. Skiftet af pulje, arkiveringen af den lærte tilstand og køen af job sker i én databasetransaktion, så en fejl efterlader den gamle tilstand uændret. Kun administratorer kan starte og gendanne (central politik), og begge dele revideres (`bayes_rebuild`, `bayes_restore`).
- **Regler (2.3):** Postkassernes egne adresser og domæner og webshop-/platformsdomænerne (altid `vexar.example`, `pinsikbing.example`, `gravisk.example`) kan ikke blokeres fra WebUI'en – heller ikke uden dialogens `scope`, via import, **Skift til Bloker** eller **Fortryd**. Kontrollen sker på serveren.

## Signerede opdateringer (2.12)

- Udgivelsens `spamfilter-X.Y.Z-source.tar.gz.sha256` signeres med `ssh-keygen -Y sign` (navnerum `spamfilter-release`). Den offentlige nøgle står i `deploy/release-signers`; den private nøgle ligger aldrig i repoet.
- `release.yml` signerer, hvis GitHub-hemmeligheden `SF_RELEASE_SIGNING_KEY` findes. Ellers signerer ejeren bagefter på sin egen maskine: `deploy/sign-release.sh vX.Y.Z` (henter pakken og kontrolsummen, tjekker dem, signerer og lægger `.sha256.sig` op på udgivelsen).
- Værtens hjælper (`deploy/update-runner.sh`) tjekker signaturen mod `deploy/release-signers` i den **kørende** `source/`. En forkert signatur afvises altid. En manglende signatur afvises fra `RELEASE_SIGNED_SINCE` (`deploy/release-signing.env`, 2.12.1); ældre udgivelser kan stadig installeres. Er der ingen nøgle i filen, tjekkes der ikke (som før 2.12).
- Skift nøgle: læg den nye offentlige nøgle i `deploy/release-signers` (gerne begge i en overgang), udgiv en version signeret med den gamle, og fjern så den gamle.

## Hemmeligheder

| Fil | Indhold | Rettigheder |
| --- | --- | --- |
| `state/imap-secrets/<konto>` | IMAP-adgangskode | 10099, 0600 |
| `state/dashboard_users` | Brugere med kode-hashes | 10099, 0600 |
| `state/dashboard_secret` | Nøgle til at signere sessioner | 10099, 0600 |
| `state/spamfilter.db` | Databasen, inkl. TOTP-hemmeligheder (`ui_twofa`) | 10099, 0600 |
| `state/controller.password`, `state/redis.password` | Koder til Rspamd og Redis | 0600 |
| `state/admin-audit.jsonl` | Revisionslog | 0600 |
| `state/smtp.password` (2.3) | Adgangskode til mailserveren, kun når login er **Brugernavn og adgangskode** | 10099, 0600 |
| `state/contacts.key` (2.3) | 32-byte nøgle til hashing af kontaktadresser og Message-ID'er | 10099, 0600 |
| `state/vapid_private.pem` (2.5.0) | VAPID-nøglen (P-256, PKCS#8) til beskeder på telefonen. Laves første gang en enhed slår beskeder til. | 10099, 0600 |
| `settings_kv` `ha_token` i databasen (2.3.6) | **Kun sha256** af Home Assistant-nøglen, oprettelsestid og -bruger. Selve nøglen gemmes aldrig. | (databasen) 10099, 0600 |
| `operations/` (uden for `state/`) | Driftsfiler og backups | kun root |

- Mapperne har mode 0700. Filterprocessen kører som UID 10099, og koden i containeren ejes af root og er skrivebeskyttet.
- Adgangskoder står aldrig i miljøvariabler eller logs.
- Brug forskellige koder til WebUI, SSH og mail. Brug helst app-adgangskoder hos udbyderne.
- Den første WebUI-kode i `operations/dashboard.initial-password` skal slettes, når du har skiftet den.
- Backups indeholder alle hemmelighederne ovenfor, også TOTP-hemmelighederne. Behandl dem derefter (se [BACKUP.md](BACKUP.md)). Fra 2.3.0-opfølgningen tager det natlige arkiv fra `backup-and-verify.sh` også `contacts.key` og `smtp.password` med, begge med mode 0600 i arkivet, og gendannelsestesten tjekker sha256, mode, ejer og at `contacts.key` er 32 byte. Et symlink i `state/` følges aldrig. Kræver, at `install-user-scripts.sh` er kørt igen efter opdateringen.
- **SMTP-adgangskoden** vises aldrig igen i WebUI'en, står aldrig i `accounts.yml`, `settings_kv`, revisionsloggen eller logs, og `mailer.status()` returnerer kun, om den er gemt. Skifter man server, skal den skrives igen. Med **Brug postkassens login** gemmes ingen ekstra kode: postkassens `password_file` læses først i det øjeblik, der sendes. Postkassens adgangskode sendes kun til postkassens egen udbyder (`smtp.gigahost.dk` til Gigahost, `mail.scannet.dk` til Scannet). En anden server skal bekræftes ved at skrive postkassens adgangskode én gang (sammenlignes med hmac, gemmes ikke). Den bekræftede `host:port:konto` gemmes som `account_bound` og kontrolleres igen ved hver afsendelse (fejl `account_host`).
- **Home Assistant-nøglen (2.3.6)** er `sfha_` + 32 tilfældige byte (`secrets.token_urlsafe`). Den vises **én gang** som direkte svar på **Opret nøgle**/**Lav ny nøgle** (ingen omdirigering, aldrig i sessionen, `Cache-Control: no-store`) eller af `sfctl ha-token create`. Kun sha256 gemmes, og sammenligningen sker med `hmac.compare_digest`. Den står aldrig i revisionsloggen, logs, `accounts.yml` eller backups i klartekst. Oprettelse, udskiftning og tilbagekaldelse revisionslogges (`ha_token_create`, `ha_token_revoke`). Kortet viser seneste brug og seneste afviste forsøg (tid og IP). Et lækket token giver kun adgang til tallene, og kun fra hjemmenetværket. Tilbagekald det under **Indstillinger → Home Assistant** eller med `sfctl ha-token revoke`.
- **API-nøgler til programmer (2.11.0)** afløser den ene Home Assistant-nøgle: flere navngivne nøgler (tabellen `ui_api_keys`), hver `sf_` + 32 tilfældige byte, kun sha256 + de sidste 4 tegn gemmes, opslag på hash og `hmac.compare_digest`. Nøglen vises **én gang** i et svar med `Cache-Control: no-store` (eller af `sfctl api-key create`). Rettigheder: Kun læse (`read`, kræves af `GET /api/v1/ha`), Læse og styre (`control`) og Administrator (`admin`); de to sidste er reserveret, da ingen endpoints kræver dem endnu. Nøglen sendes kun som `Authorization: Bearer` (aldrig i adressen). "Kun fra hjemmenetværket" er standard; findes der ingen nøgle, der må bruges udefra, svarer et kald udefra 404 uden opslag, præcis som før. Ukendt, udløbet eller forkert sted giver 404, for lidt rettighed 403, og over 60 læsekald / 10 styrekald i minuttet pr. nøgle giver 429 med `Retry-After`. Forkerte nøgler bremses pr. IP som login (`login_attempts`, nøglen `ha:<ip>`). Sidst brugt skrives højst hvert 60. sekund. Revisionsloggen (`api_key_create`, `api_key_delete`, `api_key_rejected`, `api_keys_migrated`) og loggen nævner nøglens navn og nummer, aldrig nøglen. Den gamle `sfha_`-nøgle flyttes ved første start uændret over som "Home Assistant" og virker videre; de gamle `ha_token*`-felter bliver stående én version (rollback), og sletter man den flyttede nøgle, slettes de også.
- **`contacts.key`** oprettes af filteret ved første start. Mistes eller udskiftes den, sletter filteret alle kontakttabeller og laver en ny, fuld gennemgang (hændelsen `contacts_key_regenerated`). Kontakter, der var fjernet i hånden, er så aktive igen.

## Beskeder på telefonen (web push, 2.5.0)

Beskederne følger de åbne standarder (RFC 8030 push, RFC 8291 kryptering, RFC 8292 VAPID) og bruger ingen tredjepartskonto: filteret sender direkte til den push-tjeneste, telefonens browser selv har valgt (Apple, Google, Mozilla eller Microsoft).

- **Intet indhold i beskederne.** En besked er JSON `{title, body, url, tag}` med **kun antal og postkassens visningsnavn** (fx "2 farlige mails i BYnet er lagt i Spamfilter-mappen"). Aldrig emne, afsender, adresse, link eller filnavn. Indholdet er krypteret til den enkelte telefon (aes128gcm med en ny nøgle pr. besked), så push-tjenesten kun ser krypteret data, og det fyldes op til en fast blokstørrelse.
- **Kun egne postkasser.** En hændelse går kun til brugere, der kan se postkassen (administratorer: alle); problemer kun til administratorer. Adgangen tjekkes igen i det øjeblik, beskeden sendes, så en Bruger, der har mistet adgangen til en postkasse, intet får om den. Farlige mails kan stadig kun frigives af en administrator.
- **SSRF-beskyttelse.** En enheds adresse (endpoint) skal være `https://` på port 443 hos en kendt push-tjeneste: `web.push.apple.com`, `fcm.googleapis.com`, `updates.push.services.mozilla.com` eller et underdomæne af `notify.windows.com`. Alt andet afvises, før der sendes noget. Forespørgsler følger aldrig omdirigeringer og har altid timeout (5 s forbindelse, 10 s svar).
- **VAPID-nøglen** (`state/vapid_private.pem`, 0600, uid 10099) vises, logges og sendes aldrig – kun den offentlige del går til browseren. Den er med i det natlige backuparkiv. `sfctl push-reset` laver en ny nøgle og sletter alle enheder (fx hvis nøglen er lækket). JWT'en gælder højst 12 timer og har `sub` = ejerens mailadresse (`mailto:`).
- **Brugerens egne enheder.** Alle ruter under `/me/push/` kræver login, går gennem den centrale adgangspolitik og CSRF, og hver forespørgsel er begrænset til den indloggede brugers egne enheder. Højst 10 enheder pr. bruger. En enhed, en anden bruger har tilmeldt, kan kun flyttes med de samme browsernøgler (bevis for, at det er samme enhed). Slettes en bruger, slettes vedkommendes enheder.
- **Begrænsninger.** Højst én besked pr. slags pr. 10 minutter og 20 om dagen pr. bruger, og højst 5 testbeskeder pr. 10 minutter. Svarer push-tjenesten 404/410, slettes enheden; 429/5xx giver nye forsøg med stigende pause. En enhed slettes kun efter tre afvisninger i træk, når tjenesten siger, at netop den enhed er ugyldig (fx Apples `BadDeviceToken`). Alle andre afvisninger (401/403/400/413, fx `BadJwtToken` ved forkert ur eller afsenderadresse) rammer filteret selv og aldrig enheden: enhederne beholdes, og `sfctl doctor` / `push-status` viser fejlen. Testbeskeder reserverer deres plads i grænsen, før de sendes, så samtidige tryk ikke kommer uden om den.
- **Service workeren** åbner kun stier på spamfilterets egen adresse, når man trykker på en besked. Den viser altid en besked (iOS kræver det) og gemmer stadig aldrig sider eller data.

## Nødadgang (sfctl)

Går noget galt, kan du altid rette det direkte i containeren. `sfctl` har ingen port og ingen side i WebUI'en. Kun den, der har root på værten, kan bruge den:

```sh
docker exec -it spamfilter sfctl <kommando>
```

- **Kører som containerens bruger (10099).** Den nægter at køre som root, medmindre du skriver `--allow-root`, så filerne i `/state` og `/config` bliver ved med at være ejet af 10099. I alt-i-én-containeren (2.4) skifter `sfctl` selv fra root til 10099.
- **Samme regler som WebUI'en.** Den bruger de samme funktioner, så brugerfilen stadig skrives atomisk med mode 0600, og tilstande valideres, gemmes og genindlæses på samme måde.
- **Alt logges.** Hver ændring skrives i revisionsloggen med aktøren `cli` og IP `local`. Adgangskoder skrives aldrig i logs.
- **Farlige handlinger kræver, at du skriver `ja`.** Det gælder `pause --all`, `logout-all` uden bruger, `set-role … user`, `disable-2fa`, `push-reset` og `passkeys-reset`. Med `--yes` springes spørgsmålet over.

| Kommando | Hvad den gør |
| --- | --- |
| `status` | Version, konti (adresse, tilstand, grænse, status, sidste fejl, nødbremse), hjerteslag, brugere, to-trins-login, betroede proxyer og ekstern adresse |
| `users` | Brugere med rolle, postkasser, rettigheder, to-trins-login, sidste login og spærring |
| `reset-password BRUGER [--generate]` | Ny adgangskode, mindst 12 tegn. Med `--generate` laves en stærk kode, som vises én gang. Brugeren logges ud overalt. |
| `disable-2fa BRUGER [--keep-required]` | Slår to-trins-login fra (både app og kode på mail) og fjerner kravet. Med `--keep-required` skal to-trins-login sættes op igen ved næste login. |
| `login-scope BRUGER overalt\|lokalt` (2.3) | Bestemmer, om brugeren må logge ind udefra. `sfctl users` viser det. |
| `smtp-status` (2.3) | Mailserver, seneste fejl, udbakke og notifikationer (aldrig adgangskoden) |
| `smtp-test ADRESSE` (2.3) | Sender en testmail nu med de gemte indstillinger |
| `smtp-disable` (2.3) | Nødstop: slår afsendelse af mail fra. Indstillingerne bevares. |
| `unlock [BRUGER] [--ip IP] [--all]` | Ophæver login-spærringer |
| `logout-all [BRUGER]` | Logger én bruger eller alle ud på alle enheder |
| `create-admin NAVN [--generate]` | Opretter en ny administrator. Navnet må ikke findes i forvejen. |
| `set-role BRUGER admin\|user` | Skifter rolle. Den sidste administrator kan ikke gøres til Bruger. |
| `pause [KONTO\|--all]` | Nødstop: skifter til Overvåg og husker den tidligere tilstand |
| `resume [KONTO\|--all] [--mode move\|flag]` | Genskaber præcis den tilstand, `pause` huskede. Er der intet husket, skal du angive `--mode`. |
| `resume-moves KONTO` | Genoptager flytning, når sikkerhedsbremsen har stoppet den |
| `external-url [URL\|--clear]` | Viser, sætter eller fjerner den eksterne adresse, fx hvis en forkert adresse spærrer for formularerne |
| `audit [--tail N]` | Viser de seneste N linjer i revisionsloggen (standard 30) |
| `push-status` (2.5.0) | Enheder med beskeder (bruger, enhed, push-tjeneste, seneste ok, fejl, valg), nøglens fingeraftryk og køen. Aldrig adresser eller nøgler. |
| `push-test BRUGER` (2.5.0) | Sender en testbesked nu til alle brugerens enheder |
| `push-reset` (2.5.0) | Nødstop: sletter alle enheder og køen og laver en ny VAPID-nøgle. Alle skal slå beskeder til igen. Kræver `ja`. |
| `passkeys BRUGER` (2.6) | Viser brugerens passkeys: navn, adresse (RP ID), oprettet og senest brugt. Aldrig nøgler eller id'er. |
| `passkeys-reset BRUGER` (2.6) | Nødstop: fjerner alle brugerens passkeys (mistet telefon/nøgle). Kræver `ja`. |
| `reload` | Beder filteret om at genstarte pænt |
| `ha-token create\|revoke\|status` (2.3.6) | Opretter (viser nøglen én gang, spørger før en eksisterende erstattes), tilbagekalder eller viser status for Home Assistant-nøglen. Aldrig selve nøglen i status. Fra 2.11.0 et alias for API-nøglen "Home Assistant". |
| `api-key list\|create\|delete` (2.11.0) | Viser alle API-nøgler (navn, `sf_…`+4 tegn, rettighed, sidst brugt), laver en ny (`--name`, `--scope read\|control\|admin`, `--anywhere`, `--expires DAGE`; vises én gang) eller sletter én (`delete ID`, spørger først). Aldrig selve nøglen eller dens hash. |
| `doctor` | Tjekker ejer og rettigheder i `/state` og `/config`, konfigurationen, databasen, rspamd, brugerfilen og at der findes en administrator. Fra 2.3 også mailserveren, mode på `smtp.password`, brugere med kode på mail uden mailserver og administratorer uden to-trins-login. Fra 2.5.0 også beskeder: `cryptography` findes, VAPID-nøglens mode, afsenderadresse, enheder med fejl og enheder hos slettede brugere. Fra 2.6 også passkeys hos slettede brugere og passkeys, der er lavet til en anden adresse end den nuværende eksterne adresse. Viser den præcise kommando, der retter fejlen. |

Exitkoder: 0 = ok, 1 = fejl eller afvist, 2 = forkert brug.

## Databehandling

- **Det gemmes:** SQLite gemmer metadata om mails: Message-ID, afsender, emne, scorer, grunde og historik. Det gemmes for at kunne vise, forklare og rette.
- **Det gemmes ikke:** Selve mailteksten gemmes ikke og skrives ikke i logs.
- **Rspamd** får mailindholdet inde i containeren via `127.0.0.1` (før 2.4: på `spamnet`).
- **Fuzzy-opslag** sender kun skrivebeskyttede fingeraftryk (hashes) til Rspamds fællesdatabase, aldrig selve mailen.
- **DNS-opslag** sender kun adresser og domæner gennem Unbound og LAN-resolveren `192.168.1.1`. Det gælder sortlister, SPF, DKIM og DMARC. Fra 2.3.6 slår den ugentlige kontrol af lignende domæner også NS, MX og A op for varianterne af de beskyttede domæner (højst 5 opslag/s og 1500 pr. kørsel). Navnene kommer kun fra administratorens liste, aldrig fra mailindhold.
- **Daglig kvittering** lægges med IMAP APPEND direkte i postkassens egen indbakke og sendes ikke via SMTP.
- **Daglig opsummering** er en Unraid-notifikation til administratoren. Fra 2.3 kan den også sendes som mail.
- **Kendte kontakter (2.3):** Fra Sendt læses kun modtageradresser, Message-ID og referencer, aldrig indholdet. Adresser, Message-ID'er og domæner gemmes som HMAC-SHA256 med `state/contacts.key` og med domæneadskillelse, så databasen ikke kan bruges som adressebog eller sammenlignes med en anden installation. Til visning gemmes kun en maske ("a…@kunde.dk"). Listen viser kun en fuld adresse, når personen også selv har skrevet til postkassen. Hændelser, revisionslog, symboler og logs indeholder kun masker.
- **Mail fra filteret (2.3):** Afsendes gennem den konfigurerede SMTP-server med TLS (STARTTLS eller SSL, `CERT_REQUIRED` og kontrol af værtsnavn), aldrig login uden TLS, og aldrig som åbent relæ. Adresser og emner valideres (CR/LF og styretegn afvises). Mails er mærket `Auto-Submitted: auto-generated` og `X-TH-Spamfilter: notify`, og filteret scanner, flytter og lærer aldrig af sine egne notifikationer. Højst 60 mails i timen (koder og alarmer må bruge hele budgettet, andre slags stopper ved 40) og 20 pr. modtager. Udbakken (`mail_outbox`) gemmer indholdet, til mailen er sendt eller opgivet, og metadata i 30 dage. Revisionsloggen (`mail_sent`, `mail_failed`, `smtp_test`) indeholder kun maskerede adresser og aldrig indhold eller koder.


## Mailidentitet og opgradering fra 2.14 (2.15)

Message-ID kommer fra afsenderen og er ikke en tillidsgrænse. Tabellen `mail_identity` knytter postkasse, intern nøgle, oprindeligt ID og SHA-256 af mailens stabile headere og MIME-indhold sammen. Leveringsheadere (fx Received, DKIM-signatur og Authentication-Results) og CRLF/LF normaliseres; afsender, emne, applikationsmarkører og body er bundet. Ved fejlformede headere hashes hele den normaliserede rå mail konservativt, så bodytekst ikke forveksles med leveringsheadere. Mailen ændres ikke. Manglende, usikre, reserverede eller genbrugte ID'er får en intern `sf-local:`-nøgle. Opslag og mailhandlinger kontrollerer indholdet før brug af denne binding.

Gamle rækker uden fingerprint bevares. En ny indbakkelevering må ikke arve deres frigivelse ud fra header-ID alene; den får en særskilt identitet og normal kontrol. En gammel frigivet mail kan derfor skulle frigives igen efter genlevering. Egne kvitteringer og SMTP-notifikationer undtages kun med en binding til det faktisk genererede indhold.

Skemaudvidelserne er additive og idempotente. Ældre kode ignorerer dem, men en rollback genindfører også den gamle ID-baserede tillid og manglende scanning af mails uden ID. En teknisk mulig rollback er derfor ikke en bevaret sikkerhedsrettelse. Tag backup før opdatering; gendan matchende kildekode, state og Redis ved en fuld rollback, jf. BACKUP.md.

Scanning er IMAP-efterbehandling, og læste/store mails samt antivirusnedetid begrænser dækningen. Eksplicit administratorfrigivelse og de dokumenterede, bekræftede afsenderundtagelser kan ændre beslutningen. Det er ikke en garanti mod alle skadelige mails.


**Gamle opslag og trusler:** Kendte 2.14-rækker uden indholdsbinding bruges ikke til headerbaseret måludvælgelse i kontoforbindelser. Det stopper også gamle ventende lærejob i at træne på en anden mail med genbrugt ID. Brug **Find en mail** for at binde en konkret kopi før en manuel handling. En gammel kendt trussel følger som konservativ adgangsbegrænsning med til en ny, endnu ikke scannet alias-identitet: kun administrator med bekræftelse kan frigive den, og den læres ikke som legitim. Når den oprindelige mails indhold er kendt via fingerprint, kan en anden mails egen scanning give en selvstændig klassifikation. Uden den oprindelige binding bevares det gamle administratorkrav konservativt; en ny score alene kan ikke modbevise den gamle virusmarkering. En bekræftet frigivelse bevarer trusselsmærket, så senere flytning i mailprogrammet ikke lærer mailen som legitim. Gamle afbrudte flytninger uden indholdsbinding/journalbevis skal kontrolleres manuelt; der slettes ingen kildekopi alene ud fra samme header-ID. Ventende flytninger med deres oprindelige UID/UIDVALIDITY-bevis bevarer den eksisterende køpolitik.

## Lokale evalueringsdata (under udvikling efter 2.15.0-beta)

Holdout-registret indeholder indholdsfingerprints og neutrale prøve-ID'er.
Beslutningsspor indeholder komplette politiksymboler, relevante brugerafgørelser,
valgte afsenderregler og autentificeringsdomæner, men ingen body eller emne.
Sporene er kontobundne driftsdata og slettes med de forældreløse mailposter.
Hashes er ikke anonymisering; beskyt databasen og lokale eksport-/mailfiler.

Nye AI-metadata identificerer systemprompt/faktaudtræk og den anvendte request-
konfiguration uden mailtekst eller lokal URL. De beviser hverken identiske
modelvægte, korrekt AI-confidence eller modstand mod alle prompt-injektioner.
Gamle AI-poster får ingen efterkonstrueret version. Reservationer hindrer
matchende fremtidig Bayes/fuzzy-læring gennem den nye appkode, men tilbagefører
ikke historisk læring og begrænser ikke ejerens øvrige mailhandlinger.
Ældre kode håndhæver ikke reservationerne. Se CONFIGURATION.md for omfanget.
