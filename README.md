# Spamfilter til Unraid (version 2.19.2)

Et selvhostet spamfilter til familiens og firmaets postkasser. Fra 2.4 kører det i **én Docker-container**, `spamfilter`, på en Unraid-server. Postkasserne bliver hos deres udbydere (fx Gigahost eller Scannet, som filteret kender særligt godt). Filteret logger ind via krypteret IMAP, vurderer nye ulæste mails inden for størrelsesgrænsen i indbakken og flytter spam over i mappen **Spamfilter** i samme postkasse.

Projektet bygger på [marcelverdult/imap-spamfilter](https://github.com/marcelverdult/imap-spamfilter). Den oprindelige README ligger i [UPSTREAM-README.md](UPSTREAM-README.md).

## Det vigtigste

- **Intet bliver slettet.** Filteret flytter kun mails mellem Indbakken og mappen `Spamfilter`. Du kan altid flytte en mail tilbage. Oprydning i `Spamfilter` gør du selv i dit mailprogram.
- **Udbydernes egne spamfiltre kører videre.** Filteret lægger aldrig selv noget i udbydernes spam-mapper (`Junk` o.l.) og flytter kun noget ud af dem, når du trykker **Frigiv** eller **Flyt til indbakken**. Ellers læser det dem bare, så det kan finde mails og se, hvad du selv flytter.
- **Det lærer af dig.** Trækker du en mail ind i `Spamfilter` i mailprogrammet (også på mobilen), lærer filteret, at den er spam. Trækker du den ud igen, lærer det, at den ikke er spam. Samtidig bliver afsenderen tilladt for den postkasse (det kan slås fra pr. konto).
- **Beskyttelse af ordrer og kundepost.** Afsendere med "Altid igennem", fx webshop-platformen, fritages efter ægtheds- og trusselspolitikken; en registreret virus har altid forrang. Mails til beskyttede kontaktadresser skal have en langt højere score, før de flyttes.
- **Ingen åbne porte.** MX og SMTP er uændret. WebUI'en svarer kun på det lokale netværk, medmindre du bevidst sætter en Cloudflare Tunnel op ([CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md)).
- **Folk, du har skrevet til, kommer igennem.** Fra 2.3 lærer filteret af dine sendte mails, hvem du skriver med. Svar på dine egne mails og post fra kendte kontakter og faste afsendere får et forspring. Filteret læser kun modtageradresser og Message-ID i Sendt, aldrig indholdet.
- **Registrerede trusler får forrang.** Registrerede virus, phishing og farlige vedhæftninger behandles efter trusselspolitikken. Virus kan ikke tillades med en afsenderregel. Visse andre trusler har snævre, bekræftede administratorundtagelser. Kun en administrator kan frigive farlige mails.
- **Genscanning.** Mails, filteret var i tvivl om, bliver scannet igen efter 45 minutter, 4 timer og 24 timer. Er de i mellemtiden kommet på en sortliste, flyttes de, hvis de stadig er ulæste.
- **Mail fra filteret.** Med en mailserver sat op under Indstillinger kan filteret sende alarmer, opsummeringer, ugerapport og koder til to-trins-login som almindelig mail.
- **Indbyggede sikringer.** Flytter filteret pludselig usædvanligt meget, stopper det sig selv (sikkerhedsbremsen). Efter en opdatering flytter det kun tydelig spam i 30 minutter.

## Dækning og begrænsninger

Filteret arbejder **efter IMAP-levering**. En mail kan derfor nå indbakken og udløse en telefonnotifikation før en flytning. Mails, der allerede er læst ved første kontrol, og mails over størrelsesgrænsen springes over. ClamAV-nedetid stopper ikke den øvrige scanning: virustjekket kan være utilgængeligt. Ingen spam- eller virusscanner finder alle trusler.

Fra 2.15 scannes også mails uden Message-ID. Frigivelser knyttes til et lokalt indholdsfingerprint, så en ny mail ikke overtager en anden mails afgørelse ved at genbruge dens ID. Almindelige tilladelser tilføjet i ventetiden kontrolleres igen før flytning, med afsender- og trusselskontrol bevaret.

**Drift** viser scanningstællere pr. postkasse over 14 dage. Lokal evaluering af menneskeligt mærkede prøveudvalg og en særskilt gendannet opstart af app + Redis/Bayes findes i [CONFIGURATION.md](CONFIGURATION.md) og [BACKUP.md](BACKUP.md). Tallene dokumenterer ikke familiens samlede træfsikkerhed.

## Mailudbydere

Filteret logger ind i postkasserne med IMAP og virker med de fleste udbydere. For nogle udbydere kender det særlige forhold, som bruges automatisk ud fra IMAP-serverens navn:

| Udbyder | Særligt |
| --- | --- |
| Gigahost | Serveren kan ikke IMAP MOVE, så filteret flytter med COPY + UID EXPUNGE af præcis den ene mail. Udbyderens spam-markering alene tæller ikke som bevis. |
| Scannet | Kan have SpamExperts foran domænet; Mailsikkerhed og "Find en mail" peger så på SpamExperts' karantæne. |

Postkasser, egne domæner og andre lokale værdier sættes op ved installationen og gemmes kun på serveren (`accounts.yml` og `site.yml`, se [CONFIGURATION.md](CONFIGURATION.md)). Flytningen fra fire containere til én (2.4.0), kontrollen og vejen tilbage står i [.build/RELEASE-2.4.0.md](.build/RELEASE-2.4.0.md). Tilbage fra 2.2 til 2.1 står i [deploy/README.md](deploy/README.md#going-back-from-22-to-21-rspamd-rules).

## WebUI

- **Hjemme:** `http://192.168.1.10:18080/`
- **Udefra (valgfrit):** din egen HTTPS-adresse bag Cloudflare Tunnel og Cloudflare Access. Se [CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md).
- **Som app:** WebUI'en kan lægges på hjemmeskærmen på iPhone og Android. Vejledningen står under **Min konto**.

Der er to roller:

- **Administrator** ser alt. Menuen har:
  - **Oversigt**
  - **Post:** Fanget spam, Beskeder, Find en mail og Fortryd flytninger
  - **Filtrering:** Regler (med fanerne Afsenderregler, Kendte kontakter og Vedhæftninger), Træning og AI-vurdering
  - **Sikkerhed:** Mailsikkerhed og DMARC
  - **Konti og adgang:** Konti og Brugere
  - **System:** Drift, Opdateringer og Indstillinger
  - Hjælp er (?) nederst i sidemenuen
- **Bruger** (fx et familiemedlem) får en enkel side med kun sine egne postkasser. Menuen har **Min spam**, **Kendte kontakter**, **Hjælp** og **Min konto**. **Find en mail**, **Beskeder** og **Regler** kommer kun med, hvis administratoren giver adgang. En Bruger ser ingen scorer, ingen tekniske ord og ingen andres post.

Med **Se som bruger** ser administratoren præcis det samme som en bestemt Bruger. Ingen knapper virker, så intet kan ændres i visningen.

Fra 2.3 kan en bruger begrænses til **Kun lokalt (hjemmenetværket)**, så kontoen slet ikke kan logge ind udefra. To-trins-login kan nu også bruge en **kode på mail** i stedet for en app.

## Dokumentation

| Fil | Til hvem | Indhold |
| --- | --- | --- |
| [BRUGERVEJLEDNING.md](BRUGERVEJLEDNING.md) | Ejeren | Alle funktioner forklaret, trin for trin |
| [FAMILIEGUIDE.md](FAMILIEGUIDE.md) | Familien | Én side: Spamfilter-mappen, træk ind/ud, login. Som PDF under Hjælp → “Hent familieguiden (PDF)” |
| [HOME-ASSISTANT.md](HOME-ASSISTANT.md) | Ejeren | Dagens spam, status og push-besked i Home Assistant (nøgle, pakke, dashboard-kort) |
| [CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md) | Ejeren | Adgang udefra og Android-app, klik for klik |
| [CONFIGURATION.md](CONFIGURATION.md) | Ejeren/drift | Indstillinger i WebUI'en og nøgler i `accounts.yml` |
| [INSTALLATION.md](INSTALLATION.md) | Drift | Containeren, versioner, mapper, flytning til én container, opdatering |
| [SECURITY.md](SECURITY.md) | Drift | Adgang, login, proxy, hemmeligheder, data |
| [BACKUP.md](BACKUP.md) | Drift | Backup og gendannelse |
| [deploy/README.md](deploy/README.md) | Drift (engelsk) | Scripts til udrulning og rollback |
| [.build/RELEASE-2.4.0.md](.build/RELEASE-2.4.0.md) | Drift (engelsk) | Flytning fra fire containere til én (2.4.0), kontrol og rollback |

## Containeren

Fra 2.4 er der kun én container, **`spamfilter`**, med ét ikon og én mappe i Unraids Docker-fane. Indeni kører fire dele (fra 2.7 også ClamAV), hver med sin egen bruger:

| Del | Funktion | Port |
| --- | --- | --- |
| Filter + WebUI | IMAP-motor, SQLite og WebUI | `192.168.1.10:18080` (den eneste åbne port) |
| rspamd | Scoring og Bayes-læring | kun inde i containeren |
| Redis | Bayes-lager (med adgangskode) | kun inde i containeren |
| Unbound | DNS-opslag til sortlister | kun inde i containeren |
| ClamAV (2.7) | Virusscanning af vedhæftninger (`clamd` + `freshclam`) | ingen port, kun en lokal socket |

- Går en del ned, genstarter den af sig selv, uden at resten stopper.
- ClamAV (2.7) bruger ca. 1-1,5 GB RAM; containeren har derfor 4 GB. Svarer ClamAV ikke, scannes mails videre uden virustjek, og `sfctl doctor` advarer. `SF_CLAMAV=0` slår det fra (se [CONFIGURATION.md](CONFIGURATION.md#virusscanning-27)).
- Sundhedstjekket viser, hvilken del der har problemer: `docker exec spamfilter sf-health check`.
- Nødadgangen er den samme som før: `docker exec -it spamfilter sfctl ...`.
- Billedet `imap-spamfilter-unraid:2.4.0` bygges lokalt med `deploy/aio/build.sh` på det samme låste rspamd-billede som før, så rspamd er uændret.
- Indtil oprydningen ligger de fire gamle containere (`spamfilter-legacy`, `spamfilter-rspamd`, `spamfilter-redis`, `spamfilter-unbound`) stoppet til tilbagerulning.

Detaljer står i [INSTALLATION.md](INSTALLATION.md).

## Licens

Spamfilteret er gratis at bruge, ændre og dele til **ikke-kommercielle** formål: privat, i hjemmet, som hobby,
i undervisning og i foreninger. Kommerciel brug kræver skriftlig tilladelse fra ejeren. Licensen er
[PolyForm Noncommercial License 1.0.0](LICENSE) (SPDX `PolyForm-Noncommercial-1.0.0`).

Projektet bygger på [marcelverdult/imap-spamfilter](https://github.com/marcelverdult/imap-spamfilter), og de dele,
der stammer derfra, er fortsat under MIT-licensen. Se [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).


### Opfølgning på manuelle spamrettelser (2.19)

Administratorens **Tjek disse** viser automatisk seneste 30 dages eksplicitte
spamafgørelser, højst 500 pr. postkasse. Ugerapporten bruger samme analyse for
sin uge; den korte rapport viser kun sin egen postkasse. Det oprindelige
scanningsspor viser blandt andet tilladelsesregler og scorer under grænsen.
En senere ham-afgørelse fjerner mailen fra opgørelsen. Gentagne klik tælles
ikke som forskellige mails. Gamle/slettede spor kan ikke genskabes.

Analysen bruger gemte metadata, ingen mailtekst eller ekstern AI. Senere AI-
og kampagneafgørelser kan have fanget mailen; første scanning er ikke den
endelige leveringsafgørelse. Manglende afsenderbevis og mindst tre adresser på
samme domæne er observationer, ikke bevis på en fælles spamkampagne. Opgørelsen
er et udvalgt korrektionsgrundlag, ingen samlet træfsikkerhedsprocent.
Den ændrer ikke regler, grænser eller andre familiemedlemmers præferencer.
