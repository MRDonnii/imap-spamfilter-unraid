# Ændringslog

## 2.20.0 — 2026-11-25 (beta)

- **Den lokale AI vurderer også fangede mails lige over grænsen:** Før så AI'en kun mails lige under grænsen i
  indbakken (33 af 668 fangede mails på 30 dage havde en vurdering). Nu får fangede mails op til 3 over grænsen
  også en vurdering, når afsenderen ikke er kendt, beskyttet eller blokeret. Vurderingen flytter eller frigiver
  aldrig noget og giver ingen point: Er AI'en sikker på spam eller phishing, vises mailen ikke under Tjek disse;
  mener den, at mailen er ægte, bliver den på listen med grunden "Den lokale AI mener, at den er ægte". Indbakkens
  mails går altid først i køen, og vurderingerne tæller ikke med i AI-sidens tal for Prøv/Til.
- Brugervejledningen forklarer, hvad Tjek disse skjuler, og hvordan man ser det alligevel.

## 2.19.4 — 2026-11-25 (beta)

- **Tjek disse fanger også spam fra ukendte afsendere med gyldig DMARC:** En spammers eget domæne består ofte
  DMARC. En mail fra en afsender, der aldrig har fået en mail igennem før, vises nu heller ikke, når den har et link
  på en spamliste, rspamd's phishing-tegn (linktekst og adresse passer ikke sammen), eller når Bayes-filteret, der
  har lært af jeres egne valg, er næsten sikker (mindst 4 af 5,1). Målt på 90 dage: 16 spammails færre, ingen gode.

## 2.19.3 — 2026-11-25 (beta)

- **Færre spammails under Tjek disse:** Mærket "første mail fra en ukendt afsender" forsvandt, når en mail blev
  scannet igen, så to ud af tre fangede mails manglede det, og tydelig spam blev stadig vist. Nu spørger listen
  selv databasen: er der aldrig kommet en mail fra afsenderen igennem til indbakken før, og består den ikke
  DMARC eller har et faretegn, vises den ikke. Målt på 90 dages rigtig post: 142 spammails færre på listen, og
  ingen af de 18 mails, som folk frigav, ville være skjult.
- **Beskyttede adresser:** En mail, der kun står på listen, fordi den gik til en beskyttet adresse, vises ikke, når
  scoren er mindst 10 over grænsen (fx score 33 med Spamhaus, kendt spamindhold og SPF-fejl). Telefonbeskeden følger
  de samme regler, og **Vis dem alligevel** viser alt.

## 2.19.2 — 2026-11-25 (beta)

- **Tjek disse viser kun det, der kan være en god mail:** En grænsemail vises ikke længere, når den næsten sikkert
  er spam: AI'en har kaldt den spam eller phishing med høj sikkerhed, eller det er første mail fra en helt ukendt
  afsender, som enten ikke består DMARC eller har et faretegn (lokkeemne, snydetegn, nyt domæne, misbrugt
  topdomæne, falsk brand, kendt spamindhold). Målt på 3 ugers rigtig post: listen ville være faldet fra 69 til 20
  mails, og alle 10 mails, som folk faktisk frigav, ville stadig være vist (de kom alle fra afsendere, man havde fået
  mail fra før). En ny afsender med DMARC og uden faretegn (fx en ny webshop) vises som før.
- Kortet siger, hvor mange der er skjult og hvorfor, med **Vis dem alligevel**. Telefonbeskeden springer dem også over.

## 2.19.1 — 2026-11-25 (beta)

- **Tjek disse viser ikke længere afsendere, du allerede har kaldt spam:** En mail, der kun står under Tjek disse,
  fordi scoren ligger tæt på grænsen, vises ikke, når en person tidligere har kaldt samme afsender spam ("Det er
  spam", "Lær som spam" eller en flytning til Junk) og ingen har frigivet mail derfra. Afsenderen er domænet
  (fx en kampagne med skiftende adresser på samme domæne); for gratis mailadresser kun den præcise adresse. Mails
  med en rigtig grund til et ekstra kig (kendt kontakt, svar, beskyttet adresse, eget domæne) vises som før.
  Kortet siger, hvor mange der er skjult, med **Vis dem alligevel**. Mailene ligger stadig i Spamfilter-mappen.
- **Det er spam rydder op med det samme:** Trykker man Det er spam under Tjek disse, forsvinder de andre mails fra
  samme afsender også fra listen.
- **Telefonbeskeden "Nye mails under Tjek disse"** springer de samme mails over.

## 2.19.0 — 2026-11-23 (beta)

- Automatisk metadataopfølgning på seneste eksplicitte spamrettelser i
  eksisterende Tjek disse og ugerapporten. Første scanningsspor forklarer
  daværende tilladelse, tidligere frigivelse eller lav score; allerede
  opdaget spam og manglende spor vises særskilt. Seneste brugerafgørelse
  gælder, én mail tælles én gang, højst 500 pr. konto og periode.
  Gemte afsenderbeviser og flere adresser på samme domæne giver forsigtige
  forklaringer. Ingen automatisk domæneblokering eller ændrede grænser.
- Krypteret backup angiver nu sit læringsgrundlag i den beskyttede manifest:
  standardprofilens lokale fuzzy-mønstre ligger i samme Redis-RDB som Bayes.
  Ukendt profil vises som ukendt; en kendt afvigende fuzzy-backend giver
  ufuldstændig backupstatus og bevarer seneste vellykkede backup/retention.
- CI indlærer et neutralt lokalt fuzzy-mønster i en frisk, kontoløs AIO med
  netværket afbrudt. Krypteret backup gendannes i en anden isoleret AIO;
  mønstret skal genkendes uden genindlæring. Egne maildata anvendes ikke.

## 2.18.0 — 2026-11-23 (beta)

- Ejerbestilt personlig spamautomatik: Tre nye rettelser af forskellige mails
  fra samme bekræftede adresse inden for 30 dage kan blokere adressen for den
  enkelte postkasse. Mailprogram og WebUI tælles samlet uden dubletklik.
  Gamle forslag udløser ingen blokering ved opgradering. Højst fem nye regler
  pr. konto pr. rullende døgn. Egne domæner og eksisterende tilladelser bevares.
- **Husk gentagen spam automatisk** er som standard slået til og kan slås fra
  pr. konto. Fra giver fortsat forslag; eksisterende regler bevares. Ingen
  ændring af scoregrænser, ingen automatisk domæne-/globalregel eller sletning.
- Frigivelse/legitim-afgørelse nulstiller tællegrundlaget og fortryder en
  uændret automatisk blokering, også uden automatisk tilladelse. Håndlavede
  regler bevares; en fortrudt automatisk blokering genskabes ikke af sig selv.
- Fortrydelse genvurderer også regelafhængige ventende flytninger. Kun
  afgørelser, der alene skyldtes den fjernede automatiske regel, aflyses;
  selvstændig spam/trussel/brugerafgørelse/aktuel regel bevares.

## 2.17.0 — 2026-11-23 (beta)

- Forsinkede AI- og kampagneafgørelser bruger særskilte profiler i den fælles
  rene beslutningsmotor med lokale, kontoafgrænsede input/resultat-spor.
  `sfctl policy-preview --stage` gengiver de enkelte faser skrivebeskyttet.
  Eksisterende prioritering, kampagnekonsensus og scoregulve bevares.
- Kampagner genkontrollerer brugerafgørelser, tilladelser, scoregulv og
  stoptilstand efter langsomme IMAP-kald. En frigivelse eller aflysning under
  kontrollen må ikke overskrives med en flytning eller spammarkering.

- Et personligt valg om at flytte et legitimt, etableret nyhedsbrev til spam
  starter ikke længere kampagneafgørelser på andre postkasser. Den eksisterende
  beskyttelse mod Bayes/fuzzy-læring af sådanne valg bevares.
- Syntetiske AI-prøver omfatter falske systemroller, instruktioner og delimiters
  i maildata samt ugyldige/dybt indlejrede svar. Parseren håndterer også
  decoderens rekursionsfejl som ugyldigt svar med normal backoff.

## 2.16.0 — 2026-11-23 (beta)

- Drift samler antivirusstatus/signaturalder og antal/alder for ventende
  flytninger, træning, fortrydelse og AI. Gamle/manglende helbredsmålinger
  vises som ukendte. Ventetid er ikke i sig selv en fejl; ingen nye alarmer
  eller mailhandlinger. Visningen er kun for administratorer.

- Forsinkede AI-svar respekterer en hævet postkassegrænse. En ren AI-
  scoreflytning aflyses også, hvis grænsen hæves i ventetiden. Oprindelige
  højere grænser bevares; manuelle spamafgørelser og trusler ændres ikke.

- Ny separat AIO-gendannelsesprøve fra krypteret backup. Kontrollerer app,
  Rspamd, Redis og Unbound på en kontoløs kopi uden netværk/porte og med
  containerbudgetter. Verificerer mounts/isolation før start og faktisk RDB-
  indlæsning med en neutral markør. ClamAV og udbyderlogin er undtaget.

- Familiens »Hvorfor?« bruger den registrerede blokering fra afgørelsen og
  omskriver ikke gamle mails med nye regler. Manglende forklaring udlægges ikke
  som en udokumenteret scoreoverskridelse. Reserveret prøvemateriale får en
  forståelig hændelsestekst uden at ændre knapper eller adgangsregler.
- Gendannelsesprøvens app-/Redis-underprocesser får grænser for virtuel
  hukommelse, CPU, åbne filer og core dumps. `backup-drill --memory-mib` vælger
  128–4096 MiB pr. underproces; standard er 1024. Dette er stadig app/Redis-
  prøven, ikke en separat gendannet hel-stak-container.
- `sfctl policy-trial` kan registrere en kandidatgrænse parallelt på én postkasse
  uden mailhandlinger eller aktivering. Bevarer beskyttede modtageres grænse,
  rapporterer logiske forskelle og adskiller resultater ved skift af kandidat.
- AI-poster får versionsgrundlag for prompt/fakta/politik og faktisk request-
  konfiguration uden mailindhold eller lokal URL. Gamle poster forbliver ukendte;
  modeltag er ikke et verificeret fingerprint af modelvægtene.
- Ugyldigt AI-JSON tælles som fejl med backoff. Ekstremt store confidence-tal
  afvises uden at afbryde fortolkningen. AI-point og aktive regler er uændrede.
- Lokale, kontobundne beslutningsspor gemmer den rene politiks input/resultat
  uden mailtekst. `sfctl policy-preview` kan reproducere dem og afprøve en
  anden scoregrænse uden mailhandlinger eller konfigurationsændringer.
  Prøven bruger de gemte regler og signaler og er ikke en ny scanning.
- `sfctl quality-reserve` reserverer en lokal mailfil mod fremtidig Bayes- og
  fuzzy-læring gennem appen, også på tværs af konti og import uden Message-ID.
  Kun fingerprint/ID/tid gemmes. Kendt tidligere læring afvises; historisk
  træningsfrihed kan ikke bevises, og ældre kode respekterer ikke reservationen.
- `sfctl quality-compare` sammenligner baseline og kandidat på samme lokale,
  menneskeligt mærkede udvalg. Viser nye/rettede fejl og valgt fejlomkostning
  pr. postkasse; afviser ændrede labels og udvalg. Rapporten gælder kun prøven
  og aktiverer ingen ændringer.
- Den fælles første-scannings-/flyttepolitik er udskilt i `decisionpolicy.py`
  med politikversion og stabile afgørelsesgrunde. Den eksisterende prioritering
  og motorens indgange er bevaret. Dette er første del af udskillelsen.
- Udbygningen udgives i et nyt signeret 2.16.0-kildearkiv. Den tidligere
  2.15.0-release og dens artifacts bevares uændret.

## 2.15.0 — 2026-11-23 (beta)

- Mappeobservationer uden hentbart indhold ændrer ingen eksisterende afgørelser og udløser ingen læring, heller ikke ved genbrugte ID'er. De tælles særskilt under Drift.
- Mails uden Message-ID scannes, og genbrugte ID'er med andet indhold får en selvstændig vurdering. Additive, kontobundne indholdsfingerprints beskytter frigivelse, læring, opslag og egne notifikationer uden at ændre mailens headere.
- Almindelige tilladelser genkontrolleres før en ventende flytning med komplette beslutningssymboler. Virus og forfalskningskontrol bevares. En hævet kontogrænse aflyser ventende rene scorebeslutninger.
- Drift viser 14 dages scanningstællere pr. postkasse. Nye lokale `quality-export`/`quality-evaluate` giver versionsmærket første-scanning-evaluering af menneskeligt mærkede prøveudvalg uden træning eller mailadgang.
- `backup-drill` starter app og Redis/Bayes på en privat gendannet kopi uden mailarbejdere. Månedlig off-site-kontrol og container-smokeprøven omfatter nu denne opstart.
- Mailidentitet, evalueringsregnestykke og gendannelsesprøve er udskilt i små moduler. Dokumentationen beskriver IMAP-efterbehandling, dækningsgrænser, stikprøvebias og rollbackens sikkerhedskonsekvenser.


## 2.14.2

- **Vedligeholdelse:** Test af opdatering efter flytning af repo. Ingen ændring i, hvordan filteret virker.

## 2.14.1

- **Opdateringssiden:** Et gammelt resultat (fx "Fejlet v2.11.1") vises ikke længere, når en samme eller nyere version allerede kører – fx efter en manuel installation.
- **Klar til offentligt repo:** De sidste husstandsspecifikke eksempler i test, dokumentation og kommentarer er erstattet med neutrale eksempler. Ingen ændring i, hvordan filteret virker.

## 2.14.0

- **Ingen personlige data i programmet:** Egne maildomæner, beskyttede domæner, webshops, betroede videresendere, servernavn, DNS-forwarder og LAN-adresse sættes nu op lokalt (Indstillinger → Lokal opsætning) og gemmes i `config/site.yml` på serveren. rspamd-reglerne for egne domæner dannes ud fra den, når containeren starter. En ny installation beder om opsætningen; mangler den på en eksisterende installation, vises en tydelig advarsel, og filteret kører videre.
- **Licens:** Spamfilter er nu udgivet under PolyForm Noncommercial 1.0.0. De dele, der stammer fra det oprindelige projekt, beholder deres MIT-licens (se THIRD-PARTY-NOTICES.md).
- Backup-tjekket og gendannelsesøvelsen tjekker nu også, at den lokale opsætning er med.

## 2.13.0

Tre nye beskyttelser mod phishing, bygget ud fra de mails, der faktisk slap igennem de sidste uger. De står på
**Til** fra start og kan slås over på Prøv eller Fra under **Nye beskyttelser** (samme kort som QR-koder og
Sanesecurity). Prøvet på de sidste 30 dages rigtige post: de ramte 61 spam- og phishingmails (heraf 10, der var
sluppet igennem) og ingen almindelige mails.

- **Snydetegn i emnet:** Russiske eller græske bogstaver gemt i danske og engelske ord ("Dоmænеnаvnеt еr blоkеrеt",
  hvor o, e og a er russiske) giver 5 point. Et emne helt på russisk eller græsk giver ingenting.
- **Betalings- og kontophishing:** Et emne om betaling, konto, abonnement, domæne, MitID, udbetaling eller
  ophavsret giver 4 point, når afsenderen samtidig har et faretegn: gratis mailadresse, et misbrugt topdomæne,
  falske tegn i navnet, snydetegn i emnet, et domæne under 60 dage, ingen DMARC-godkendelse, eller svar der går til
  et andet domæne. To faretegn giver 5 og tre eller flere 6. En rigtig tjeneste, der signerer for sit eget domæne,
  har ingen faretegn og får intet, og kendte kontakter beholder deres tillid.
- **Nyregistrerede domæner:** Filteret slår afsenderdomænets alder op i det offentlige domæneregister (RDAP, over
  almindelig HTTPS, ingen nye porte). Under 7 dage giver 4,5 point, under 30 dage 3. Gratis mailadresser og
  postkassernes egne domæner slås aldrig op; topdomæner uden RDAP (.dk, .de, .eu m.fl.) giver ingenting. Svar
  gemmes i 90 dage, opslag er begrænset, og en langsom eller utilgængelig server betyder blot "ingen viden".
- **AI'en** spørges nu også ved disse tegn (som ved de andre mistænkelige tegn).
- **Ugerapporten** tæller de nye beskyttelser med under "Nye beskyttelser".

## 2.12.3

- **Sammenklappelig menu:** Sidemenuen kan klappes sammen til en smal ikon-skinne med knappen nederst i menuen eller Ctrl/⌘+B (ikke mens du skriver). Tællere vises på ikonerne, og valget huskes i browseren. Versionsnummeret står nu under logoet. Mobil og "Menu i toppen" er uændret.

## 2.12.2

- **Graf rettet:** På brede skærme blev søjlerne i "Post de seneste 14 dage" klemt sammen på midten, så de ikke passede med datoerne. Nu fylder de hele bredden.

## 2.12.1

- **Sikkerhed:** Image'et tager nu Debians sikkerhedsrettelser til grundpakkerne med, når det bygges (bl.a. en rettelse til `apt`). rspamd er stadig låst til den testede version.
- Fra denne version skal udgivelser være signerede, før opdateringshjælperen installerer dem.

## 2.12.0

- **Udbyderens spam-mappe bliver scoret:** Mail, som mailudbyderen selv har lagt i sin spam-mappe, scorer filteret nu
  også, men kun ved at læse den (højst 10 pr. runde og kun fra de seneste 14 dage). Mailen flyttes eller markeres
  aldrig, og den læres ikke (scoren rummer udbyderens egen markering, og Bayes lærer kun af brugernes egne
  flytninger). Har filteret en lav score til en kendt afsender, står mailen under **Tjek disse**, så fejlplaceret
  post bliver opdaget.
- **Tilladelser, der strider mod brugerens egne flytninger:** Har en administrator tilladt en afsender i en postkasse
  (fx med **Tillad afsender** ved en frigivelse), og flytter brugeren alligevel mails fra afsenderen til Junk, vises det
  for administratorer under **Fanget spam → Tjek disse: regler og flytninger til Junk** med knapperne **Fjern reglen**,
  **Bloker for kontoen** og **Ignorer**. Filteret fjerner ikke selv en tilladelse, som en person har lavet.
- **Tre flytninger til Junk giver et forslag om at blokere afsenderen for den postkasse:** Flytter en bruger mails fra
  samme afsender til Junk 3 gange (inden for 180 dage), og dækker ingen regel afsenderen, foreslår filteret under
  Tjek disse at blokere netop den adresse i netop den postkasse. Administratoren vælger **Bloker for kontoen** eller
  **Ignorer**; filteret blokerer ikke selv. En flytning tæller kun, når afsenderen er bevist (DMARC eller en
  DKIM-signatur, der passer til afsenderens domæne, og ingen tegn på forfalsket afsender), og kun i postkasser, der
  lærer af flytninger. Andre postkasser påvirkes ikke, mails der allerede ligger i postkassen røres ikke, og der
  slettes intet: nye mails derfra flyttes til Spamfilter-mappen. vexar.example, pinsikbing.example og gravisk.example, alle
  postkassers platform- og webshopdomæner, alle postkassers domæner og alle postkasseadresser foreslås aldrig (samme
  beskyttelse som ved blokeringer i WebUI'en).
- **Nyhedsbreve læres ikke som spam:** Flytter man et almindeligt nyhedsbrev til Junk (afmeldingslink, signeret af
  afsenderens eget domæne gennem en kendt nyhedsbrevstjeneste, en afsender med historik, dvs. fast afsender eller
  tidligere godkendt post, under grænsen og ingen spam-tegn som phishing, falsk afsender, lister eller fuzzy), lærer hverken Bayes eller
  den lokale fuzzy-database den som spam. Mailen bliver i Junk som før. Det samme gælder **Flyt til spam** i WebUI'en, og
  så sættes andres kopier heller ikke i kø som en kampagne. Spam med afmeldingslink, der har spam-tegn eller kommer fra
  en ny afsender (også med en gyldig signatur), læres som før, og kampagne-oprydningen kører.
- **DMARC "Klar (lav volumen)":** Et domæne med få mails når sjældent 7 rapportdage på 14 dage. Efter 30 dage, hvor
  alle rapporterede kilder er kendte og består DMARC (ingen fejlende kilder overhovedet), viser DMARC-siden og
  anbefalingen nu **Klar (lav volumen)** med næste trin (p=quarantine, pct=100 eller p=reject).
- **Kontrolrum logger ind som den rigtige person:** Kontrolrum 1.104.0 sender den Kontrolrum-brugers eget brugernavn.
  Spamfilter tager imod det, når brugeren findes og har fluebenet **Må logges ind fra Kontrolrum** (som før), og
  ændringsloggen skriver nu **via Kontrolrum** ud for alt, personen gør i den session. Et langt eller ukendt navn
  afvises som ukendt bruger, så Kontrolrum kan sige, hvilken kobling der skal rettes. Ingen brugeres login-indstillinger
  er ændret.
- **Udbyderens spam-markering vejer mindre for kendte afsendere:** Har udbyderen sat sin egen spam-markering
  (`SPAM_FLAG`, +5) på en mail fra en fast afsender, en kendt kontakt eller et svar, tæller markeringen nu ca. +2. For
  farlige mails (virus, phishing) tæller den fuldt ud som før.
- **Genscanning, når virusscanneren er klar:** Mails, der blev scannet, mens ClamAV var ved at starte, bliver nu sat i
  kø også uden vedhæftninger (ClamAV læser også teksten). Køen venter, til ClamAV svarer, og bruger ikke sine forsøg
  imens. Første genscanning kører, så snart ClamAV er klar.
- **Gammel post i en ny postkasse tæller ikke som flytninger til Junk:** Rydder man op i mail fra før filteret begyndte
  at se postkassen, gemmes valget, men det tælles ikke og læres ikke. Tallene fra en ny postkasses første dage rettes én
  gang ved start (kun statistikken, ingen mail røres).
- **Kopien ud af huset overvåges:** Er kopien ud af huset ældre end 48 timer eller fejlet, kommer der en advarsel. En
  gang om måneden henter værten den nyeste krypterede backup ud af huset igen og tjekker den med `sfctl backup-verify`
  (kun læsning, i en midlertidig mappe, der slettes bagefter). Resultatet står under Drift → Krypteret backup, og en
  fejlet øvelse giver en advarsel.
- **Signerede opdateringer:** Kildepakkens kontrolsum signeres med en nøgle, hvis offentlige del ligger i
  `deploy/release-signers`. Værtens hjælper afviser en pakke med en forkert signatur. Fra version 2.12.1 skal der også
  være en signatur, ældre udgivelser kan stadig installeres uden. Se SECURITY.md. Udgivelsen signeres, før billedet
  bygges og lægges op, så en forkert nøgle stopper udgivelsen, inden noget når GHCR.
- **Login-spærring pr. adresse og brugernavn:** Forkerte forsøg spærrer nu brugernavnet fra den adresse, de kom
  fra (5 forsøg). Gæt udefra kan derfor ikke længere låse ejeren ude hjemme. Samtidig tælles alle forsøg udefra på samme
  brugernavn samlet (20 forsøg på 15 minutter), så et gætteangreb fra mange adresser stadig bremses. Spærringen pr. IP
  er uændret, og `sfctl unlock BRUGER` fjerner også den samlede spærring.
- **API-nøgler med rettigheden Administrator** virker kun fra hjemmenetværket (også en, der er lavet før) og har deres
  egen, lave grænse for antal kald.
- **Home Assistant:** Pakken skriver, hvilke postkasser den har sensorer for, og den nye
  `binary_sensor.spamfilter_pakken_skal_hentes_igen` slår til, når filteret har en postkasse, pakken ikke kender. Hent
  pakken igen under Indstillinger → Adgang for programmer, når der kommer en ny postkasse.
- **Drift og oprydning:** Advarsel, når docker.img er 85 % fuld. Ved en opdatering gemmes den forrige containers log
  (72 timer) i `operations/`, før containeren fjernes. Højst 3 gamle `source.prev`/`source.bak`-mapper og egne logfiler
  i 30 dage beholdes. Ingen mail, ingen database og ingen backup røres. rspamd må nu bruge 25 sekunder pr. mail (før 8).
- **Forsyningskæde:** CI tjekker Python-pakkerne med pip-audit og hele billedet med Trivy (fejler ved HIGH/CRITICAL med
  en rettelse), og Dependabot foreslår opdateringer hver måned. Redis er opdateret til 8.10.3, rspamd 4.2.2 til den
  nyeste genbygning, og billedet kræver mindst ClamAV 1.4.6. pip er fjernet fra billedet, så dets gamle kopier af
  urllib3 og certifi ikke længere ligger der.

## 2.11.2

- **Opdatering fra WebUI'en virker med et privat repo:** GitHub-tokenen, der er gemt under System → Opdateringer →
  Indstillinger, bruges nu også af værtens hjælper. Når man trykker **Opdatér nu**, og værten ikke har sin egen
  token-fil, gives tokenen med til hjælperen sammen med den signerede anmodning. Den er bundet til netop den anmodning,
  bruges kun mod det repo, værten selv har sat op, og slettes, så snart kildepakken er hentet. Den skrives aldrig i
  loggen, i status eller i en backup. En token-fil på værten (`operations/github-token`) går stadig forud.
- **Tydelig besked, når GitHub siger nej:** Svarer GitHub 401, 403 eller 404, står der nu, at tokenen ikke har adgang
  til repoet og skal have *Contents: read* på repoet, i stedet for en teknisk curl-fejl. Det gælder både for tjekket på
  siden og for selve opdateringen. Siden viser også, hvilken token hjælperen bruger.
- **Hjælperen holdes opdateret:** `deploy/aio/update.sh` installerer nu værtens User Scripts igen efter en vellykket
  opdatering, så en ny version af hjælperen (og af backup- og overvågningsjobbene) tages i brug med det samme.
- **Sikrere geninstallation af User Scripts:** Kan `schedule.json` eller `customSchedule.cron` ikke læses, stopper
  geninstallationen med en advarsel og lader filerne være. Den skriver aldrig en tom tidsplan.
- **Tokenen gives kun videre, når hjælperen er set** inden for de seneste minutter. Ellers afvises **Opdatér nu** med en
  besked, så tokenen ikke ligger og venter på en hjælper, der ikke kører.
- **Mere præcise fejl:** En slettet udgivelse eller en kladde giver "udgivelsen findes ikke" i stedet for "tokenen har
  ikke adgang", og en fejl fra download-værten kaldes ikke længere et adgangsproblem. Arbejdsmapper efter en afbrudt
  opdatering (fx strømsvigt) ryddes op efter 4 timer.
- **Overgang:** Den hjælper, der kører fra 2.11.0/2.11.1, kender ikke tokenen fra WebUI'en. Læg tokenen midlertidigt
  i `operations/github-token` på værten (root, 0600), tryk **Opdatér nu**, og slet filen igen, når 2.11.2 kører.
  Derefter bruger knappen tokenen fra WebUI'en. Se INSTALLATION.md.

## 2.11.1

- **Sikkerhedsopdatering af Python-pakker:** certifi, urllib3, Werkzeug, Flask og dnspython er opdateret til versioner
  uden kendte sårbarheder (certifi 2026.11.20, urllib3 2.8.0, Werkzeug 3.1.9, Flask 3.1.3, dnspython 2.9.2). Billedet
  tjekker under bygningen, at netop disse versioner er installeret.
- **"Lær som spam" flytter nu mailen som ventet:** Lærte man en mail som spam, mens filteret ventede på at flytte den,
  blev flytningen annulleret, og mailen blev liggende i indbakken. Nu bliver flytningen til Spamfilter-mappen
  gennemført som normalt. Det gælder også en mail, der er læst under ventetiden. Intet slettes. Lær som legitim og
  Frigiv annullerer stadig flytningen.
- **DMARC-tællere i statistikken:** Læste og flyttede DMARC-rapporter tælles nu korrekt, og loggen skriver ikke længere
  "unknown metric".
- **Tippet om SpamExperts i "Find en mail"** vises kun, når domænets post stadig går gennem SpamExperts (Mailsikkerhed ser
  SpamExperts i MX). Ellers vises det ikke.

## 2.11.0

- **Ny side "Adgang for programmer"** (Konti og adgang, kun administratorer): login fra Kontrolrum for personer og
  API-nøgler for programmer står nu side om side. Login fra Kontrolrum (SSO) virker som før; kortet er bare flyttet
  hertil fra Indstillinger og viser fingeraftryk, oprettet, sidst brugt og antal brugere.
- **Flere API-nøgler:** Hvert program (fx Home Assistant, Kontrolrum eller et script) kan få sin egen nøgle med sit eget
  navn og sin egen rettighed (Kun læse, Læse og styre eller Administrator). En nøgle kan slettes alene, uden at de andre
  holder op. Listen viser oprettet, sidst brugt med IP-adresse, "Ubrugt i 90 dage" og det seneste afviste forsøg.
- **Ny API-nøgle:** navn, rettighed, **Kun fra hjemmenetværket** (slået til som standard) og udløb (aldrig, 30, 90
  eller 365 dage). Nøglen (`sf_…`) vises kun én gang med en Kopiér-knap og et eksempel på `Authorization`-headeren.
  Spamfilteret gemmer kun et fingeraftryk (SHA-256) og de sidste 4 tegn.
- **Den gamle Home Assistant-nøgle virker videre:** Den flyttes automatisk over som "Home Assistant" med mærket
  **Flyttet**. Intet skal ændres i Home Assistant eller Kontrolrum. Deler de to den samme nøgle, kan man give Kontrolrum
  sin egen nøgle.
- Højst 60 læsekald og 10 styrekald i minuttet pr. nøgle, og forkerte nøgler bremses pr. IP-adresse. Loggen viser
  nøglens navn, aldrig selve nøglen.
- `sfctl api-key list|create|delete` til kommandolinjen; `sfctl ha-token` virker stadig. Ændringer af Claude AI.

## 2.10.1

- Søgefeltet (Ctrl K) vises nu også, når menuen ligger i toppen, og det finder alle sider i den nye menu. På telefonen er der en tydelig søgeknap.

## 2.10.0

- **Nyt udseende:** Spamfilteret bruger nu samme designsystem og menu som Fleetdeck. Under Udseende kan man vælge stil
  (Command med sidemenu eller Aurora med menu i toppen) og lyst eller mørkt tema; valget huskes i browseren.
- Topbjælke med søgefelt (Ctrl K eller "/"), kontovælger og brugermenu. På telefonen er der en fanebjælke med Oversigt,
  Spam, Beskeder, Find og Mere.
- Ingen farvede venstrekanter; knapper, kort, badges, tabeller og felter følger Fleetdecks komponenter. Nye app-ikoner.
- **Ny menu:** Siderne er samlet i få grupper efter, hvad man vil gøre: Oversigt, **Post** (Fanget spam, Beskeder,
  Find en mail, Fortryd flytninger), **Filtrering** (Regler, Træning, AI-vurdering), **Sikkerhed** (Mailsikkerhed,
  DMARC), **Konti og adgang** (Konti, Brugere) og **System** (Drift, Opdateringer, Indstillinger). Den skjulte gruppe
  "Avanceret" er væk. Samme grupper i sidemenuen, i topmenuen og under Mere på telefonen. Hjælp er (?) nederst i
  sidemenuen. En almindelig bruger har stadig sin enkle menu.
- **Opdateringer:** Ny side (kun administratorer), der viser den kørende version, den nyeste udgivelse på GitHub (kanal
  Beta eller Stabil) og ændringerne i de nyere versioner. **Opdatér nu** beder værten installere versionen med backup,
  test og automatisk tilbagerulning (User Script "Spamfilter-update"). Kun versionsnummeret sendes, signeret, og værten
  tjekker kildepakkens kontrolsum. En GitHub-token til et privat repo kan gemmes krypteret. Se INSTALLATION.md.
- Alle sider og funktioner er bevaret. Ændringer af Claude AI.

## 2.9.0

- **Login fra Kontrolrum:** Husstandens dashboard Kontrolrum kan nu logge ind i spamfilteret af sig selv, også når Kontrolrum åbnes hjemmefra gennem Cloudflare-tunnellen. Kontrolrum skal ikke kende nogen adgangskode: det får en nøgle (**Indstillinger → Kontrolrum → Lav SSO-nøgle**, vises kun én gang og gemmes krypteret) og må kun logge ind som brugere med fluebenet **Må logges ind fra Kontrolrum** (standard fra). Login virker kun fra de IP-adresser, du skriver på kortet.
- **Sessionen er bundet til Kontrolrum:** Den gælder for en "Kun lokalt"-bruger, men kun så længe hvert kald kommer fra Kontrolrums adresse. En kopieret cookie, der bruges direkte på tunnel-adressen eller et andet sted, logges ud med det samme. En ny nøgle, **Slå fra**, en fjernet adresse eller et fjernet flueben logger også Kontrolrum ud. Adgangskoder til "Kun lokalt"-brugere virker stadig kun hjemme.
- Login fra Kontrolrum står i revisionsloggen og loginhistorikken, og første gang giver det en advarsel om ny enhed som andre logins.

## 2.8.4

- **Afvis et forslag:** Forslag til følsomhed (på Oversigt og på kontosiden) har nu en **Afvis**-knap. Et afvist forslag kommer kun igen, hvis filteret når frem til et andet forslag. Blokeringsforslagenes knap hedder nu også **Afvis** (før Ignorer).

## 2.8.3

- **DMARC-rapporter fra Cisco flyttes nu også:** Ciscos e-mailsikkerhed (bruges af mange virksomheder) signerer ikke sine rapporter med DKIM, så de blev liggende i indbakken. De tages nu, når afsenderen er bekræftet på anden måde (DMARC godkendt via SPF for Ciscos eget domæne), lægges i mappen DMARC-rapporter og tælles med på siden DMARC.

## 2.8.2

- **Afgør flere mails på én gang i Tjek disse:** Hver mail har nu et afkrydsningsfelt, og øverst kan alle vælges. Når der er valgt nogen, kommer en bjælke med **Frigiv** og **Det er spam**, så man ikke skal trykke på hver enkelt. Intet slettes: Det er spam lader mailen blive i spam-mappen og lærer filteret, at den er spam.

## 2.8.1

- **Sidemenuen kan klappes sammen:** En knap øverst i menuen gør den til en smal bjælke med kun ikoner, så der bliver mere plads til indholdet. Hold musen over et ikon for at se navnet. Valget huskes i browseren. Gælder computer og tablet; telefonen bruger stadig bundmenuen.

## 2.8.0

Mere phishing fanget. Alt nyt starter i **Prøv** (Indstillinger → Nye beskyttelser), så det kun viser, hvad det ville fange, før det må give point.

- **Ekstra phishing- og svindellister til antivirus:** ClamAV får Sanesecurity's gratis lister over phishing, svindel og farlige filer (kun lister med lav fejlrate). De hentes automatisk et par gange i døgnet og bruges kun, når deres digitale signatur passer, og ClamAV kan indlæse dem. Et fund giver point (+6 for phishing og svindel, +4 for resten), men behandles aldrig som en virus. Selve mailteksten scannes nu også.
- **Forkortede links følges:** bit.ly, t.co og andre kendte forkortere følges til den rigtige adresse, som tjekkes mod sortlister og phishinglister. Kun adressen hentes, aldrig selve siden.
- **QR-kode-phishing:** QR-koder i billeder og på første side af vedhæftede PDF'er aflæses, og linket tjekkes: kendt phishing (+7), mistænkelig adresse som forkorter, IP-adresse, misbrugt topdomæne eller et brand-navn i et fremmed domæne (+3, +2 mere med et lokkende emne). En almindelig QR-kode giver 0 point.
- **AI ser flere mistænkelige mails:** Den lokale AI spørges nu også om mails med lav score fra ukendte afsendere, når der er et advarselstegn (lokkende emne, freemail-afsender, Googles relæ, første mail fra afsenderen). Kendte kontakter vises stadig aldrig, og AI'en giver aldrig point til mails til de beskyttede adresser.
- **Ugerapporten** viser, hvad de nye beskyttelser har fundet.
- **Rettet:** Den sidste rest af strafpointene på en stor nyhedsbrevsudbyders fælles domæne er væk.

## 2.7.6

- **Færre gode nyhedsbreve og shop-mails i spam:** En stor nyhedsbrevsudbyders fælles link-domæner stod på en sortliste, så alle mails sendt gennem den fik 5 strafpoint, også kontomails og licensmails fra webshops. Udbyderens fælles domæner tjekkes ikke længere mod sortlisten; shoppens egne links gør stadig.
- **Phishing via Google fanges:** Svindlere sender "Meddelelse vedrørende din konto" og "Handling påkrævet for at bevare dine filer" fra tilfældige Gmail-adresser gennem en Google-tjeneste, så mailen består alle afsendertjek. En ukendt Gmail-afsender sendt den vej giver nu 7 point. Kendte kontakter trækker stadig deres tillidsfradrag fra.
- **Kontomails bliver i indbakken:** "Din konto er blevet oprettet" / "Your account has been created" flyttes ikke længere til Nyhedsbreve.

## 2.7.5

- **Rettet: den lokale genkendelse af kendt spam var aldrig startet.** Når en mail markeres som spam, gemmes et "fingeraftryk", så senere kopier af samme spam genkendes. rspamd 4.2 starter ikke længere den database, som fingeraftrykkene ligger i, af sig selv, så den kørte ikke. Den startes nu, lytter kun inde i containeren, og fingeraftrykkene gemmes i den samme Redis som resten af filterets hukommelse.

## 2.7.4

- **Rettet: databasen kunne blive beskadiget om natten.** Den natlige krypterede backup kørte inde i selve filteret. Når den læste databasefilen, mistede filteret sine låse på databasen, så en anden proces kunne rydde databasens skrivelog væk, mens filteret stadig skrev i den. Backuppen kører nu i sin egen proces, så filterets låse aldrig røres. En test viser både fejlen og rettelsen.

## 2.7.3

- **Én alarm i stedet for mange:** Står flere postkasser stille på samme tid (fælles årsag), sendes nu én samlet alarm i stedet for én pr. postkasse.
- **Tjek af databasen:** Overvågningen tjekker hvert 5. minut, at filterets database er hel. Er den beskadiget, kommer én tydelig besked om det (og ingen "hængt?"-mails oveni), så den kan gendannes fra backuppen med det samme.

## 2.7.2

- **Postkassekortene viser også udbyderens spam-mappe:** Under "Spam" står nu fx "+ 224 i udbyderens spam-mappe", når mailudbyderens eget filter (fx Scannets) har lagt mails i Junk. Det giver det samlede billede af, hvor meget spam en postkasse får.

## 2.7.1

- **Mailsikkerhed – DKIM:** Når mails fra jeres domæne ikke er DKIM-signeret, viser tjekket nu, hvilken server de kom fra (fx hjemmesidens webhost). Rådet peger på den rigtige afsender i stedet for altid på mailudbyderen.

## 2.7.0

### Virusscanning med ClamAV
- **Indbygget antivirus:** ClamAV kører nu i alt-i-én-containeren. rspamd sender hver vedhæftning (op til 20 MB, også pakket ud af arkiver) til ClamAV. Et fund bliver trusselsklassen **Virus**: mailen flyttes altid til Spamfilter, en almindelig bruger kan aldrig frigive den, og der kommer Straks-advarsel og besked på telefonen som ved de andre trusler.
- **Virussignaturerne hentes automatisk** fire gange i døgnet og gemmes i app-mappen (`clamav/`, ca. 300 MB), så de ikke hentes igen, når containeren laves om. Første gang tager det nogle minutter; imens scannes mails som før, bare uden virustjek.
- **Fejler ClamAV, kører filteret videre:** svarer ClamAV ikke, får mailen kun en informativ markering uden point, og `sfctl doctor`, sundhedstjekket og Home Assistant viser en advarsel (også når signaturerne er over 3 dage gamle). Containeren bliver aldrig "unhealthy" af ClamAV alene.
- **RAM:** containeren har nu 4 GB (før 3 GB), fordi ClamAV bruger ca. 1-1,5 GB. På en server med lidt RAM kan ClamAV slås fra med `SF_CLAMAV=0` (Unraid-skabelonen: **Antivirus (ClamAV)**).
- ClamAV lytter kun på en lokal socket inde i containeren og kører som sin egen bruger (uid 3310). Ingen ny port.
- **Virus-genscanning:** Svarede ClamAV ikke, da en mail med vedhæftninger kom, scannes den igen efter 10 minutter, 1 time og 6 timer – også fra kendte kontakter og tilladte afsendere. Kun en rigtig virus flytter den. Ved start venter filteret op til 2 minutter på ClamAV, så mails efter en genstart også bliver virusscannet. ClamAV har nu 8 tråde og stopper selv en scanning efter 5 sekunder.
- Mails over 5 MB scannes slet ikke (som før) – heller ikke for virus. Den gamle opsætning med fire containere får antivirus slået fra (der er ingen ClamAV dér).
- **Heuristiske fund er ikke virus:** ClamAV's heuristik, PUA, phishing-signaturer og tredjepartslister (Sanesecurity m.fl.) giver kun +4 point (`TH_CLAM_HEURISTIC`) og kan frigives af brugeren; kun rigtige virussignaturer bliver trusselsklassen Virus.

### Lokal AI-vurdering
- **En ekstra vurdering af grænsetilfælde** fra jeres egen lokale AI (Ollama på hjemmenetværket, standard `qwen2.5:7b`). Kun mails i indbakken med en score lige under grænsen (standard fra 3 og op til grænsen) bliver vurderet. Kendte kontakter, svar på jeres egne mails, tilladte afsendere, beskyttede adresser, trusler, falske afsendernavne og mails, der allerede er afgjort, bliver aldrig sendt til AI'en. AI'en ser kun rspamds egne regelnavne, ikke filterets.
- **Intet forlader huset:** Der sendes intet, før en administrator har gemt Ollama-adressen. Adressen skal være en IP-adresse på hjemmenetværket (aldrig selve containeren eller link-local). AI'en får kun afsender, svar-til, emne, dato, reglernes navne, link-domæner, vedhæftningernes navne og de første 2000 tegn tekst – aldrig modtagere, IP-adresser eller andre headere. Selve mailteksten gemmes ikke.
- **Fra / Prøv / Til** under **Avanceret → AI-vurdering**. Alle starter i **Prøv**, som kun gemmer vurderingen. **Til** giver op til +3 point ved spam og phishing – aldrig minuspoint, så en mail, der prøver at snyde AI'en, højst kan undgå at få point. Kun i postkasser i Filtrér.
- **Mailen venter aldrig på AI'en** ud over den normale ventetid. Svarer AI'en ikke, eller svarer den for sent (eller bliver svaret først brugt over 5 minutter efter fristen), vurderes mailen præcis som før. Kun administratorer ser AI'ens begrundelse. Højst 120 vurderinger i timen, og filteret holder pause, hvis Ollama ikke svarer.
- **Evaluering** på samme side: de seneste vurderinger med udfald og brugerens dom, enighed med brugerne, hvor mange der ville være flyttet med Til, og falske positiver. **Test forbindelse** viser de installerede modeller. `sfctl doctor` advarer, hvis Ollama ikke svarer.

### Falske afsendernavne
- **Beskyttede navne:** En mail, der bruger navnet på en af jeres egne som afsendernavn, men kommer fra en fremmed adresse (den klassiske "direktørsvindel" med en hurtig betaling eller et gavekort), får point. Går svaret til en anden adresse, eller handler emnet om betaling eller hast, får den flere. Sådan en mail får aldrig fradrag som kendt kontakt eller svar.
- Navnene matches uden accenter (æ/ø/å = ae/oe/aa), i begge rækkefølger, med ekstra mellemrum og med forvekslelige tegn fra andre alfabeter. Et navn på ét ord rammer kun, når afsendernavnet er præcis det ord, så andre med samme fornavn går fri.
- Listen fyldes selv med jeres afsendernavne fra Sendt post og kan rettes under **Indstillinger → Beskyttede navne**: personens rigtige adresser, domæner personen skriver via, og **Tillad adressen** direkte fra et fund. Jeres egne domæner er altid tilladt.
- **Fra / Prøv / Til**, standard **Prøv**: filteret viser kun, hvilke mails der ville have fået point. Efter en uge foreslår Oversigt at slå det til.
- **Færre falske fund:** almindelige ord som faktura, regning og betaling giver ikke længere ekstra point – kun tydelige svindelsætninger (gavekort, "Er du ved din computer?", hast eller fortrolighed om en overførsel), svar til et fremmed domæne eller et ugyldigt afsenderfelt. En faktura sendt i firmaets navn fra en platform med gyldig signatur (fx e-conomic) får højst 5 point, og en besked "via" en platform (Google Docs, MobilePay) kun 2.
- **Snyd med afsenderfeltet virker ikke:** to afsenderlinjer, flere adresser, komma eller affald til sidst og adresser som `ole@bynet.example@evil.example` giver nu det stærke fund i stedet for at blive sprunget over.
- Delte webshop-platforme (fx vexar.example) tæller ikke længere som jeres eget domæne her; dér skal personens præcise adresse stå på listen. Kalibreringen bruger nu samme tjek som den rigtige scanning.

### Mailsikkerhedstjek
- **Ny side Mailsikkerhed** (Avanceret): tjekker jeres egne domæner og mailservere hver nat og med **Tjek nu** – MX, SPF (én post, -all, højst 10 DNS-opslag), DKIM, DMARC (politik, rapportadresse og tilladelse til eksterne rapportadresser), DNSSEC, MTA-STS/TLS-RPT (valgfrit) og jokertegn i DNS. Hvert punkt får OK, Advarsel eller Fejl med en forklaring og hvad der skal rettes hos hvilken udbyder.
- **DKIM ud fra jeres rigtige mail:** selectors læres af de mails, filteret faktisk har modtaget fra jer, og af DMARC-rapporterne. Sendes jeres mail uden DKIM-signatur, er det en fejl med besked om at slå DKIM til hos udbyderen.
- **Domæner, der ikke sender mail,** kan markeres; så tjekkes der for `v=spf1 -all` og `p=reject`.
- **Mailservere:** kryptering (STARTTLS/TLS 1.2+), certifikatets navn og udløb for MX, afsenderserver og postkassernes IMAP-servere. Blokerer internetudbyderen port 25, står der "kunne ikke testes" i stedet for en fejl.
- **Blokeringslister:** de adresser, jeres mail faktisk sendes fra, og MX-serverne slås op i Spamhaus, SpamCop, Barracuda og PSBL via filterets egen DNS. Afviste Spamhaus-opslag vises som "kunne ikke slås op".
- **Intern tilstand** på samme side: sundhedstjek, livstegn, backup og DMARC-rapporter med link til Drift.
- **Historik og advarsler:** de seneste 30 tjek og hvad der er ændret siden sidst. Mail og push kun, når noget bliver værre i to tjek i træk, eller med det samme ved en ny opførelse af en afsenderadresse på en blokeringsliste eller et certifikat med under 7 dage tilbage – samme problem kun én gang, og ikke igen inden for en uge, hvis det kommer og går.
- **Ingen falske alarmer:** er nettet eller DNS nede under tjekket, står alt som "ikke testet", og der sendes intet. En server, der afviser testforbindelsen fra en hjemme-IP, en intern adresse, SERVFAIL uden bevis for ødelagt DNSSEC og Spamhaus PBL er heller ikke fejl.
- **Kendt – ignorér** ved hvert problem: det vises så som info, giver ingen beskeder og tæller ikke med i Home Assistant, før det ændrer sig.
- `sfctl mailcheck` kører tjekket fra kommandolinjen, `sfctl doctor` viser én linje fra det seneste, og Home Assistant får en kort status.

## 2.6.2

- **Vagten for beskyttede adresser** tæller nu kun mails, der scorer mellem den normale grænse og den nuværende grænse for beskyttede adresser, og som ikke er blokeret. Før talte den også gamle mails fra før grænsen blev sænket – mails, som allerede var væk fra indbakken – og sendte en falsk advarsel.

## 2.6.1

- **De nye spamregler fra 2.6.0 er nu aktive.** Opdateringen installerede ikke rspamd-reglerne i app-mappen (kun ved første installation), så brand-svindel i emnet, Phishing Army og de nye lokke-emner var ikke slået til. `update.sh` tester nu reglerne med det nye image i en engangscontainer uden netværk, installerer dem og lægger de gamle tilbage, hvis den nye container ikke kommer op.

## 2.6.0

Fokus: mindre spam i indbakken, filteret rydder selv op, og bedre beskyttelse af login og data.

### Mindre spam
- **Brand-svindel i emnet:** Et kendt brand i emnet (MobilePay, MitID, EasyPark, PostNord, banker, forsikring, tele og energi) sammen med et typisk lokke-emne ("opdater dine betalingsoplysninger", "forbind din … til MitID", "betalingen kunne ikke gennemføres") fra et domæne, der ikke er brandets eget, giver nu point. Brandlisterne er udvidet. Almindelige danske emner som "Din refusion via MobilePay er på vej" holdes under grænsen.
- **Samme spam på alle postkasser:** Når nogen markerer en mail som spam, flyttes ulæste kopier af samme kampagne i de andre postkasser også, når de selv scorer tæt på grænsen, eller når mindst to har markeret den. Fortrydes markeringen, annulleres oprydningen. Kendte kontakter, tilladte afsendere og mail, I har frigivet, røres aldrig.
- **Forslag om blokering:** Når samme afsenderdomæne er markeret som spam i mindst to postkasser, vises et forslag med én knap: "Bloker for alle". Aldrig freemail, kendte brands eller jeres egne domæner.
- **Flere phishing-lister:** Phishing Army supplerer OpenPhish. Listen opdateres automatisk.
- **Vagt for beskyttede adresser:** Du får besked på mail og telefon, hvis spam over grænsen samler sig i en beskyttet indbakke.

### Mappen Nyhedsbreve
- Nyhedsbreve og reklamer kan flyttes til mappen **Nyhedsbreve**. Det vælges pr. postkasse: Fra / Prøv / Til. Alle starter i **Prøv**, som kun viser, hvad der ville blive flyttet.
- Kendte kontakter, svar, kvitteringer, ordrer, koder og invitationer bliver i indbakken. Trækker du en mail tilbage, husker filteret afsenderen.
- Spam har altid forrang, og intet bliver lært som spam.

### Sikkerhed
- **Passkeys:** Log ind med Face ID, fingeraftryk eller en sikkerhedsnøgle via den eksterne adresse. Det tæller som adgangskode og to-trins-login, og det kan ikke phishes. Passkeys fjernes ved nulstilling af adgangskode og, som standard, ved "Log ud overalt".
- **Besked ved nyt login** fra en ny enhed (mail og telefon) og til administratorer ved gentagne forkerte forsøg.
- **Krypteret backup hver nat** til `/backup` på Unraid-arrayet og videre til skyen med rclone. Gendannes med `sfctl backup-restore` til en ny mappe. Advarsel, hvis der ikke er lavet backup i 48 timer.

### DMARC
- **DMARC-rapporter** fra Google, Microsoft m.fl. fanges, når de er ægte (DKIM-signeret af afsenderen) og ikke er spam. De lægges i mappen DMARC-rapporter og vises på siden **DMARC**: hvem sender som jeres domæner, og er de klar til en strammere politik.

### Rettelser efter uafhængig gennemgang
- En falsk "DMARC-rapport" kan ikke længere slippe uden om scanningen.
- En fortrudt spam-markering kan ikke flytte post i andre postkasser.
- Statusfiler fra værtens scripts skrives sikkert (ingen symlink-angreb).
- Grænse pr. IP for passkey-forsøg, så login ikke kan blokeres udefra.
- Opdateringen ruller nu også tilbage til ende, hvis man trykker Ctrl-C eller mister forbindelsen undervejs på Unraid 7 (bash 5.3 kunne stoppe tilbagerulningen).

## 2.5.0

Fokus: hurtigere håndtering af mail på telefonen og beskeder, når der sker noget.

### Stryg på mails
- **Stryg til højre for Frigiv og til venstre for Det er spam** i Fanget spam, Tjek disse og Beskeder – i browseren og i appen på hjemmeskærmen. Knapperne er der stadig; strygningen er en genvej.
- Serveren bestemmer, hvad hver række må: en bruger får aldrig Frigiv på en farlig mail, og en administrator skal stadig bekræfte først.
- Rækken følger fingeren, giver tydelig farve og ikon, når den er langt nok, og glider tilbage ved et kort træk. Lodret rulning, træk-for-at-opdatere og browserens tilbage-strygning virker som før.
- Samme resultat og **Fortryd** som knapperne. Et lille tip vises første gang.

### Beskeder på telefonen
- **Push-beskeder direkte på enheden** (Min konto → Beskeder på denne enhed) ved farlig mail stoppet, nye mails under Tjek disse og – for administratorer – problemer med filteret. Virker i appen på hjemmeskærmen på iPhone (iOS 16.4+) og i nyere Chrome, Edge og Firefox.
- Uden konto hos en tredjepart: filteret sender selv til den push-tjeneste, browseren har valgt, krypteret og signeret.
- Beskederne indeholder kun antal og postkassens navn – aldrig afsender, emne eller adresse. Brugere får kun beskeder om deres egne postkasser.
- Valg pr. enhed, **Send testbesked**, liste over egne enheder og nødstop med `sfctl push-reset`. `sfctl doctor` og `sfctl push-status` viser tilstanden.
- Grænser: højst én besked pr. slags pr. 10 minutter og 20 om dagen; flere hændelser samles i én besked.

### Rettelser efter gennemgang
- Afviser en push-tjeneste filterets egen nøgle (fx forkert ur), beholdes alle enheder, og fejlen vises i `sfctl doctor` i stedet for at enhederne slettes.
- Grænsen for testbeskeder holder også ved mange tryk på én gang.
- Strygning i Tjek disse gør ikke længere siden bredere end skærmen.
- En række, der bliver opdateret, mens man stryger på den, efterlader ikke længere en farvet baggrund.
- Teksten bag rækken vises først, når den kan ses helt; indtil da kun ikonet.
- Sproglig rettelse i vejledningen til iPhone.

## 2.4.1

- **Træk for at opdatere** i appen på hjemmeskærmen.

## 2.4.0

Fokus: hele spamfilteret i én container.

### Én container
- **Alt i én:** Filteret og WebUI'en, rspamd, Redis og Unbound kører nu i én container med ét ikon, én mappe og én opdatering. Det interne netværk og de tre hjælpecontainere forsvinder.
- **Kun WebUI'en er åben.** rspamd, Redis og Unbound lytter kun inde i containeren. Hver del kører med sin egen bruger og de samme ejere som før.
- **Selvreparation:** Går en del ned, genstarter den af sig selv med stigende pause, uden at resten stopper. Delene startes i den rigtige rækkefølge og stoppes pænt.
- **Ét sundhedstjek for alle fire dele.** Docker viser, hvilken del der har problemer. `sfctl doctor` tjekker også Redis og Unbound.
- **Unraid-skabelon** med ikon, WebUI-link og beskrivelse på dansk.

### Flytning og drift
- **Sikker flytning fra fire containere til én:** backup først, og de fire stoppes uden at blive slettet. Bagefter kontrolleres de fire dele, versionen, kontiernes forbindelse, Bayes-tallene og Home Assistant. Fejler noget, rulles der automatisk tilbage.
- **Prøvekørsel før flytningen** på en kopi af backuppen. Alle konti er slået fra, og koderne er fjernet, så ingen postkasse bliver rørt.
- Tilbagerulning til de fire containere når som helst, indtil oprydningen er kørt. Oprydningen fjerner kun spamfilterets egne gamle containere, netværk og billeder.
- Opdateringer af den nye container med backup, kontrol og automatisk tilbagerulning.
- Backup og overvågning virker med både én og fire containere. Overvågningen viser i alarmen, hvilken del der fejler.
- **GitHub** bygger og prøvekører den nye container ved hver ændring og udgiver præcis det prøvekørte billede ved en release.

### Rettelser efter gennemgang
- **Prøvekørslen læser nu Bayes-dataene fra backuppen.** Før startede kopiens Redis tom, fordi AOF var slået til, og testen fejlede altid på rigtige data.
- **Prøvekørslen kan ikke logge ind nogen steder,** uanset hvor kontiens kode ligger. Ventende fortryd- og træningsjob fra backuppen annulleres i kopien.
- **Ctrl-C eller en afbrudt SSH-forbindelse** under flytning eller opdatering stopper ikke længere tilbagerulningen halvvejs.
- **Beskyttelse mod to Redis-servere på samme data:** Overvågningen giver straks alarm og stopper en gammel Redis, der bliver startet ved siden af den nye container.
- Tilbagerulningen lægger de fire containere tilbage i Unraids autostart i den rigtige rækkefølge og reparerer en afbrudt flytning.
- **Strammere sikkerhed:** rspamds styring kræver altid adgangskoden i den ene container, og Unbound bruger en almindelig port, så containeren ikke behøver en særlig systemindstilling.
- Redis-billedet, som containeren bygges af, er låst, så en build altid får de samme filer. Billedet indeholder en liste over sine pakkeversioner.
- **Gendannelse af Redis** fra backup er rettet i BACKUP.md: Redis skal første gang starte med AOF slået fra.

## 2.3.0

Fokus: post fra folk, du kender, kommer sikkert igennem, farlig post går aldrig igennem, og filteret kan sende mail.

### Kendte kontakter
- **Folk, du har skrevet til:** Filteret lærer af dine sendte mails, hvem du skriver med, og giver deres mails et forspring. Det læser kun modtageradresser og Message-ID, aldrig indholdet, og gemmer adresserne som nøglede hashes.
- **Svar på din mail:** Svar på mails, du selv har sendt, genkendes og får det største forspring. Lige før en flytning tjekkes Sendt igen, så et svar på en netop sendt mail også kommer igennem.
- **Fast afsender og første mail:** Afsendere, der længe har skrevet til dig fra samme opsætning, får et lille forspring. En helt ny afsender får et lille tillæg.
- Tilliden kræver en bekræftet afsender (DKIM eller DMARC), er samlet højst 6 point og gælder aldrig for farlig post, falske afsendere eller blokerede afsendere.
- **Regler → Kendte kontakter** viser status, søgning, personer og organisationer, og kontakter kan fjernes og gendannes. Mails viser mærker som "Kendt kontakt" og "Svar på din mail". Markeres en kendt kontakts mail som spam, fjernes kontakten, med mulighed for at fortryde.

### Trusler
- **Virus, phishing-links, malware-links og farlige vedhæftninger** flyttes uanset score og regler og læres aldrig som legitime. Kun en administrator kan frigive dem, efter en bekræftelse.
- **Farlige filtyper** (programmer, scripts og diskbilleder) blokeres, også inde i zip-filer og med navnetricks som dobbelte endelser. Listen kan rettes, og der kan laves undtagelser for bekræftede afsendere.
- **Genscanning:** Mails, filteret var i tvivl om, scannes igen efter 45 minutter, 4 timer og 24 timer. Er de kommet på en sortliste i mellemtiden, flyttes de, hvis de stadig er ulæste.
- Ugerapporten viser trusler stoppet og mails flyttet efterfølgende.

### Mail fra filteret
- **Indstillinger → Mailserver:** Filteret kan sende mail gennem udbyderens SMTP-server, altid krypteret. Postkassens eget login kan bruges, så der ikke skal gemmes en ekstra adgangskode.
- **Notifikationer:** Alarmer, daglig opsummering, ugerapport og sikkerhedsbeskeder kan komme som mail til valgte modtagere. Filteret scanner aldrig sine egne notifikationer.
- **To-trins-login med kode på mail** som alternativ til appen. Ændringer af to-trins-login kræver en kode fra den metode, man allerede har, og giver en sikkerhedsmail.

### Adgang
- **Kun lokalt:** En bruger kan begrænses til hjemmenetværket. Alt gennem en tunnel eller proxy tæller som udefra.
- Nye nødkommandoer i `sfctl` til mailserveren og login-sted.

### Drift
- Udrulningsscripts rydder op efter en vellykket opdatering: den stoppede rollback-container fjernes (kan beholdes med `--keep-rollback`), og gamle filterbilleder slettes. Det kørende og det forrige billede bevares altid.
- Reparér Bayes: hos udbydere, hvis spam-markering er upålidelig, er markeringen alene ikke længere nok som bevis.
- Mindre layoutrettelser på Oversigten på tablets og ensartede danske tekster ("sikkerhedsbremsen").

## 2.2.0

Fokus: færre gode mails i spam, bedre fangst af phishing og en hukommelse (Bayes), der kan repareres.

### Bedre fangst af phishing og falske afsendere
- **Falske brands:** Ny regel for afsendernavne, der udgiver sig for at være et kendt firma (pakkeselskaber, betalingstjenester, banker, offentlige tjenester, store webshops), når mailen kommer fra et andet domæne. Listen over ægte domæner kan udvides.
- **Forvekslelige bogstaver:** Afsendernavne med græske, kyrilliske og lignende bogstaver, der ligner latinske, giver nu point.
- **Lokkende emner:** Danske og engelske lokkemønstre om betaling, pakker, konti og gevinster. Alene giver de kun lidt. Sammen med en falsk afsender giver de meget.
- **Misbrugte topdomæner:** Afsendere på topdomæner, som spam-kampagner skifter imellem, får point. .cn og .ru får færre point.
- **OpenPhish:** Den offentlige liste over phishing-links er slået til. Ejerens egne webshops undtages.
- Rapporterne og "Hvorfor?" forklarer de nye grunde på almindeligt dansk, fx hvilket firma afsendernavnet udgiver sig for at være.

### Færre gode mails i spam
- Vægten er sat ned på regler, der især rammer legitime nyhedsbreve, fakturaer og webshop-post. Det gælder bl.a. gråliste-links, Outlook-Message-ID'er, Microsoft 365-afsendere og PDF-fakturaer.
- **Webshop-platform på domæneliste:** Står ejerens egen webshop-platform fejlagtigt på en offentlig domæneliste, trækker filteret pointene fra igen. Det sker kun, når der ikke er andre tegn på et farligt link, og hændelsen vises på Drift. Egne domæner er undtaget fra domænelisterne.
- **Sen scanning:** Mails, der scannes mere end 6 timer efter modtagelsen (efter et nedbrud eller en opdatering), får ikke længere falske SPF-, DMARC- og datostrafpoint. I stedet bruges udbyderens egen godkendelse fra modtagelsen. Grænsen kan indstilles pr. konto.
  - En almindelig tilladelse gælder ved sen scanning kun, når noget beviser afsenderen: udbyderens godkendelse eller en gyldig signatur. Fejlede udbyderens SPF- eller DMARC-tjek, vurderes mailen på sin score.
  - Lister over kendte afsendere, der bygger på SPF og DMARC, er også slået fra ved sen scanning. Ellers kunne de give store betalingstjenester strafpoint i stedet for fradrag.
- Kalibrering og forslag til grænsen holder sene scanninger adskilt, så tallene er til at stole på.

### Reparér Bayes
- **Træning → Reparér Bayes** viser mails, der er lært som legitime, men hvor der er tegn på spam: en phishing-regel, brugerens egen markering eller udbyderens vurdering. Valgte mails læres som spam i en baggrunds-**læreliste**. Den læser kun mails og flytter intet.
- Lærelister kan følges, stoppes og prøves igen. "Prøv igen" vises kun, når der er noget at prøve igen, og genoptager også de mails, en stoppet liste ikke nåede.
- **Rebalancér fra spam-mapper:** Viser først en plan og lærer derefter fra spam-mapperne, indtil forholdet mellem spam og legitim post er nået. Indbakken læres aldrig som spam på den måde.
- **Ham-vagt:** Filteret lærer aldrig en mail som legitim, hvis en phishing-regel ramte den, hvis afsenderen er blokeret, eller hvis den kun lå under grænsen på grund af filterets egne bonusser. Informative regler, fx "link til egen webshop", tæller ikke som phishing.

### Ugerapport
- Valgfri rapport hver mandag morgen, lagt direkte i indbakken. Den viser ugens tal pr. postkasse sammenlignet med ugen før, de mest blokerede domæner, forslag til grænsen og driftsstatus.
- **Webshop-linje:** Rapporten dokumenterer, at webshop-posten kom igennem, og viser en eventuelt flyttet mail med et link til at frigive den.
- Rapporten kan forhåndsvises og sendes som prøve under Indstillinger. Brugere kan få en kort version, der kun handler om deres egen postkasse.

### Drift og udrulning
- De nye rspamd-filer og deres lister installeres, valideres før aktivering og indgår i konfigurationens fingeraftryk.
- Udrulningen noterer nu, hvilke konfigurationsfiler den har oprettet (`NEW_FILES` i config-backup). `deploy/README.md` beskriver, hvordan man går tilbage til 2.1 og fjerner de nye regler.
- Første tjek af spam-mapperne sker med det samme på en nystartet maskine.
- Alle databaseændringer er additive. 2.1 kan køre videre på en 2.2-database.
