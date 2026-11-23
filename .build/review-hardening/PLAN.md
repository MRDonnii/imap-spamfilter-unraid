# Plan: gennemgang, rettelser og installationsklar udgivelse

Oprettet 22. november 2026. Brugerens bestilling er at gennemføre alle punkter fra kodegennemgangen, committe og pushe ændringerne og gøre en testet udgivelse klar til installation 23. november. Byggearbejdet starter tidligst 22. november kl. 23.55.56 UTC (23. november kl. 00.55.56 dansk tid), efter den ønskede ventetid på 62 minutter. Kvotens faktiske nulstilling kan ikke aflæses.

## Afgrænsning og arbejdssted

- Kun `MRDonnii/imap-spamfilter-unraid`, det offentlige repository.
- Arbejdsmappe: `/home/donnii/Codex/imap-spamfilter-unraid`.
- Branch: `agent/review-hardening`. Kontroller nyeste remote inden ændringer; bevar andres arbejde.
- Gennemgået udgangspunkt: `249fca756a11ba24fc301f4cbe73314711091534`, version 2.14.2.
- Det private repository må ikke åbnes eller ændres.
- Ingen installation, SSH-ændringer, konfigurationsændringer eller mailhandlinger på den kørende server. Ingen rigtige mails i tests eller offentlige artifacts.
- Brug den eksisterende arkitektur, filrettigheder, adgangspolitik, trusselskontrol, flyttejournal, sikkerhedsbremse og signaturkæde.
- Ingen bred omskrivning af filteret. Udskil kun afgrænsede moduler, når det hjælper de konkrete ændringer.

## Leverancer og rækkefølge

### 1. Reproducer fejlene som regressionstests

Omsæt de isolerede reproduktioner fra gennemgangen til repository-tests med FakeIMAP og rigtig midlertidig SQLite. Kontroller først at de fejler på udgangspunktet. Test både Gigahost-lignende UIDPLUS og MOVE, hvor det er relevant. Ingen kontakt med rigtige mailkonti, push-tjenester eller SMTP.

De tre observerede fejl:

1. `_classify_inbox_uid` returnerer før scanning, når Message-ID mangler.
2. En ny mail med samme Message-ID som en frigivet mail, men anden afsender og andet indhold, bliver ikke scannet.
3. En almindelig tilladelsesregel oprettet under ventetiden forhindrer ikke en allerede planlagt spamflytning.

Accept: regressionsprøverne demonstrerer de oprindelige fejl og består efter rettelserne; almindelig frigivelse og flytning fungerer fortsat.

### 2. Mailidentitet og mails uden Message-ID

- Adskil intern identitet fra det afsenderstyrede Message-ID. Genbrug eksisterende helpers, hvor de er egnede.
- Mails uden ID skal stadig nå normal scoring, antivirus og vedhæftningskontrol.
- En intern fallback-identitet skal være stabil på tværs af genstart og kunne knyttes til den aktuelle mail ved UID/UIDVALIDITY; den må ikke indsættes som et opdigtet headerfelt i brugerens mail.
- Frigivelse og andre vedvarende afgørelser må kun genbruges, når den konkrete mails identitet og indhold er bekræftet. Et Message-ID alene er utilstrækkeligt. Undersøg DMARC-modulets eksisterende ID + SHA-256-princip.
- Kontroller alle relevante genveje: sticky ham, brugerens flytning tilbage, nyhedsbreve, egne kvitteringer/notifikationer, læring, genscanning, UI-handlinger og gendannelse efter afbrudt flytning.
- Lav additive, idempotente databaseskemaændringer og en eksplicit politik for gamle rækker uden fingerprint. Dokumentér konsekvenser ved rollback; påstå ikke bagudkompatibilitet uden prøve.

Acceptprøver:

- Manglende ID scannes og kan flyttes, findes og frigives.
- To forskellige mails uden ID sammenblandes ikke.
- Genbrugt ID med ændret afsender eller body arver ingen frigivelse eller tillid.
- Ægte COPY/MOVE af samme frigivne mail bliver i indbakken og mister ikke brugerens afgørelse.
- Dubletleverancer og nye UID'er efter genstart giver ikke gentagen læring eller utilsigtede flytninger.
- Virus og farlige vedhæftninger omgår ikke kontrollen ved manglende/genbrugt ID.

### 3. Genkontroller beslutningen lige før flytning

- Brug samme beslutningspolitik ved scanning og ved en ventende flytnings udførelse.
- Inddrag aktuelle almindelige tilladelsesregler, blokeringer, Altid igennem, kontogrænse, brugerafgørelser og flag, hvor de ændrer den pågældende beslutning.
- Bevar kontrollen af afsenderens ægthed og truslers forrang; en almindelig tilladelse må ikke frikende en virus.
- Aflyste flytninger skal få korrekt databogføring og forklaring i log/UI uden falske spamflytningstal.
- Kontroller også ventende flytninger fra AI, kampagner og genscanning.

Accept: en ægte tilladt afsender bliver ikke flyttet på baggrund af en gammel beslutning; en forfalsket afsender eller virus beskyttes ikke af tilladelsesreglen. Samtidig læsning, flagning, frigivelse og genstart dækkes.

### 4. Synlig scanningdækning pr. postkasse

- Saml eksisterende tællere for scannet, læst før første behandling, oversize, opgivet scanning og eventuelle resterende undtagelser i en forståelig driftsvisning.
- Adskil et bevidst fravalg fra en fejl og fra en mail, der afventer behandling. Efter ID-rettelsen må manglende ID ikke længere være et generelt fravalg.
- Undgå et misvisende procenttal: alle led skal have samme tidsvindue og veldefinerede nævnere. Vis ukendt/manglende datagrundlag tydeligt.
- Bevar adgangsfiltrering pr. postkasse og eksisterende API-kompatibilitet. Udvid kun eksisterende visninger/API'er, når det er nødvendigt.
- Bevar fokus, åbne dialoger og brugerens valgte filtre under almindelige statusopdateringer.

Accept: syntetiske forløb giver de forventede tal; andre brugeres postkasser lækker ikke gennem tællere, eksport eller UI.

### 5. Måling af træfsikkerhed og kontrolleret evaluering

- Byg videre på eksisterende kalibrering og brugerafgørelser; undgå en parallel træningsmotor.
- Lav en reproducerbar evaluering pr. postkasse med klare spam/ham-labels og et holdout-sæt, der ikke indgår i træningen.
- Vis forvekslingsmatrix, falske positiver, falske negativer og datamængde. Når der er for lidt eller skævt udvalgt data, skal resultatet kaldes et prøveudvalg frem for samlet træfsikkerhed.
- Registrér filterversion og relevante AI-model-/promptindstillinger, så før/efter-resultater kan sammenlignes.
- Hold AI's selvrapporterede confidence adskilt fra målt korrekthed.
- Tilføj neutral prøvefixture og dokumentér lokal import/eksport. Ingen rigtige mails, adresser, emner, secrets eller labels fra familien skal til GitHub.

Accept: samme neutralt mærkede input giver deterministiske måltal; skift i scorer/threshold afspejles korrekt; evaluator lærer intet og ændrer ingen mail.

Vigtig grænse: uden et menneskeligt vurderet mailudvalg fra installationen kan funktionen og regnestykket valideres, men en virkelig forbedring af familiens træfsikkerhed kan ikke måles denne nat. Dette skal stå i leveringsrapporten.

### 6. Reel, isoleret gendannelsesøvelse

- Bevar den nuværende download-, dekrypterings- og checksumkontrol.
- Tilføj en særskilt øvelse, som gendanner til en ny midlertidig app-mappe, åbner/kontrollerer SQLite, indlæser Redis/Bayes og starter de nødvendige dele isoleret.
- Ingen aktive mailkonti og ingen udgående IMAP/SMTP/push i den isolerede prøve. Hemmeligheder må ikke komme i logs eller pakkes som testartefakter.
- Beskyt den eksisterende installation gennem eksplicit destinationskontrol, separate containernavne/mounts, begrænsede ressourcer og sikker oprydning.
- Skeln mellem arkivkontrol og vellykket opstart af en gendannet installation i status og dokumentation.
- Integrér gennem eksisterende CLI/deploy-flow; ændr ikke den kørende servers cronjobs.

Accept: neutral backup kan gendannes og startes; beskadiget arkiv, forkert nøgle, ugyldig DB og ugyldig destination afvises. Der må ikke være sideeffekter på en eksisterende app-mappe eller postkasse. Dokumentér om fuld containerprøve er udført lokalt/CI.

### 7. Afgrænset vedligeholdelse og dokumentation

- Udskil mailidentitet og/eller ren flyttebeslutning, hvis det reducerer kompleksiteten i de konkrete rettelser. Bevar eksisterende import- og servicegrænser, hvor tests/rollback behøver dem.
- Opdatér README, SECURITY, CONFIGURATION, BACKUP, relevante brugervejledninger og CHANGELOG.
- Fjern absolutte garantier om, at trusler aldrig kan komme igennem. Beskriv IMAP-efterbehandling, læste/store mails, antivirusnedetid og bruger-/administratorundtagelser præcist.
- Vælg næste passende ledige version ud fra nyeste remote. Hold versionsfiler, dokumentation, tests og releasepakke enige.

## Validering og udgivelse

1. Kør fokuserede tests efter hvert arbejdsområde og de oprindelige reproduktioner efter rettelserne.
2. Kør hele testsuiten med `ulimit -Sn 65536`. Sidste lokale kørsel fik midlertidige descriptorfejl ved grænsen 1024; alle 67 berørte tests bestod ved separat genkørsel med højere grænse. Undgå at forveksle den miljøfejl med en produktfejl.
3. Kør repositoryets syntaks-/shellcheck, `git diff --check` og relevante container-smokechecks. Installer dokumenterede testafhængigheder i isoleret miljø, hvis de mangler.
4. Gennemgå diffen for hemmeligheder, private data, manglende adgangsfiltrering og utiltænkte ændringer. Ingen debugfiler eller eksterne kontooplysninger i commits.
5. Lav forståelige commits for de sammenhængende ændringer og push til det offentlige repository. Opret en PR med problem, effekt og validering; følg GitHub-skillens publiceringsflow.
6. Vent på GitHub CI for den faktiske ændrede commit og ret fejl. En tidligere grøn version tæller ikke som validering af denne udgivelse.
7. Klargør en installerbar release efter repositoryets eksisterende proces: matchende tag/version, source-tarball, SHA-256 og gyldig signatur med den allerede konfigurerede udgivelsesnøgle. Vis aldrig nøglens indhold. Kontrollér readback/download og signaturverifikation.
8. Angiv klart om udgivelsen er prerelease/beta eller stabil, og hvilken installationsvej den understøtter. En branch eller PR uden de nødvendige signerede artifacts må ikke kaldes installationsklar.
9. Hvis et nødvendigt release-/signerings-/containertrin reelt ikke kan gennemføres, aflever alt færdigt arbejde og angiv det konkrete resterende trin. Udgiv ikke uprøvet kode som stabil for at overholde en tidsfrist.

## Leveringsrapport 23. november

- Hvilke punkter er implementeret, og hvilke har eksplicitte bevisgrænser?
- Commit(s), PR, release-URL, version og CI-resultat.
- Regressionstest, som viste fejl før og består efter.
- Lokal/containerbaseret gendannelses- og installationsprøve, faktisk udført.
- Installationsvej og rollback for ejeren; ingen serverinstallation udført.
- Evt. data, som ejeren senere skal levere lokalt for at måle reel træfsikkerhed.

## Status 23. november

Implementeret: indholdsbundet identitet og regressioner for alle tre fejl; aktuelle almindelige tilladelser og rene scoregrænser ved flytning; administratorens kontoopdelte dækningstal; lokalt første-scannings-prøveudvalg og holdout-regnestykke; reel midlertidig app/Redis-opstart fra krypteret backup; afgrænsede moduler og dokumentation. Version 2.15.0 beta.

Fokuserede tests: 269 og efterfølgende 195 bestået. Endelig samlet kørsel og GitHub CI pågår ved denne commits oprettelse. Containerbygning kræver CI, da lokal Docker-adgang er afvist. Udgivelsen må først publiceres som installationsklar efter grøn CI og verificerede signerede artifacts. Se VALIDATION.md for den afsluttende dokumentation.

Bevisgrænser: ingen live-installation eller rigtige mails; ingen målt forbedring af familiens træfsikkerhed. Evaluering gælder første scanning før AI, så model/prompt-egenskaber kan ikke udledes af den. Gendannelsesøvelsen starter app og Redis, ikke Rspamd/ClamAV eller udbyderadgang; Rspamd dækkes særskilt af container-smokeprøven. Nye schemaer er additive; gamle ubundne frigivelser kan kræve genfrigivelse ved genlevering. Rollback til gammel kode genindfører ID-fejlene.
