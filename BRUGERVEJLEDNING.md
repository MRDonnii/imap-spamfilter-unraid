# Brugervejledning – Spamfilter 2.3

Vejledningen er til dig, der administrerer spamfilteret. Familiemedlemmer har deres egen, kortere vejledning: [FAMILIEGUIDE.md](FAMILIEGUIDE.md). WebUI'en har også en **Hjælp**-side, som du kan sende et link til.

**Hjemme** åbner du `http://192.168.1.10:18080/`. **Udefra** bruger du din HTTPS-adresse (se [CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md)).

---

## Kort fortalt

1. Filteret holder øje med indbakkerne døgnet rundt. Hver ny mail får en score: jo højere, jo mere ligner den spam.
2. Når scoren når grænsen (lige nu 10), flytter filteret mailen til mappen **Spamfilter** i samme postkasse:
   - **Tydelig spam** (5 point eller mere over grænsen) flyttes efter ca. 3 sekunder.
   - **Mails tæt på grænsen** venter et minut, så du kan nå at reagere.
3. **Intet bliver slettet.** Mappen `Spamfilter` tømmer du selv i dit mailprogram, når du vil.
4. Udbydernes eget spamfilter (fx hos Gigahost eller Scannet/SpamExperts) fortsætter som før. Filteret lægger aldrig noget i deres spam-mapper.
5. Fra version 2.2 kender filteret også de typiske phishing-tricks: en afsender, der kalder sig "PostNord" eller "MobilePay" uden at komme fra dem, mærkelige bogstaver i afsendernavnet og lokkende emner om betaling, pakker eller konti. Se **Phishing-regler** nedenfor.
6. Fra version 2.3 ved filteret, hvem du selv skriver med. Svar på dine egne mails og post fra kendte kontakter kommer lettere igennem. Se **Kendte kontakter** nedenfor.
7. Virus, phishing-links og farlige vedhæftninger går aldrig igennem, og kun en administrator kan frigive dem. Mails, filteret var i tvivl om, scannes igen senere. Se **Trusler** og **Genscanning**.

---

## Fanget spam og knapperne

**Fanget spam** viser de mails, filteret har flyttet eller ville have flyttet. Fanerne **Alle / Filter / Udbyder / Overvåg** sorterer efter, hvem der fangede mailen. Hver række viser afsender, emne, score og de vigtigste grunde.

| Knap | Hvad sker der |
| --- | --- |
| **Frigiv** | Mailen flyttes tilbage til indbakken, og filteret lærer, at den ikke er spam. Den flyttes aldrig igen. Afsenderen bliver **ikke** tilladt fremover. En farlig mail (rødt mærke) kan kun frigives af en administrator. Se **Trusler**. |
| **Tillad afsender** | Som Frigiv. Du vælger først, om det gælder **kun adressen** eller **hele domænet** (se **Bloker eller Tillad: adresse eller domæne**). Derefter flyttes post fra afsenderen ikke længere, medmindre den ser forfalsket ud. |
| **Bloker afsender** | Post fra adressen behandles altid som spam. |
| **Flyt til spam** (i Beskeder) | Mailen flyttes fra indbakken til Spamfilter, og filteret lærer, at den er spam. |
| **Lær som legitim / Lær som spam** (på mailens egen side) | Filteret lærer uden at flytte mailen. |

Åbner du en mail, kan du også vælge **Tillad domæne** eller **Bloker domæne**, så reglen gælder hele afsenderdomænet. Freemail-domæner som gmail.com kan ikke blokeres på den måde.

Som administrator kan du sætte flueben ved flere rækker og udføre en handling på dem alle på én gang. Brugere har ikke afkrydsningsfelter. De ser i stedet store knapper og et roligt **Hvorfor?**, der forklarer grunden med almindelige ord.

### Ny og "Markér alle som gennemset"

Mails, der er kommet til siden dit sidste besøg, har et **Ny**-mærke. Menuen viser antallet. Tryk **Markér alle som gennemset**, når du har kigget listen igennem. Det huskes pr. bruger.

---

## Phishing-regler og falske afsendere

Under **Hvorfor?** og på mailens egen side kan du nu se disse grunde:

| Grund | Hvad det betyder |
| --- | --- |
| **Afsendernavnet udgiver sig for at være …** | Navnet nævner et kendt firma (fx PostNord, MobilePay, en bank), men mailen kommer fra et helt andet domæne. Giver 5 point. |
| **Afsendernavnet bruger forvekslelige bogstaver …** | Afsendernavnet bruger græske, kyrilliske eller lignende bogstaver, der ligner almindelige (fx "ΕasyΡark"). Giver 5 point. |
| **Emnet ligner en typisk lokkemail** | Emnet ligner en typisk lokkemail om betaling, pakke, konto eller gevinst. Giver kun 1,5 point alene, for mange ægte firmaer skriver sådan. |
| **Lokkende emne og falsk afsender på én gang** | Begge dele i samme mail. Giver 4 point ekstra. |
| **Emnet udgiver sig for at komme fra et kendt brand og lokker …** | Emnet nævner et kendt firma (fx EasyPark, MobilePay, Tryg, PostNord, en bank) og beder om betalings- eller kontooplysninger, MitID eller din identitet, eller siger, at en betaling er afvist, at der mangler fragt, eller at kontoen er spærret – men mailen kommer ikke fra firmaets eget domæne. Fx "EasyPark: Opdater dine betalingsoplysninger" fra et fremmed domæne. Giver 2,5 point (4 med det lokkende emne), så emnet alene aldrig flytter en mail. Almindelige beskeder som "Din refusion er på vej", "Handling påkrævet" eller "Din pakke kan ikke leveres" tæller ikke her. Et brand i emnet alene giver 0 point. Hotmail.com, outlook.com og lignende gratis mailtjenester tæller aldrig som brandets eget domæne. |
| **Afsenderdomænet bruger et topdomæne, som spammere ofte misbruger** | Afsenderen bruger et topdomæne, som spam-kampagner skifter rundt i (fx .homes, .guru, .xyz). Giver 5 point. .cn og .ru giver 2 point. |
| **Link til en kendt phishing-side** | Et link står på en offentlig liste over phishing-sider (OpenPhish eller PhishTank). |
| **Link til en kendt phishing-side (Phishing Army)** | Linkets domæne står på Phishing Army, en gratis liste over svindel-domæner, som hentes automatisk flere gange i døgnet. Giver 3 point og fjerner ikke point for kendte kontakter. Listen gælder hele domæner og ikke præcise links, så den giver point, men gør ikke mailen til en trussel. Jeres egne domæner og de store link-tjenester (fx bit.ly, HubSpot og Mailchimp) tjekkes ikke mod listen. |
| **Link til jeres egen webshop** | Kun til orientering, giver 0 point. Jeres egne webshops tjekkes ikke mod phishing-listerne. |
| **Jeres egen webshop-platform står fejlagtigt på en domæneliste – udlignet** | Webshop-platformen står på en offentlig domæneliste. Filteret trækker de point fra igen, så længe der ikke er andre tegn på et farligt link. |

### Nye beskyttelser mod phishing (2.13)

Tre ekstra regler, bygget ud fra de phishingmails, der faktisk slap igennem. De står på **Til** og kan slås over på
**Prøv** (kun registrering, ingen point) eller **Fra** under **Indstillinger → Nye beskyttelser**. Kortet viser også,
hvor mange mails hver regel har ramt de sidste 7 dage, og under **Seneste fund** de nyeste mails med link til dem.

| Grund | Hvad det betyder |
| --- | --- |
| **Emnet indeholder "…", hvor nogle bogstaver er russiske eller græske** | Et ord i emnet blander almindelige bogstaver med russiske eller græske, der ser ens ud ("Dоmænеnаvnеt", hvor o, e og a er russiske). Det er et kendt trick for at snyde spamfiltre. Giver 5 point. Et emne helt på russisk eller græsk giver intet. |
| **Afsenderdomænet blev registreret for … dage siden** | Filteret slår afsenderdomænets alder op i det offentlige domæneregister. Under 7 dage giver 4,5 point, under 30 dage 3. Gratis mailadresser og jeres egne domæner slås ikke op, og .dk, .de, .eu m.fl. har ingen offentlig opslagstjeneste og giver intet. |
| **Emnet handler om betaling, konto … og afsenderen har faretegn** | Emnet handler om betaling, konto, abonnement, domæne, MitID, udbetaling eller ophavsret, **og** afsenderen har mindst ét faretegn: gratis mailadresse, misbrugt topdomæne, falske tegn i navnet eller emnet, et domæne under 60 dage, ingen DMARC-godkendelse, eller svar der går til et andet domæne. Giver 4 point, 5 med to faretegn og 6 med tre. En ægte tjeneste, der signerer for sit eget domæne, har ingen faretegn og får intet. |

**Rammer reglerne en ægte afsender?** Det kan ske for en forhandler, et betalingssystem eller en anmeldelsesside, der bruger et brandnavn. Listen over ægte domæner ligger i `rspamd/local.d/maps.d/th_brand_domains.map` i repoet. Tilføj afsenderens domæne (fx `forhandler.dk`) på en ny linje og udrul igen. Frigiv mailen i mellemtiden, eller giv afsenderen en **Tillad**-regel.

---

## Trusler: virus, phishing og farlige vedhæftninger

Nogle mails er farlige, uanset hvem de ser ud til at komme fra. Filteret giver dem en **trusselsklasse** og et rødt mærke:

| Mærke | Hvornår |
| --- | --- |
| **Virus: …** (med virussens navn) | Antivirus fandt en virus. (Antivirus er ikke sat op endnu, så det mærke ses først, når det kommer.) |
| **Phishing-link** | Et link står på en liste over phishing-sider (Spamhaus, OpenPhish, PhishTank m.fl.). |
| **Malware-link** | Et link peger på en side, der spreder skadelig software. |
| **Farlig vedhæftning: …** (med filnavnet) | Mailen har en fil af en type, der kan køre programmer, fx `.exe`, `.js`, `.iso` eller `.lnk`. Filteret kigger også ind i zip-filer (to niveauer) og gennemskuer tricks som `faktura.pdf.exe` og omvendt skrift i filnavnet. |

Hvad sker der med en farlig mail:

- Den flyttes til Spamfilter efter den korte ventetid, **uanset score, Tillad-regler, kendte kontakter og beskyttede adresser**.
- En virus flyttes altid, også hvis afsenderen står som **Altid igennem**.
- Ved phishing-links, malware-links og farlige vedhæftninger slipper en **Altid igennem**-regel kun igennem, hvis mailen har en gyldig DKIM-signatur fra afsenderens domæne. Så kan webshop-platformen ikke blive stoppet af et filnavn, der fejlagtigt ligner noget farligt. Det står på **Drift** som "Farlig mail sluppet igennem (Altid igennem)". Hold øje med den hændelse.
- Filteret lærer **aldrig**, at en farlig mail er legitim, og tillader aldrig afsenderen automatisk.

**Hvorfor kan kun en administrator frigive den?** En phishing-mail er lavet til at narre. Den ligner en rigtig faktura eller pakkebesked, og det er netop dem, man gerne vil frigive. Derfor ser en Bruger "Farlig mail. Kontakt administrator, hvis den skal frigives." i stedet for **Frigiv**. Det gælder også i **Find en mail** og **Fortryd flytninger**, der springer farlige mails over.

Som administrator skal du bekræfte frigivelsen. Siden siger præcis, hvad der er fundet, fx "Denne mail har en farlig vedhæftning: faktura.pdf.exe". Tryk **Frigiv alligevel** (eller sæt flueben ved "Jeg forstår …", hvis JavaScript er slået fra). Mailen lægges i indbakken, men læres **ikke** som legitim.

Trækker nogen en farlig mail ud af Spamfilter i mailprogrammet, bliver den liggende, hvor den blev lagt. Filteret lærer ikke af det og tillader ikke afsenderen.

**Listen over farlige filtyper** ligger under **Indstillinger → Farlige vedhæftninger** (kun administrator). Standardlisten er `exe scr com pif cpl msi msix appx bat cmd ps1 vbs vbe js jse wsf wsh hta lnk jar iso img vhd vhdx xll chm reg`. Du kan rette listen eller trykke **Gendan standardlisten**. En tom liste blokerer ingenting.

**Undtagelser:** Har en fast samarbejdspartner brug for at sende fx `.msi`-filer, så gå til **Regler → Vedhæftninger** og vælg **Tillad farlige vedhæftninger fra denne afsender**. Knappen findes også på mailens egen side. Undtagelsen gælder kun, når afsenderen kan bekræftes med DKIM eller sin egen server, og den gælder aldrig for virus.

Et krypteret arkiv (zip med adgangskode) fra en ukendt afsender giver 4 point, fordi filteret ikke kan se, hvad der er i det.

### Straks-advarsel ved farlige mails

Stopper filteret en virus, et phishing-link, et malware-link eller en farlig vedhæftning, lægger det straks en kort advarsel i postkassens egen indbakke. Så ved den, mailen var til, at der var noget farligt på vej, og at det er taget hånd om.

- Advarslen hedder "⚠️ Spamfilteret har stoppet en farlig mail" og fortæller **hvem den udgav sig for at være fra**, **emnet**, **hvornår** og **hvad der var farligt** – fx "Phishing-link" eller "Farlig vedhæftning: faktura.pdf.exe".
- Der er **ingen links, ingen vedhæftninger og intet indhold** fra den farlige mail. Navne og domæner skrives, så de ikke kan klikkes på (punktummet er byttet ud med et tegn, der ligner).
- Der kommer **højst én advarsel hver halve time** pr. postkasse. Kommer der flere farlige mails på den tid, samles de i den næste advarsel (højst 10 nævnt).
- Advarslen ligger i indbakken, men filteret scanner den aldrig og lærer aldrig af den. En falsk "advarsel", som en svindler sender, bliver derimod scannet som al anden post.
- Advarslen sendes kun, når postkassen står i **Filtrér** – det er kun der, filteret flytter mails.
- Slå den til eller fra under **Konti → postkassen → Straks-advarsel ved farlige mails**. Den er slået til fra start. Tryk **Sådan ser advarslen ud** for at se et eksempel.
- Er **Indstillinger → Mailserver** sat op, og er **Alarmer på mail** slået til, får administratoren også en kort alarm ved virus, phishing, malware-links og farlige vedhæftninger.

**På Oversigt** (og på Brugerens egen forside) står der et rødt kort, de dage hvor der er stoppet noget: "Farlige mails stoppet i dag: 2" med antallet pr. type og hvor mange straks-advarsler, der er sendt. **Se dem** viser kun dagens farlige mails i Fanget spam. En Bruger ser kun sine egne postkasser. Står en postkasse i **Overvåg** eller **Markér**, eller kunne en mail ikke flyttes, står det på kortet som "1 farlig mail ligger stadig i indbakken – slet den uden at åbne den". Den tælles ikke som stoppet.

### Lignende domæner (efterligninger af jeres egne)

Svindlere registrerer domæner, der ligner jeres, fx `pinslkbing.example` (et lille l i stedet for i) eller `pinsikbing-example.com`, og sender falske ordrer, fakturaer eller betalingsbeskeder i jeres navn. Fra 2.3.6 kender filteret jeres **beskyttede domæner** og stopper efterligningerne.

**Hvilke domæner er beskyttet?** Alle postkassernes egne domæner (fx bynet.example og molt.example) og listen under **Indstillinger → Beskyttede domæner**. Standardlisten er pinsikbing.example, gravisk.example og vexar.example. Du kan tilføje fx jeres bank eller e-conomic.dk under **Redigér listen** (højst 50). Postkassernes domæner kan ikke fjernes.

**Hvad tæller som en efterligning?** Filteret laver en fast liste over de typiske tricks i stedet for at gætte: et bogstav for lidt, for meget eller byttet om, en nabotast (også æ, ø og å), tegn der ligner hinanden (0/o, 1/l, rn/m, kyrilliske bogstaver), bindestreger, et andet topdomæne (.com, .net, .shop, .eu …) og jeres domæne gemt i et andet (`pinsikbing.example.svindel.com`). Korte navne (bynet, vexar, molt) får kun tegn-, bindestregs- og topdomænetricks, så almindelige danske navne som itnet.dk ikke rammes.

**Hvad sker der med mailen?**

- Står efterligningen i **afsenderen, svar-til-adressen, konvolut-afsenderen eller DKIM-signaturen**, får mailen mærket **Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example**. Den behandles som en farlig mail: den flyttes uanset score og regler, kun en administrator kan frigive den, postkassen får en Straks-advarsel, og filteret lærer aldrig, at den er legitim.
- Står efterligningen kun i **et link**, giver det 4 point. Mailen flyttes kun, hvis den samlede score når grænsen.

**Hvornår tæller det ikke?**

- Afsenderen har sendt mindst 3 mails, I har beholdt, eller er en kendt kontakt. På delte platforme (fx et `….onmicrosoft.com`-navn) tæller kun netop det navn, aldrig resten af platformen.
- Mailen er underskrevet af det rigtige domæne selv.
- Det er jeres egen mail sendt gennem Google Workspace eller Microsoft 365 uden egen DKIM-nøgle (signaturer som `pinsikbing-example.….gappssmtp.com` eller `bynetexample.onmicrosoft.com`).
- Domænet står på listen **Ikke en efterligning**.

I de tilfælde står der et gråt info-mærke på mailen, fx "… men tæller ikke (kendt afsender)", og det giver 0 point.

**Ikke en efterligning:** Er et domæne helt i orden (fx en leverandør, der hedder noget, der ligner), så tryk **Ikke en efterligning** på mailens side eller i listen under **Indstillinger → Beskyttede domæner**. Det gælder også domænets underdomæner. Du kan fjerne det igen med **Fjern**. Kun administratorer ser knappen.

**Ugentlig kontrol af nyregistreringer:** En gang om ugen, om natten mellem kl. 3 og 5, slår filteret alle varianterne op hos navneserveren (højst 5 opslag i sekundet, et par minutter i alt). Første kontrol er kun en optælling og giver ingen alarm. Derefter giver det en alarm, når en variant **får en mailserver eller en hjemmeside**, den ikke havde før:

- Oversigten viser et rødt kort, "Nyt domæne ligner pinsikbing.example", med knappen **Set**.
- Er **Alarmer på mail** slået til, kommer der en mail. Domænet er skrevet, så det ikke kan klikkes på.
- Den fulde ugerapport har linjen "Nye domæner, der ligner jeres".
- Home Assistant viser det som et problem (se nedenfor).

**Kør kontrol nu** starter kontrollen inden for et minut (højst hvert kvarter). Kunne navneserveren ikke svare, står det på kortet, og filteret prøver igen mellem kl. 3 og 5 om natten. Kortet viser også de registrerede lignende domæner med mærkerne **Mailserver** og **Hjemmeside** og mails fra lignende domæner de sidste 30 dage.

**Hvad gør jeg ved et nyt domæne?** Advar evt. kunder og kolleger, og anmeld domænet til registratoren, hvis det bruges til svindel. Mails derfra bliver allerede stoppet.

---

## Genscanning

Nogle spam-mails er så nye, at sortlisterne ikke kender dem endnu, når de ankommer. Derfor scanner filteret visse mails igen **45 minutter, 4 timer og 24 timer** efter, de kom:

- mails, der lå tæt under grænsen (mindst grænsen − 6), og
- mails med links eller vedhæftninger.

Mails fra kendte kontakter, svar på dine egne mails, tilladte afsendere og mails, du selv har sagt ikke er spam, scannes ikke igen.

Filteret flytter kun ved genscanning, hvis **begge** dele gælder:

1. Mailen er nu over grænsen (eller farlig).
2. Der er kommet en **ny** grund fra en sortliste eller en trusselsliste siden første scanning. Bayes alene er aldrig nok.

Og så kun, hvis mailen stadig ligger i indbakken, er **ulæst**, ikke har et flag og ikke er rørt af dig. En **læst** mail flyttes kun, hvis den er farlig. Ellers noteres det bare som "ville være flyttet".

Mails, der er flyttet sådan, får mærket **Fanget ved genscanning**. På mailens side står, hvad der var nyt, fx "Ny viden efter 3 timer: Linkdomæne på Spamhaus' spamliste". I den daglige kvittering og ugerapporten står de som **Flyttet efterfølgende**.

Genscanningen er slået til som standard. Den kan slås fra pr. konto i `accounts.yml` med `zap: false`.

---

## Sen scanning

Normalt scanner filteret en mail få sekunder efter, den er kommet. Efter et nedbrud, en opdatering eller når en gammel mail lægges i indbakken, kan der gå timer. Så længe efter kan afsenderens SPF og DMARC ikke kontrolleres pålideligt: signaturer udløber, og afsenderens servere skifter.

Er mailen mere end 6 timer gammel, gør filteret derfor sådan:

- SPF, DMARC og de tilhørende lister over kendte afsendere slås fra for netop den scanning.
- I stedet bruges udbyderens egen vurdering fra modtagelsen. Bekræftede udbyderen afsenderen, giver det 1 point i fradrag. Afviste den afsenderen, giver det 2 point.
- Mailen får mærket **Scannet sent – udbyderens godkendelse brugt** på sin egen side.

**Tilladelser ved sen scanning:** En almindelig **Tillad**-regel gælder kun, hvis noget beviser, at mailen virkelig kommer fra afsenderen. Det kan være udbyderens godkendelse ved modtagelsen eller en gyldig signatur fra afsenderens domæne. Fejlede udbyderens SPF- eller DMARC-tjek, eller findes der intet bevis, vurderes mailen på sin score som alle andre. Så kan en forfalsket afsender ikke snige sig igennem på en tilladelse. **Altid igennem** virker som før, når mailen kan bekræftes.

Grænsen på 6 timer kan ændres pr. konto i `accounts.yml` med `aged_scan_hours` (0 slår sen scanning fra).

---

## Tjek disse

Øverst på Fanget spam samler **Tjek disse** de få fangede mails, der måske ikke er spam:

- mails med en score tæt over grænsen (under grænsen + 3)
- mails fra afsendere, du tidligere har fået legitim post fra
- mails fra dit eget domæne
- mails til en beskyttet adresse

Hvert kort viser én linje med grunden og to store knapper:

- **Frigiv** lægger mailen tilbage i indbakken.
- **Det er spam** lader mailen blive i Spamfilter og lærer filteret, at den er spam.

Begge dele fjerner kortet. Som administrator står der "Lige over grænsen", når scoren højst er 1,5 over grænsen. En Bruger ser bare "Tæt på grænsen – kig en ekstra gang".

Oversigten viser også, hvor mange der venter i Tjek disse.

Farlige mails og mails, der er fanget ved genscanning, vises aldrig under Tjek disse.

---

## Træk mails ind og ud af Spamfilter i mailprogrammet

Det virker i alle mailprogrammer: iPhone Mail, Outlook, Gmail-appen med IMAP, Thunderbird osv. Du behøver ikke WebUI'en.

**Spam i indbakken?** Træk mailen over i mappen **Spamfilter**:

- Filteret lærer, at den slags er spam.
- Var afsenderen tidligere blevet tilladt automatisk (se nedenfor), fjernes den automatiske tilladelse igen. Regler, du selv har lavet, bliver ikke rørt, og der oprettes ingen blokering.

**Rigtig mail i Spamfilter?** Træk den tilbage til **Indbakken**:

- Filteret lærer, at den ikke er spam, og flytter aldrig den mail igen.
- **Afsenderen bliver automatisk tilladt** for den postkasse (kun den præcise adresse). Den næste mail fra dem kommer altså også igennem.
- Er afsenderen sat til **Altid igennem**, laves der ingen ekstra regel. Den regel gælder allerede.

Den automatiske tilladelse styres pr. konto under **Konti → konto → Lær af mailprogrammet** (kontakten "Tillad afsenderen automatisk", slået til som standard). Du kan altid fjerne en automatisk tilladelse under **Regler**.

Godt at vide:

- iPhone Mail sætter selv mærket "ikke spam" på næsten alle mails. Det ignorerer filteret. Det er kun en rigtig flytning (eller et flag), der tæller som din beslutning.
- **Frigiv** i WebUI'en giver ingen automatisk tilladelse. Brug **Tillad afsender**, hvis du også vil tillade afsenderen fremover.
- Trækker du en mail ud af udbyderens egen spam-mappe, respekterer filteret det og flytter den ikke tilbage.
- Trækker du en **farlig** mail ud af Spamfilter, bliver den liggende, men filteret lærer ikke af det og tillader ikke afsenderen. Se **Trusler**.
- Trækker du mail fra en kendt kontakt ind i Spamfilter, fjernes afsenderen fra Kendte kontakter.

---

## Find en mail

Mangler du en mail, så gå til **Find en mail**:

1. Vælg postkasse, skriv afsenderens navn, adresse eller et ord fra emnet, og vælg en periode (standard 30 dage).
2. Først ser du, hvad filteret ved om mailen fra sin egen database.
3. Tryk **Søg også i postkassen** for at lede direkte i postkassen. Søgningen er skrivebeskyttet og ændrer intet. Den kigger i:
   - mappen Spamfilter
   - udbyderens spam-mapper (også "Uønsket e-mail" o.l.)
   - papirkurven
   - Indbakken, hvis man må se Beskeder

   Resultaterne grupperes pr. mappe med en forklaring på dansk.
4. Tryk **Flyt til indbakken** ud for den rigtige mail. Præcis den mail flyttes hjem, og filteret flytter den aldrig igen.

Finder søgningen intet, viser siden tips. Går posten til domænet stadig gennem SpamExperts først (Mailsikkerhed ser SpamExperts i MX), og stopper SpamExperts en mail, når den aldrig frem til postkassen. Så viser siden et tip om at kigge i SpamExperts' karantæne eller bede Scannet om at frigive den. Når MX ikke længere peger på SpamExperts, vises tippet ikke.

Man kan søge i postkassen én gang hvert 10. sekund pr. postkasse, så udbyderen ikke bliver belastet.

---

## Fortryd flytninger

Har filteret flyttet rigtige mails i en periode, fx efter en ændring af følsomheden, kan du lægge dem tilbage på én gang. Du finder **Fortryd flytninger** som en knap på Fanget spam og i banneret "Flytning på pause". Brugere med frigiv-adgang har knappen på deres forside.

1. **Vælg postkasse og periode:** Seneste time, I dag, I går eller Vælg selv. Perioden kan højst være 92 dage.
2. **Se efter:** Du ser, hvor mange mails det drejer sig om, og et udsnit af dem.
3. Sæt evt. flueben ved **Lær at disse ikke er spam**. Uden flueben lægges mailene bare tilbage og flyttes aldrig igen. Filteret lærer ikke noget af dem. Det er det sikre valg, når mange mails var en blanding af spam og ikke-spam.
4. Start. Fremdriften vises løbende (10 mails i sekundet). Du kan trykke **Stop**, og de mails, der allerede er lagt tilbage, bliver i indbakken.

Kun mails, som filteret selv har flyttet, og som stadig ligger i Spamfilter, bliver lagt tilbage. Højst 2.000 ad gangen. Mails, du selv har ændret i mellemtiden, springes over. Farlige mails springes altid over og skal frigives én ad gangen af en administrator.

---

## Tillad, Bloker og Altid igennem (Regler)

Under **Regler** ser du alle regler og kan oprette nye:

- **Tillad:** post fra adressen eller domænet (fx `@firma.dk`) flyttes aldrig til spam. Undtagelsen er mails, der ser forfalskede ud (fejl i SPF, DMARC eller udbyderens egen spam-markering). De vurderes på score.
- **Bloker:** posten behandles altid som spam.
- Passer flere regler på samme afsender, vinder den mest præcise:
  1. en regel for postkassen før en regel for alle konti
  2. en adresse før et domæne
  3. Bloker før Tillad, hvis de to regler er lige præcise
- **Altid igennem** (kun administrator, kun for Tillad): flyttes aldrig, uanset score, så længe mailen kan bekræftes som ægte fra domænet (DKIM-signatur eller domænets egne servere). Bruges til helt afgørende afsendere. `@vexar.example` har denne regel for alle konti, så ordrer, fakturaer og kundehenvendelser altid når frem. Forfalskede mails, der kun låner navnet, behandles som en almindelig tilladelse.
- **Gælder for:** én postkasse eller alle konti. En Bruger med regel-adgang kan kun lave regler for sine egne postkasser, aldrig for alle og aldrig Altid igennem. Administratorens fælles regler kan Brugeren se, men ikke ændre.
- Med **Normal tilladelse** gør du en Altid igennem-regel til en almindelig Tillad-regel igen. **Skift til Bloker** vender en Tillad-regel.
- **Importér flere på én gang** tager en liste af adresser eller domæner. Linjer med jeres egne adresser, domæner eller webshop springes over (se nedenfor).

### Bloker eller Tillad: adresse eller domæne

Alle knapper, der hedder **Bloker** eller **Tillad**, åbner det samme lille vindue: i Fanget spam, Beskeder, på mailens egen side, i **Tjek disse**, under **Kendte kontakter** og under **Regler → Ny regel**. Du vælger mellem to ting:

- **Kun denne adresse** – fx `tilbud@firma.dk`. Kun mails fra præcis den afsender bliver blokeret (eller flyttes ikke til spam). Andre fra `firma.dk` vurderes som normalt.
- **Hele domænet** – alle mails fra `firma.dk` og underdomæner som `nyhed.firma.dk`.

Under **Regler → Ny regel** indsætter du bare hele adressen, så viser siden de to valg med det samme.

Vinduet passer på dig:

- **Kun denne adresse** er valgt på forhånd. Er adressen låst, fordi der allerede er en regel for den, er **ingenting** valgt – så kan et hurtigt tryk aldrig komme til at blokere et helt domæne. Knappen virker først, når du selv har valgt.
- Findes der allerede en regel, ser du den øverst med en knap: **Skift til Bloker** eller **Skift til Tillad**. Den bevarer reglens note. Der laves aldrig en dobbelt regel.
- **Hele domænet** kan ikke vælges for gratis mailtjenester som gmail.com, hotmail.com og outlook.dk. Så ville du ramme alle, der bruger tjenesten.
- **Jeres egne postkasser, jeres egne domæner og webshoppen** (bl.a. `vexar.example`, `pinsikbing.example` og `gravisk.example`) kan aldrig blokeres – heller ikke via import, Fortryd eller et gammelt faneblad. Mail fra webshoppen skal altid kunne komme ind. Får du en falsk mail, der udgiver sig for at komme fra jer selv eller fra webshoppen, så tryk **Lær som spam** (eller **Det er spam**) på selve mailen i stedet. Filteret fanger den slags alligevel.
- En afsender, en administrator har sat til **Altid igennem**, kan ikke blokeres herfra.
- En almindelig **Tillad** er ikke det samme som **Altid igennem**: ser en tilladt mail forfalsket ud, bliver den stadig vurderet som al anden post.

Efter et tryk står der fx "tilbud@firma.dk er nu blokeret på Ole", og **Fortryd** sætter alt tilbage.

---

## Kendte kontakter

Har du selv skrevet til nogen, er deres svar næsten aldrig spam. Fra 2.3 læser filteret derfor dine **sendte mails** og husker, hvem du har skrevet til.

**Det læser filteret:** kun modtageradresserne og Message-ID i dine Sendt-mapper, aldrig indholdet. Adresserne gemmes ikke i klartekst, men som en nøgle (hash), så databasen ikke kan bruges som adressebog. Sendt-mapperne findes selv, også når de hedder noget forskelligt hos Gigahost og Scannet.

**Første gennemgang:** Efter opdateringen gennemgår filteret hver postkasses sendte mails i små bidder, mens det scanner ny post som normalt. Det tager typisk nogle minutter pr. postkasse. **Kendte kontakter bruges først, når den første gennemgang er færdig.** Derefter tjekkes Sendt hvert 15. minut.

Du finder det under **Regler → Kendte kontakter** (en Bruger uden regel-adgang har punktet **Kendte kontakter** i menuen):

- **Statuskortet** viser fx "Lært fra dine sendte mails: 518 kontakter · 1.666 sendte mails · opdateret i dag 14:05". Under den første gennemgang står "Sendte mails gennemgået 980 / 2.400".
- **Opdater nu** henter nye sendte mails med det samme.
- **Stol på folk, jeg har skrevet til** slår funktionen til og fra for postkassen (kræver regel-adgang).
- Fanerne **Personer** og **Organisationer** viser kontakterne og de firmaer, du skriver med. Filtrene viser aktive og fjernede kontakter.
- **Søg:** skriv en adresse, så svarer siden fx "Ja, du har skrevet til … 7 gange, senest marts 2026" eller "Nej, du har ikke skrevet til … fra denne postkasse".
- **Fjern** tager en kontakt af listen (med **Fortryd**). **Gendan** sætter den på igen. En fjernet kontakt giver heller ikke fradrag som **Fast afsender** eller **Kendt organisation**, og den forbliver fjernet, også når Sendt gennemgås igen.
- Adresser vises kun fuldt ud, hvis personen også har skrevet til dig. Ellers står de forkortet med en lille lås, fx "a…@kunde.dk".

**Sådan virker det på scoren:**

| Mærke på mailen | Hvornår | Fradrag |
| --- | --- | --- |
| **Kendt kontakt – du har skrevet til afsenderen 7 gange** | Du har skrevet til afsenderen mindst 2 gange, eller inden for 2 år | −4 |
| | Kun én gang for 2–5 år siden | −3 |
| | Kun én gang for mere end 5 år siden | −2 |
| **Kendt kontakt – en kollega har skrevet til afsenderen** | En anden postkasse i samme gruppe (fx alle molt.example-postkasser) har skrevet til afsenderen | −3 |
| **Kendt organisation – du har skrevet til andre her** | Du har skrevet til mindst to andre på samme firmadomæne (ikke gmail.com o.l.), og mailen har en gyldig DKIM-signatur | −1 |

Nyhedsbreve og lister får højst −2.

**Det giver aldrig fradrag:**

- når afsenderen ikke kan bekræftes. Mailen skal have en gyldig DKIM-signatur fra afsenderens domæne eller bestå DMARC. Videresendt post og post fra jeres egne domæner kræver DKIM.
- når mailen er farlig (se **Trusler**), har et falsk afsendernavn, et link på en sortliste eller forfalskningstegn
- når afsenderen er blokeret. En blokering vinder altid.

Alle fradrag for tillid (kontakter, svar, fast afsender og nyhedsbreve) kan tilsammen højst blive −6. Kun det stærkeste kontaktsignal tæller.

**Når en kendt kontakt sender spam:** Trykker du **Det er spam** (eller trækker mailen ind i Spamfilter), fjernes afsenderen fra Kendte kontakter med status "Fjernet efter spam". I WebUI'en får du en besked med knappen **Behold som kontakt**, hvis det var en fejl. Det samme punkt står på Oversigten. Mærkerne på mailen bliver grå ("Var kendt kontakt – du har markeret mailen som spam").

**Oversigten** har en stribe, der viser, hvor mange mails kendte kontakter har beskyttet, hvor mange der er flyttet efterfølgende, og hvor mange trusler der er stoppet. Den følger perioden 24 t / 7 dage.

Brugere ser mærkerne uden tal, fx bare "Kendt kontakt". Kun administratorer ser antal og datoer.

---

## Svar på din mail

Når nogen svarer på en mail, du har sendt, kan filteret se det på mailens referencer. Det er det stærkeste tegn på, at mailen er ægte:

| Mærke | Hvornår | Fradrag |
| --- | --- | --- |
| **Svar på din mail fra 12. okt.** | Mailen er et svar på din mail, og afsenderen hører til samme domæne som en, du skrev til | −5 |
| **Svar på din mail … (ny deltager i tråden)** | Svaret kommer fra en ny person i samme tråd | −2 |
| **Ligner et svar, men afsenderen kunne ikke bekræftes** (grå) | Referencen passer, men afsenderen kunne ikke bekræftes | 0 |

Er et svar lige ved at blive flyttet, tjekker filteret Sendt igen først. Så kommer et svar på en mail, du sendte for et øjeblik siden, også igennem. Svar på dine egne mails tæller, selv om du har fjernet afsenderen fra Kendte kontakter.

Svarer du selv på en mail, filteret har fanget som spam, bliver modtageren ikke en kendt kontakt, og tråden tæller ikke.

---

## Fast afsender og første mail

Filteret husker også, hvem der skriver til **dig**, og hvordan det gik:

- **Fast afsender – 14 mails siden 2021** (blå, −2): afsenderen har sendt mindst 3 mails, du har beholdt, over mindst 30 dage, og mailen kommer fra den samme afsenderopsætning som før (samme DKIM-domæne, eller samme server-netværk). En forfalskning fra et andet netværk får ikke fradraget. Én spam-markering fra dig stopper det igen.
- **Første mail fra denne afsender** (gul, +1): filteret har aldrig set afsenderen eller domænet før. Det er kun et lille tillæg, men det hjælper mod nye svindlere. Det gives aldrig til jeres egne domæner, til kendte kontakter eller til afsendere med en Tillad-regel.

Filteret har lært historikken fra dine eksisterende mapper (indbakke og egne mapper, aldrig Sendt, Spamfilter, spam-mapper, papirkurv og kladder) ved første gennemgang.

---

## Beskyttede adresser

Kundepost må aldrig forsvinde. Under **Konti → konto → Beskyttede adresser** skriver du de kontaktadresser, der modtager kundepost, én pr. linje. For Ole (molt) og Ole (bynet) er det `info@gravisk.example` og `info@pinsikbing.example`.

Mails til disse adresser bruger en langt højere grænse, **Grænse for beskyttede adresser** (anbefalet 18), før de flyttes. Det gælder, uanset om adressen står i Til, Cc eller i videresendelsen.

Under samme konto ligger **Betroede videresendere**. Det er de servere, der sender post videre til dig, som webshop-platformens mailserver `mail.vexar.example`. Filteret kigger forbi dem og vurderer den rigtige afsender. Standardlisten er allerede med, og du kan tilføje flere.

---

## Brugere og adgang

Under **Administration → Brugere** opretter og styrer du, hvem der kan logge ind.

**Opret bruger**, eller tryk **Opret bruger til denne postkasse** på et konto-kort under Konti:

1. **Navn** og **adgangskode** to gange (mindst 12 tegn). **Generér stærk kode** laver en, du kan give videre.
2. **Rolle:**
   - **Administrator** ser og må alt.
   - **Bruger** ser kun de valgte postkasser.
3. **Postkasser:** sæt flueben ved de postkasser, Brugeren må se.
4. **Tilladelser** for en Bruger:
   - **Frigive og flytte post:** Frigiv, Flyt til spam og Lær, samt adgang til Find en mail og Fortryd flytninger.
   - **Tillade og blokere afsendere:** regler for egne postkasser.
   - **Se alle beskeder:** siden Beskeder med al scannet post. Uden den ser Brugeren kun sin fangede spam.
5. **Kræv to-trins-login**, hvis Brugeren skal kunne logge ind udefra. Kravet er opfyldt med enten appen eller kode på mail.
6. **Må logge ind:** **Overalt** eller **Kun lokalt (hjemmenetværket)**. Med Kun lokalt kan Brugeren slet ikke logge ind udefra, heller ikke med en gemt "Husk mig"-session. Kortet får mærket **Kun lokalt**.

En opsummering, fx "Kan se Inge · Må frigive post", viser resultatet, før du gemmer.

Hvert brugerkort har:

- **Rediger**
- **Skift kode**
- **Log ud overalt**, som afslutter alle sessioner, også dem med Husk mig
- **Nulstil** to-trins-login, hvis telefonen er væk
- **Slet bruger**, hvor du skal skrive navnet for at bekræfte

Den sidste administrator kan ikke slettes eller gøres til Bruger.

**Kun lokalt** i praksis:

- Hjemme betyder: forbindelsen kommer direkte fra hjemmenetværket (10.x, 192.168.x osv.), ikke gennem Cloudflare Tunnel eller en anden proxy. Alt gennem tunnellen tæller som udefra.
- Et forsøg udefra får den samme fejlside som en forkert adgangskode og tæller med i spærringen. Det står i revisionsloggen som "Login udefra afvist (kun lokalt)".
- Du kan ikke sætte dig selv til Kun lokalt, mens du selv er logget ind udefra. Er alle administratorer sat til Kun lokalt, viser siden en advarsel: "Ingen administrator kan logge ind udefra".
- Under **Indstillinger → Adgang udefra** viser rækken **Hjemmenetværk**, om din nuværende forbindelse tæller som hjemme.
- Nødadgang: `sfctl login-scope NAVN overalt` (se **Nødadgang via sfctl**).

### Se som bruger

Tryk **Se som bruger** på en Brugers kort. Så ser du WebUI'en præcis som Brugeren: deres postkasser, deres menu og deres knapper. Øverst står "Forhåndsvisning som <navn> – ingen handlinger mulige":

- Alle knapper og felter er slået fra, og intet gemmes for Brugeren, heller ikke Ny-mærkerne.
- Du kan klikke rundt mellem siderne inde i forhåndsvisningen.
- Hver forhåndsvisning skrives i revisionsloggen.
- En anden administrator kan ikke forhåndsvises.

---

## Den simple brugerprofil

En Bruger møder en enkel side uden tekniske ord:

- **Min spam** (forsiden): en kort opsummering pr. postkasse, fx "inge@molt.example · 10 mails fanget de sidste 7 dage", højst tre **Tjek disse** og listen over fanget spam fra de sidste 30 dage. Ingen scorer, ingen nøgletal.
- **Hvorfor?** folder grunden ud med almindelige ord, fx "Afsenderen er blokeret" eller "Din udbyders eget spamfilter lagde den i spam".
- **Store knapper** efter tilladelse: Frigiv, Tillad og Bloker. På mobilen står de på én række.
- **Find en mail**, **Beskeder** og **Regler** vises kun, hvis Brugeren har adgang. Uden "Se alle beskeder" søger Find en mail kun i spam-mapperne, aldrig i indbakken eller papirkurven.
- **Hjælp**, tilpasset Brugerens rettigheder.
- **Kendte kontakter:** hvem filteret ved, at Brugeren skriver med, og søgning på en adresse.
- **Min konto:** skift adgangskode, to-trins-login (app eller kode på mail), Log ud overalt, tema og vejledning til at lægge siden på hjemmeskærmen.

Har Brugeren kun én postkasse, er der ingen kontovælger.

---

## To-trins-login

To-trins-login betyder, at man ud over adgangskoden skal indtaste en 6-cifret kode. Koden kommer enten fra en **app** på telefonen eller som en **kode på mail** (se næste afsnit). Det anbefales for alle administratorer og for alle, der logger ind udefra. **Administratorer bør bruge appen.**

**Slå appen til** under **Min konto → To-trins-login** (er en mailserver sat op, vælger du først **App** eller **Kode på mail**):

1. Scan QR-koden med en godkendelses-app, fx Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden eller iPhonens indbyggede **Adgangskoder** (iOS 18+). På telefonen kan du trykke på knappen, der åbner appen direkte, eller skrive nøglen af.
2. Skriv den 6-cifrede kode for at bekræfte.
3. Du får **8 genoprettelseskoder**. De vises kun én gang, så gem dem et sikkert sted, fx i din adgangskode-app eller på papir. Hver kode virker én gang, hvis telefonen er væk.

Senere kan du lave nye genoprettelseskoder (de gamle holder op med at virke) eller slå to-trins-login fra igen. Det sidste kan du ikke, hvis administratoren har krævet det.

**Bekræft, at det er dig:** Har du allerede to-trins-login, og vil du tilføje den anden metode eller skifte mailadresse, beder siden først om en kode fra det, du allerede bruger: appen, en kode til din nuværende mailadresse eller en genoprettelseskode. Bekræftelsen gælder i 10 minutter. Har du lige logget ind med to-trins-login, tæller det som bekræftelse i 10 minutter. Det forhindrer, at en, der har fået fat i en åben session, kan skifte din metode ud.

Hver gang to-trins-login eller adgangskoden ændres (også af en administrator eller med `sfctl`), får brugeren en sikkerhedsmail, hvis en mailserver er sat op.

**Kræv det for andre:** Under Brugere kan du sætte **Kræv to-trins-login**. Brugeren skal så sætte appen op, før spamfilteret kan bruges.

**Mistet telefon:**

- Log ind med en genoprettelseskode.
- Har du også kode på mail slået til, så brug den.
- Eller lad en administrator trykke **Nulstil** under Brugere. Det slår både app og kode på mail fra.
- Er det den eneste administrator, der er låst ude, så kør på serveren:

  ```sh
  docker exec -it spamfilter sfctl disable-2fa <brugernavn>
  ```

---

## To-trins-login med kode på mail

Er en mailserver sat op (se **Mailserver og notifikationer**), kan to-trins-login bruge en kode på mail i stedet for, eller ud over, appen.

**Slå det til** under **Min konto → To-trins-login → Kode på mail**:

1. Skriv den mailadresse, koden skal sendes til.
2. Tryk **Send kode**, og skriv den 6-cifrede kode fra mailen. Så er adressen bekræftet.
3. Er det din første metode, får du 8 genoprettelseskoder. Har du allerede appen, beholder du dine koder.

**Ved login:** Efter adgangskoden sendes en kode automatisk til din adresse, fx "Send kode til o…@bynet.example". Koden:

- består af 6 cifre og gælder i **10 minutter**
- kan kun bruges én gang, og kun den nyeste kode virker
- tåler 5 forkerte forsøg
- kan sendes højst 3 gange pr. 15 minutter, med mindst 1 minut imellem. Knappen **Send en ny kode** viser, hvornår du kan få en ny.

Har du både app og mail, kan du bruge den, du har ved hånden.

**App eller mail?** Appen er sikrest. En kode på mail er kun så sikker som mailkontoen: får nogen fat i din mail, kan de også få koden. Brug derfor appen til administratorer, og mail som alternativ eller reserve for familien.

**Fjern én metode** under Min konto. Genoprettelseskoderne bliver, så længe den anden metode er slået til.

Er mailserveren nede, kan man ikke få en kode på mail. Brug så appen, en genoprettelseskode, eller lad en administrator nulstille to-trins-login.

---

## Passkeys (2.6)

En passkey logger dig ind med **Face ID, fingeraftryk eller telefonens skærmlås** i stedet for adgangskode og kode. Den kan ikke phishes: den virker kun på spamfilterets egen adresse.

- **Kun via https:** Passkeys virker via den eksterne adresse (fx `https://spamfilter.example.org`). På hjemmenetværkets adresse (`http://192.168.1.10:18080`) vises knappen ikke, og du logger ind med adgangskode som før.
- **Tilføj** under **Min konto → Passkeys → Tilføj passkey**. Du bekræfter først, at det er dig: med en kode fra dit to-trins-login, eller med din adgangskode, hvis du ikke har to-trins-login. Giv passkeyen et navn, fx "Annas iPhone". Du kan have op til 10.
- **Log ind:** Tryk **Log ind med passkey** på login-siden. Det tæller som både adgangskode og kode. **Husk mig** og **Kun lokalt** gælder som ved et almindeligt login.
- **Fjern** en passkey under Min konto (kræver også bekræftelse). Slet den derefter også på enheden.
- **Mistet telefon:** Log ind med adgangskode (og kode) og fjern passkeyen, eller kør på serveren `docker exec -it spamfilter sfctl passkeys-reset <brugernavn>`.

## Besked ved login (2.6)

- **Ny enhed:** Logger du ind fra en browser eller enhed, spamfilteret ikke har set før, får du en mail (til din bekræftede mailadresse fra to-trins-login) og en besked på telefonen: "Nyt login på din konto: … Var det ikke dig? Skift adgangskode og log ud overalt." Administratorerne under **Notifikationer → Sikkerhed** får en kopi. Første login efter opdateringen giver ingen besked.
- **Seneste login** står under **Min konto → Logget ind** sammen med **Log ud overalt**.
- **Forkerte forsøg:** Efter 5 forkerte forsøg på 15 minutter for ét brugernavn eller fra én IP-adresse får administratorerne én besked (mail under **Sikkerhed** og besked på telefonen under **Problemer med filteret**). Højst én gang i timen pr. brugernavn og IP.

---

## Husk mig

Sæt flueben ved **Husk mig på denne enhed i 30 dage** på login-siden:

| | Uden Husk mig | Med Husk mig |
| --- | --- | --- |
| Maksimal varighed | 12 timer | 30 dage |
| Logges ud efter inaktivitet | 2 timer | 7 dage |

Med to-trins-login bliver du spurgt om koden én gang. Derefter husker sessionen det i hele perioden. **Log ud overalt** og skift af adgangskode afslutter også de huskede sessioner.

---

## Web-app på mobilen

Spamfilteret kan ligge på hjemmeskærmen som en app uden adresselinje. Vejledningen står også under **Min konto**.

**iPhone (Safari):**

1. Åbn spamfilteret i Safari.
2. Tryk på **Del** nederst på skærmen.
3. Vælg **Føj til hjemmeskærm**, og tryk **Tilføj**.

Det virker også på den lokale adresse.

**Android (Chrome):**

1. Åbn spamfilteret i Chrome på **HTTPS-adressen** (Cloudflare Tunnel).
2. Tryk på menuen øverst til højre.
3. Vælg **Installer app** (eller **Føj til startskærm**), og bekræft.

En fuld installation på Android kræver HTTPS. På den lokale `http://`-adresse bliver det kun et bogmærke.

Appen gemmer aldrig dine mails eller sider på telefonen. Er serveren ikke til at nå, viser den bare en "Du er offline"-side.

---

## Beskeder på telefonen

Spamfilteret kan give dig en besked på telefonen (2.5.0) – fx "Farlig mail stoppet" – også når appen er lukket. Det slås til pr. enhed under **Min konto → Beskeder på denne enhed**.

**iPhone og iPad (iOS 16.4 eller nyere):**

1. Åbn spamfilteret i **Safari** på den sikre adresse **https://spamfilter.example.org** – ikke den lokale `http://192.168.1.10:18080`.
2. Tryk på **Del** og vælg **Føj til hjemmeskærm** (se [Web-app på mobilen](#web-app-på-mobilen)). Beskeder virker kun i appen på hjemmeskærmen, ikke i Safari.
3. Åbn spamfilteret fra **ikonet på hjemmeskærmen**, og log ind.
4. Gå til **Min konto → Beskeder på denne enhed**, og tryk **Slå beskeder til**.
5. Tryk **Tillad**, når iPhonen spørger.
6. Tryk **Send testbesked**. Efter et par sekunder kommer beskeden.

**Android:** Åbn den sikre adresse i Chrome, installér appen (eller brug Chrome direkte), og følg trin 4–6.

**Hvad du får besked om** (vælges pr. enhed):

| Valg | Standard | Hvornår |
| --- | --- | --- |
| **Farlige mails stoppet** | til | Filteret har lagt en farlig mail (virus, phishing, farlig vedhæftning) i Spamfilter-mappen i en af dine postkasser |
| **Nye mails under Tjek disse** | fra | Nye mails, der måske ikke er spam. Højst én besked pr. halve time pr. postkasse |
| **Problemer med filteret** | til | Kun administratorer: login afvist, sikkerhedsbremse, sikkerhedstilstand, og når filteret kører igen efter et stop |

Godt at vide:

- Beskeden siger kun **hvor mange** mails det drejer sig om og **i hvilken postkasse** – aldrig afsender, emne eller indhold. Tryk på den for at åbne Fanget spam.
- Du får kun beskeder om dine egne postkasser.
- Højst én besked af hver slags pr. 10 minutter – det, der kommer imens, samles i den næste – og højst 20 beskeder om dagen.
- Listen **Dine enheder** viser alle dine telefoner med beskeder. **Fjern** stopper beskederne til en enhed, du ikke har mere. Du kan have op til 10 enheder.
- **Slå fra på denne enhed** stopper beskederne her. "Log ud overalt" stopper dem ikke – slet enheden på listen, hvis telefonen er væk.
- Står der **Blokeret**, har du sagt nej på telefonen: Indstillinger → Notifikationer → Spamfilter → Tillad notifikationer.
- Mailbeskederne til administratoren (Mailserver og notifikationer) virker som før – beskeder på telefonen er et ekstra valg.

---

## Følsomhed og forslag

**Følsomhed** er grænsen for, hvornår en mail regnes som spam. Den indstilles pr. konto under **Konti → konto → Følsomhed** (5–15):

- **Lav grænse** giver et strengere filter.
- **Høj grænse** lader flere mails slippe igennem.

**Forslag til følsomhed** på samme side regner et forslag ud fra de sidste 14 dage, altså hvad du har frigivet, og hvad du selv har flyttet til spam:

- Forslaget ligger altid over enhver mail, du har frigivet i perioden.
- Grænsen sænkes kun, hvis mindst to mails er sluppet igennem, og aldrig med mere end 2 point ad gangen.
- **Brug forslaget** skifter grænsen, når du har bekræftet. Du kan altid ændre den igen.
- Er der for lidt data, siger kortet "Ingen forslag lige nu".
- **Afvis** skjuler forslaget, både her og på Oversigt. Det kommer først igen, hvis filteret når frem til et andet forslag.

**Flyttetider** på samme side styrer, hvor hurtigt spam flyttes:

- Tydelig spam flyttes efter få sekunder. Standard er score over grænsen + 5, flyttet efter 3 sekunder.
- Mails tæt på grænsen venter 60 sekunder.

---

## Reparér Bayes og lærelister

Filterets hukommelse (Bayes) har tidligere lært noget phishing som god post, fordi hele indbakker blev lært som legitime. Under **Træning → Reparér Bayes** kan du rette det:

- Øverst står forholdet mellem lært spam og lært legitim post. Målet er mindst 1 spam pr. 2 legitime.
- Listen viser mails, som filteret har lært som legitime, men som der er tegn på er spam. Grunden står ved hver mail:
  - en phishing-regel ramte;
  - du har selv markeret mailen som spam;
  - udbyderen markerede den som spam.
- Mails med en phishing-regel eller din egen markering er sat flueben ved på forhånd. Mails, som kun udbyderen har markeret, skal du selv vælge.
- **Lær de valgte som spam** lægger mailene i en **læreliste**. Den kører i baggrunden og læser kun mailene. Intet flyttes eller slettes.
- Listen kan vise flere mails, når du har kørt en kalibrering af indbakken med de nye regler.

Lærelisterne står i **Job**-kortet på Træning. Tryk **Detaljer** for at se, hvad der skete med hver mail. **Stop** standser en liste, og det, der allerede er lært, bevares. **Prøv igen** vises kun, når der er noget at prøve igen: mails, der fejlede eller blev udskudt, og mails, en stoppet liste ikke nåede.

Har hukommelsen for lidt spam, så tryk **Rebalancér fra spam-mapper**. Du ser først en plan over, hvilke spam-mapper der læres fra og hvor meget. Først når du bekræfter, startes jobbene. De stopper af sig selv, når forholdet er nået. Indbakken læres aldrig som spam på den måde.

Fra 2.2 lærer filteret desuden aldrig en mail som legitim, hvis en phishing-regel ramte den, hvis afsenderen er blokeret, eller hvis den kun lå under grænsen på grund af filterets egne bonusser. Det står i **Drift** som "Ikke lært som legitim (læringsvagt)".

### Byg Bayes op på ny

Da filteret blev sat op, lærte det hele indbakker som legitim post – også den spam og phishing, der lå i dem. Derfor trækker Bayes for meget mod »legitim«. **Træning → Byg Bayes op på ny** (kun administrator) starter forfra med en ren Bayes, der kun lærer af sikre eksempler:

- **Spam** læres fra Spamfilter-mappen, udbydernes spam-mapper (fx Uønsket e-mail) – også gammel spam – og fra enkeltmails, I selv har lagt i spam eller som en administrator har sagt "ikke legitim" om.
- **Legitim post** læres kun fra jeres egne **arkivmapper**, de nyeste først – aldrig fra Indbakken, Sendt, Kladder, Udbakke, Papirkurv eller spam-mapper. Højst 2 legitime pr. spam (du kan vælge 1, 1,5, 2 eller 3), spredt over postkasser og mapper.
- En mail med en trussel, din egen spam-markering eller en tilbagerullet autolæring læres aldrig som legitim.
- **Intet i postkasserne** flyttes, markeres eller slettes – mailene bliver kun læst.
- **Den gamle Bayes gemmes urørt** som backup (puljen `spamfilter`). Den nye hedder `spamfilter-r2` (næste gang `-r3` osv.).
- **Bayes er slået fra**, indtil den nye har lært mindst 200 spam og 200 legitime. Imens afgør filterets andre regler alene. Mens genopbygningen kører, autolærer filteret ingen legitim post, og bagefter autolærer det aldrig mails fra indbakken, som den gamle Bayes allerede havde lært.

Sådan gør du:

1. Tryk **Se planen**. Siden viser, hvor spam og legitim post kommer fra, og hvor mange der læres. Intet er startet endnu.
2. Skriv **BYG OP** i feltet og tryk **Start genopbygningen**. Filteret genstarter kort.
3. Kortet på Træning viser, hvor langt genopbygningen er (i procent af mailene), og hvor mange spam og legitime der er lært.
4. **Gendan tidligere Bayes** skifter tilbage til den gamle med ét klik og stopper genopbygningens job. Den nye pulje bliver liggende urørt.

Står der, at rspamd svarede **»allerede lært«**, lærte den nye Bayes næsten intet. Tryk så **Gendan tidligere Bayes** (knappen er fremhævet) og kontakt den, der passer serveren. Går en gendannelse i stå halvvejs, står der "Gendannelsen er ikke færdig" – tryk **Gendan tidligere Bayes** igen.

Det samme kan gøres fra kommandolinjen: `docker exec -it spamfilter sfctl bayes-rebuild --dry-run` (planen), `sfctl bayes-rebuild`, `sfctl bayes-status` og `sfctl bayes-restore`.

---

## Daglig opsummering og daglig kvittering

Der er to forskellige morgenbeskeder:

**Daglig opsummering** (til administratoren) slås til og fra under **Indstillinger → Daglig opsummering**. Den er slået til som standard:

- Hver morgen efter kl. 07 kommer en Unraid-notifikation om gårsdagen. For hver postkasse står, hvor meget der blev flyttet, frigivet og selv markeret som spam, og der er et link til Fanget spam.
- Om mandagen får du også forslag til grænsen.
- Var der ingen spam, står der "Ingen spam i går".
- Notifikationen sendes af Unraid. Tjek under **Settings → Notification Settings** i Unraid, at notifikationer når din telefon (fx via e-mail, Pushover eller Telegram).
- Fra 2.3 kan den også komme som almindelig mail. Slå **Daglig opsummering på mail** til under **Indstillinger → Notifikationer**.

**Daglig kvittering** (til den enkelte postkasse) slås til pr. konto under **Konti → konto → Daglig kvittering**. Den er slået fra som standard:

- En gang om dagen, på det valgte klokkeslæt, lægges en kort mail i postkassens egen indbakke. Den viser, hvad filteret har flyttet det seneste døgn: afsender, emne og hovedgrund.
- Er en af mailene rigtig post, trækker man den bare tilbage til Indbakken.
- Kvitteringen sendes kun, når kontoen står i Filtrér, og når der faktisk er flyttet noget.
- **Send prøve nu** lægger en kvittering mærket "Prøve" i indbakken med det samme.

Kvitteringen er god til familiemedlemmer, der sjældent kigger i WebUI'en.

**Ugerapport** slås til under **Indstillinger → Ugerapport**. Den er slået fra som standard:

- Hver mandag morgen lægges en rapport over den forrige uge i indbakken. Den viser pr. postkasse, hvad filteret scannede, flyttede og fangede, og hvad der blev frigivet eller selv flyttet til spam. Den sammenligner med ugen før.
- Rapporten viser også de mest blokerede domæner, forslag til grænsen og en kort driftsstatus.
- **Webshop-linjen** viser, hvor mange mails der kom fra webshop-domænerne, og om nogen blev flyttet. Blev en flyttet, står den i rapporten med et link til at frigive den.
- **Fuld rapport til** vælger, hvilken postkasse der får hele rapporten. **Kort version til de andre postkasser** giver hver bruger en rapport kun om sin egen postkasse, uden tekniske tal.
- **Forhåndsvis** viser rapporten uden at sende noget. **Send nu** lægger en rapport mærket "[Prøve]" i indbakken. Mandagens rapport kommer stadig.
- Postkasser, der kun overvåges, får aldrig en rapport. Filteret scanner aldrig sine egne rapporter.
- Rapporten viser fra 2.3 også **Trusler stoppet** (fx "Virus 1, Phishing-link 2"), **Flyttet efterfølgende (genscanning)** og en linje om kendte kontakter.
- Med **Ugerapport på mail** under **Indstillinger → Notifikationer** kommer den fulde rapport også som mail, én gang om ugen.

---

## Mailserver og notifikationer

Filteret kan sende almindelige mails: koder til to-trins-login, alarmer, den daglige opsummering, ugerapporten og sikkerhedsbeskeder. Indtil du har sat en mailserver op, sendes der ingen mail, og alt virker som i 2.2.

**Sæt mailserveren op** under **Indstillinger → Mailserver** (kun administrator):

1. Vælg login. Det nemmeste er **Brug postkassens login**: vælg fx postkassen Ole (bynet), så bruger filteret den postkasses egen adgangskode, når det sender. Den kopieres eller vises aldrig.
2. Server og port udfyldes med et forslag for udbyderen: Gigahost `smtp.gigahost.dk`, port 587, STARTTLS, og Scannet `mail.scannet.dk`, port 587, STARTTLS. Forslagene er mærket "forslag – bekræftes med testmail".
3. Afsender: adressen og navnet, mailene kommer fra (standardnavn "Spamfilter <servernavn>" fra Lokal opsætning).
4. Gem, og tryk **Send testmail** til din egen adresse. Kortet viser, om det lykkedes, eller en dansk fejltekst, fx om certifikatet eller adgangskoden er forkert. Virker 587 ikke, så prøv port 465 med SSL/TLS.

Godt at vide:

- Der bruges altid kryptering (STARTTLS eller SSL), og serverens certifikat kontrolleres. Login sker aldrig uden kryptering.
- Vælger du **Brugernavn og adgangskode** i stedet, gemmes adgangskoden i en fil på serveren, som kun filteret kan læse. Den vises aldrig igen. Skifter du server, skal du skrive adgangskoden igen.
- Bruger du **postkassens login** med en anden server end postkassens egen udbyder, skal du skrive postkassens adgangskode én gang i feltet **Postkassens adgangskode**. Så kan postkassens adgangskode ikke sendes til en fremmed server ved en fejl.
- Filteret sender højst 60 mails i timen og højst 20 til samme adresse. Koder og alarmer har forrang.

**Vælg modtagere** under **Indstillinger → Notifikationer**, lige under Mailserver. Hver slags kan slås til for sig og have sine egne modtagere:

| Kontakt | Hvad der sendes |
| --- | --- |
| **Alarmer på mail** | Container nede, login afvist, sikkerhedsbremsen og andre problemer, og når de er løst igen |
| **Daglig opsummering på mail** | Gårsdagens tal hver morgen, ud over Unraid-notifikationen |
| **Ugerapport på mail** | Den fulde ugerapport om mandagen |
| **Sikkerhed på mail** | Nyt to-trins-login, ny adgangskode og nulstillinger. Brugeren selv får altid besked på sin bekræftede adresse. |

**Drift → Mail** viser, om mailserveren virker, hvornår der sidst blev sendt, hvor mange der venter i køen, og fejl det seneste døgn.

Filterets egne mails er mærket, så filteret aldrig scanner, flytter eller lærer af dem, heller ikke når de sendes til en postkasse, det selv filtrerer.

Mens filteret selv er stoppet, kan det ikke sende mail. Så kommer kun Unraid-notifikationen. Når filteret starter igen efter mere end 10 minutter, sender det en alarm om, hvor længe det var stoppet.

---

## Home Assistant

Fra 2.3.6 kan Home Assistant vise dagens spam pr. postkasse og give en push-besked på telefonen, når der er et problem. Den fulde vejledning med pakken, push-automationen og kort til **ejerens side** og **Sofies side** står i [HOME-ASSISTANT.md](HOME-ASSISTANT.md).

Kort fortalt:

1. **Konti og adgang → Adgang for programmer → Ny API-nøgle** (kun administrator), fx med navnet "Home Assistant" og **Kun læse**. Nøglen vises **én gang**, så kopiér den med det samme. Filteret gemmer kun et fingeraftryk af den.
2. Læg `spamfilter_auth: "Bearer <nøglen>"` i Home Assistants `secrets.yaml`, og kopiér pakken fra kortet til `packages/spamfilter.yaml`.
3. Tjek konfigurationen i Home Assistant, og genstart.

Godt at vide:

- API'en (`/api/v1/ha`) svarer **kun fra hjemmenetværket** og kun med nøglen. Udefra, gennem tunnelen eller uden nøgle svarer den "Siden findes ikke", som en adresse der ikke findes. 5 forkerte forsøg fra samme adresse spærrer i 15 minutter.
- Svaret indeholder kun tal og tilstande: spam i dag og de sidste 7 dage, scannet i dag, postkassens status og en liste over problemer. Ingen adresser, emner eller afsendere.
- **Problemer**, der giver push-besked: login afvist, en postkasse der er stoppet, filteret svarer ikke, rspamd er nede, en farlig mail ligger stadig i en indbakke, mislykkede flytninger og et nyt lignende domæne.
- Listen viser, hvornår og hvorfra hver nøgle sidst blev brugt, og det seneste afviste forsøg. Skraldespanden sletter én nøgle med det samme; de andre virker videre. Lav en nøgle pr. program (fx "Home Assistant" og "Kontrolrum"). Alt står i loggen med nøglens navn, aldrig selve nøglen.
- **Login fra Kontrolrum (SSO)** står på samme side, over listen. Det er til personer og virker som før.
- I nød: `docker exec -it spamfilter sfctl api-key list|create|delete` (eller det gamle `sfctl ha-token status|create|revoke`).

---

## Sikkerhedsbremsen

Filteret stopper selv flytningerne, hvis det pludselig flytter usædvanligt meget:

- mere end 25 mails på en time, eller
- mere end 40 % af den scannede post på 2 timer (mindst 10 flytninger).

Når det sker:

- Kontoen får status **Flytning på pause**, og der kommer straks en Unraid-notifikation (og en mail, hvis **Alarmer på mail** er slået til).
- Spam bliver liggende i indbakken. Filteret bliver ved med at vurdere og sætter mailene i kø.
- På konto-siden står et rødt banner med grunden og knappen **Genoptag flytning**.

Gør sådan her:

1. Kig **Fanget spam** og **Beskeder** igennem. Var det rigtige mails, der blev flyttet, så brug **Fortryd flytninger** (knappen sidder også i banneret).
2. Når alt ser rigtigt ud, så tryk **Genoptag flytning**. Mails i køen bliver så flyttet.

Efter en opdatering af filteret flytter det desuden kun tydelig spam (grænsen + 5) de første 30 minutter. Resten venter i køen, indtil de 30 minutter er gået.

---

## Nødadgang via sfctl

Kan du ikke komme ind i WebUI'en, kan du rette det meste direkte på serveren. Log ind på Unraid som root (fx via SSH eller terminalen i Unraid), og skriv:

```sh
docker exec -it spamfilter sfctl <kommando>
```

| Problem | Kommando |
| --- | --- |
| Glemt adgangskode | `sfctl reset-password NAVN --generate` |
| Mistet telefon eller mail (to-trins-login) | `sfctl disable-2fa NAVN` – slår både app og kode på mail fra |
| Spærret ude efter for mange forsøg | `sfctl unlock NAVN` |
| Kan ikke logge ind udefra (Kun lokalt) | `sfctl login-scope NAVN overalt` |
| Mailserveren driller | `sfctl smtp-status`, `sfctl smtp-test ADRESSE` eller `sfctl smtp-disable` (slår afsendelse fra, indstillingerne bevares) |
| Der er ingen administrator | `sfctl create-admin NAVN --generate` |
| Filteret flytter forkert post | `sfctl pause --all` (senere `sfctl resume --all`) |
| Flytning stoppet af sikkerhedsbremsen | `sfctl resume-moves KONTO` |
| Noget virker ikke | `sfctl doctor` |

`sfctl users` og `sfctl status` viser navne og tilstand. `sfctl` alene viser hjælpen på dansk. Farlige handlinger beder dig skrive `ja`. Alt skrives i revisionsloggen. Se også [SECURITY.md](SECURITY.md#nødadgang-sfctl).

---

## Hvis noget går galt

| Problem | Gør sådan |
| --- | --- |
| En rigtig mail ligger i Spamfilter | Træk den tilbage til Indbakken i mailprogrammet. Eller tryk **Frigiv** (kun denne mail) eller **Tillad afsender** (også fremover). |
| En mail er forsvundet | **Find en mail** → **Søg også i postkassen**. Går posten stadig gennem SpamExperts, kan den ligge i SpamExperts' karantæne (siden siger det så). Filteret sletter aldrig noget, så tjek også papirkurven og mailprogrammets egne regler. |
| Filteret har flyttet for meget | **Fortryd flytninger** for perioden. Sæt evt. grænsen op under Konti → Følsomhed. |
| "Flytning på pause" | Se **Sikkerhedsbremsen** ovenfor. |
| Spam slipper igennem | Træk den ind i Spamfilter. Det lærer filteret af. Bliver den samme afsender ved, så brug **Bloker afsender** eller **Bloker domæne**. Se også **Forslag til følsomhed**. |
| En webshop-ordre er havnet i Spamfilter | Tjek under Regler, at `@vexar.example` står som **Altid igennem**, og at adressen står under **Beskyttede adresser**. Træk mailen tilbage. |
| En ægte mail fik "Afsendernavnet udgiver sig for at være …" | Frigiv mailen, og tilføj afsenderens domæne i `th_brand_domains.map`. Se **Phishing-regler** ovenfor. |
| En tilladt afsender blev alligevel vurderet på score | Se på mailens egen side, om den er **Scannet sent**. Se **Sen scanning** ovenfor. |
| Kontoen viser "Udbyder begrænser" | Gør ingenting. Filteret venter selv 5–30 minutter og prøver igen. |
| Kontoen viser "Login fejler" | Adgangskoden hos udbyderen er skiftet. Indtast den nye under **Konti → konto → Forbindelse** (den testes, før den gemmes). |
| Kan ikke logge ind | Efter 5 forkerte forsøg er login låst i 15 minutter. Har du glemt koden, så lad en administrator trykke **Skift kode** under Brugere. |
| Mistet telefon (to-trins-login) | Brug en genoprettelseskode eller kode på mail, eller se afsnittet **To-trins-login**. |
| Koden på mail kommer ikke | Tjek spam-mappen og **Drift → Mail**. Vent til **Send en ny kode** er aktiv igen. Virker mailserveren ikke, så brug appen eller en genoprettelseskode, eller `sfctl disable-2fa NAVN`. |
| "Send testmail" fejler | Læs fejlteksten på kortet. Prøv port 465 med SSL/TLS. Tjek adgangskoden, eller brug **Brug postkassens login**. |
| En Bruger kan ikke logge ind udefra | Brugeren står måske til **Kun lokalt**. Ret det under Brugere, eller `sfctl login-scope NAVN overalt`. |
| En mail har et rødt mærke ("Farlig mail") | Se **Trusler**. Kun en administrator kan frigive den, og den læres aldrig som legitim. |
| En kunde, du har skrevet med, havnede alligevel i Spamfilter | Se på mailens side, om den har mærket **Kendt kontakt**. Mangler det, kunne afsenderen ikke bekræftes (DKIM/DMARC), eller den første gennemgang af Sendt er ikke færdig. Se **Regler → Kendte kontakter**. |
| Afsenderen blev fjernet fra Kendte kontakter ved en fejl | Tryk **Behold som kontakt** på Oversigten, eller **Gendan** under Regler → Kendte kontakter. |
| WebUI'en svarer slet ikke | Tjek i Unraid under Docker, at `spamfilter` kører, eller kør `docker ps --filter name=spamfilter`. Siden **Drift** viser containere, DNS og backup. Se også [INSTALLATION.md](INSTALLATION.md). |
| Udefra siger login hele tiden "Siden var udløbet", eller en side siger "Sikkerhedstokenet passede ikke" | Skriv adressen under **Indstillinger → Adgang udefra → Ekstern adresse**. Den skal være præcis den adresse, du åbner, med `https://`. Tjek også, at TRUSTED_PROXIES er sat. Se [CLOUDFLARE-TUNNEL.md](CLOUDFLARE-TUNNEL.md). |

Kommer du ikke videre, så kig i **Drift → Ændringslog**. Alle administrative handlinger står i revisionsloggen.


## Kontrol af dækning (2.15)

Administrator kan under **Drift** se, hvor mange scanninger, læste/store mails og fejlede forsøg der er registreret pr. postkasse de seneste 14 dage. Det er hændelsestal og ikke en procent for, hvor god filtreringen er. Filteret arbejder efter mailens levering, så en telefon kan nå at vise en notifikation. Ingen scanning finder alle trusler; allerede læst post, størrelsesgrænsen og et utilgængeligt virustjek begrænser dækningen.

Mails uden Message-ID bliver nu også scannet. Filteret husker frigivelsen af den konkrete mail ud fra dens indhold. En ny mail med samme ID, men andet indhold, vurderes selvstændigt. En almindelig tilladelse tilføjet under ventetiden kan aflyse flytningen, når afsender- og trusselskontrollen tillader det.
