# Adgang udefra med Cloudflare Tunnel

Med en Cloudflare Tunnel kan du bruge spamfilteret uden for huset via `https://spam.dit-domæne.dk` og installere det som app på Android. Der åbnes ingen porte i routeren: `cloudflared` på Unraid ringer selv ud til Cloudflare.

**Cloudflare Access** står foran tunnellen. Kun de e-mailadresser, du godkender, når overhovedet frem til login-siden. Bagefter kommer spamfilterets eget login, med to-trins-login for administratorer.

> Gør trinene i rækkefølge. Spamfilteret må aldrig være åbent udefra uden Cloudflare Access og to-trins-login.

Du skal bruge:

- en Cloudflare-konto, hvor dit domæne ligger (DNS hos Cloudflare)
- Cloudflare Zero Trust (gratis-planen er nok)
- adgang til Unraid som root

I eksemplerne hedder adressen `spam.dit-domæne.dk`. Brug din egen.

---

## Trin 1 – Slå to-trins-login til for alle administratorer

1. Log ind på `http://192.168.1.10:18080` hjemmefra.
2. Gå til **Min konto → To-trins-login**, og følg vejledningen. Gem de 8 genoprettelseskoder.
3. Gør det samme for de andre administratorer. Under **Brugere** kan du sætte **Kræv to-trins-login** for dem og for de Brugere, der skal kunne logge ind udefra.

**Indstillinger → Adgang udefra** advarer, hvis en administrator mangler to-trins-login.

## Trin 2 – Opret Access-applikationen (låsen foran)

Lav låsen, før døren åbnes.

1. Gå til [one.dash.cloudflare.com](https://one.dash.cloudflare.com) og vælg din konto.
2. Gå til **Access → Applications** (i nyere udgaver **Access controls → Applications**), og tryk **Add an application**.
3. Vælg **Self-hosted**.
4. Udfyld:
   - **Application name:** `Spamfilter`
   - **Session duration:** fx `1 month`, så du ikke skal logge ind hos Cloudflare hver dag
   - **Public hostname / Application domain:** subdomæne `spam`, domæne `dit-domæne.dk`
5. Under **Policies** trykker du **Add a policy**:
   - **Policy name:** `Ejer og familie`
   - **Action:** `Allow`
   - **Include → Selector: Emails →** skriv dine egne adresser, fx `ole@bynet.example` og `ole@molt.example`. Tilføj familiemedlemmer, der skal kunne logge ind udefra.
   - Lav **ikke** en `Bypass`- eller `Everyone`-regel.
6. Under **Login methods** er **One-time PIN** nok. Cloudflare sender så en kode til mailadressen.
7. Gem applikationen.

## Trin 3 – Opret tunnellen og den offentlige adresse

### A. Du har allerede en `cloudflared`-container på Unraid

Lad containeren være, som den er. Du skal ikke genskabe eller omkonfigurere den, hvis den også bruges til andre tjenester.

1. Gå til **Networks → Tunnels** i Zero Trust (i nyere udgaver **Networks → Connectors → Cloudflare Tunnels**).
2. Vælg den eksisterende tunnel, og tryk **Configure**.
3. Under **Public Hostname** (i nyere udgaver **Published application routes**) tryk **Add a public hostname**:
   - **Subdomain:** `spam`
   - **Domain:** `dit-domæne.dk`
   - **Path:** tom
   - **Service Type:** `HTTP`
   - **URL:** `192.168.1.10:18080`
4. Gem. Lad **Additional application settings** stå som standard. Du må ikke ændre **HTTP Host Header**.

Styres tunnellen af en lokal `config.yml` i stedet for fra dashboardet, så tag en kopi af filen først. Tilføj derefter en ingress-linje før den afsluttende `http_status:404`, og genstart kun den container:

```yaml
  - hostname: spam.dit-domæne.dk
    service: http://192.168.1.10:18080
```

### B. Du har ingen tunnel endnu

1. Gå til **Networks → Tunnels** og tryk **Create a tunnel**. Vælg **Cloudflared** og kald den fx `spamfilter`.
2. Vælg **Docker** som miljø, og kopiér den viste token (den lange streng efter `--token`). Behandl den som en adgangskode.
3. Opret containeren på Unraid. Det kan være via **Apps** (Community Applications, søg på "cloudflared") eller som root i en terminal:

   ```sh
   docker run -d --name cloudflared --restart unless-stopped \
     cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <DIN-TOKEN>
   ```

   Brug gerne et fast versionsnummer i stedet for `latest`. Standard-netværket (`bridge`) er fint, for containeren skal bare kunne nå `192.168.1.10:18080`.
4. Tilbage i Cloudflare skal tunnellen stå som **Healthy**. Tryk **Next**, og tilføj den offentlige adresse som i A, punkt 3: `spam` · `dit-domæne.dk` · `HTTP` · `192.168.1.10:18080`.

Åbn nu `https://spam.dit-domæne.dk` på telefonen med mobildata. Først skal Cloudflare spørge om din e-mail (Access), og derefter kommer spamfilterets login. Gør Cloudflare ikke det, så stop her og ret Access-applikationen.

## Trin 4 – Skriv den eksterne adresse i spamfilteret

1. Hjemmefra går du til **Indstillinger → Adgang udefra** (under **System**).
2. Skriv `https://spam.dit-domæne.dk` i **Ekstern adresse**, og tryk **Gem adresse**.

Adressen bruges til sikkerhedstjekket af formularer, til linket i den daglige opsummering og i app-vejledningen. Uden den afviser spamfilteret login udefra med "Siden var udløbet".

## Trin 5 – Stol på cloudflared (TRUSTED_PROXIES)

Spamfilteret stoler ikke på headere fra en proxy, før du har sagt, hvilken adresse proxyen kommer fra. Først derefter kan det se:

- din rigtige IP-adresse, som bruges til spærringen af login efter for mange forsøg og i loggen
- at forbindelsen er HTTPS, så cookies bliver `Secure` og HSTS slås til
- din Cloudflare Access-identitet, som skrives i revisionsloggen

Find adressen:

1. Åbn `https://spam.dit-domæne.dk` udefra, og log ind som administrator.
2. Gå til **Indstillinger → Adgang udefra**. Kortet viser **Proxy ikke betroet** med teksten "… kommer fra **172.x.y.z**, som ikke er betroet". Det er adressen, du skal bruge.

   Typisk er det `cloudflared`-containerens IP eller gatewayen på Docker-netværket `spamnet`. Kortet viser altid den rigtige adresse. Containerens egen IP kan du se med:

   ```sh
   docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' cloudflared
   ```

Sæt den på serveren som root:

```sh
cd /mnt/user/appdata/spamfilter/source
nano deploy/versions.env          # sæt: TRUSTED_PROXIES=172.x.y.z
./deploy/recreate-filter.sh       # tager backup, genskaber filteret og tjekker helbredet
```

Regler for adressen:

- Skriv kun den ene adresse. Flere adresser adskilles med komma uden mellemrum.
- Skriv aldrig hele LAN'et (`192.168.1.0/24`) eller `0.0.0.0/0`. Alle adresser, du skriver, kan bestemme, hvilken IP og hvilken Access-identitet spamfilteret ser.
- `deploy/versions.env` bliver overskrevet, når en ny version af kildekoden kopieres ind. Skriv TRUSTED_PROXIES ind igen efter hver opdatering, før du kører `recreate-filter.sh`.
- Får `cloudflared` en ny IP, fx hvis containeren genskabes på et andet netværk, viser kortet "Proxy ikke betroet" igen. Så gentager du trin 5.

## Trin 6 – Tjek statuskortet

Åbn **Indstillinger → Adgang udefra** via `https://spam.dit-domæne.dk`. Det skal vise:

| Felt | Forventet |
| --- | --- |
| Forbindelse | **HTTPS** – "Via Cloudflare Tunnel." |
| Via proxy | Ja – fra den adresse, du satte |
| Din IP | Din telefons offentlige IP, ikke `172.…` |
| Betroede proxyer | Din adresse |
| Ekstern adresse | `https://spam.dit-domæne.dk` |
| Sikre cookies / HSTS | Ja / Slået til |
| Cloudflare Access | Den e-mail, du loggede ind hos Cloudflare med |

Nederst står der: "Alt ser godt ud: HTTPS, betroet proxy, Cloudflare Access og to-trins-login." Hjemme på `http://192.168.1.10:18080` viser kortet bare "Lokal forbindelse (HTTP)". Det er korrekt.

## Trin 7 – Installér som app på Android

1. Åbn `https://spam.dit-domæne.dk` i **Chrome** på telefonen, og log ind (Cloudflare først, så spamfilteret). Sæt flueben ved **Husk mig**.
2. Tryk på menuen ⋮ øverst til højre, og vælg **Installer app** (eller **Føj til startskærm**). Nogle gange viser siden selv knappen **Installer app**.
3. Appen ligger nu på startskærmen og i app-oversigten.

Så længe Cloudflare Access-sessionen holder (fx 1 måned), åbner appen direkte. Derefter beder Cloudflare om en ny kode på mail.

**iPhone:** Åbn adressen i Safari, og tryk **Del → Føj til hjemmeskærm**. Det virker også på den lokale adresse hjemme.

Appen gemmer kun design-filer og en offline-side på telefonen, aldrig mails eller sider med dine data.

## Spamfilteret gennem Kontrolrum (2.9)

Åbner du spamfilteret inde i Kontrolrum på Kontrolrums offentlige adresse, går kaldet gennem Kontrolrums tunnel og videre fra Kontrolrum til spamfilteret. Spamfilteret ser det derfor som "udefra", og en *Kun lokalt*-bruger som `kontrolrum` bliver afvist – med vilje.

Med **Login fra Kontrolrum** (Adgang for programmer → Login fra Kontrolrum, se [CONFIGURATION.md](CONFIGURATION.md#login-fra-kontrolrum-29)) logger Kontrolrum ind med en signeret engangspåstand i stedet for adgangskoden. Den session må bruges udefra, men **kun fra Kontrolrums egen adresse**:

- Kopierer nogen sessions-cookien og bruger den direkte på `spam.dit-domæne.dk`, kommer kaldet fra `cloudflared`, ikke fra Kontrolrum, og sessionen logges ud.
- Adgangskoden til en *Kun lokalt*-bruger virker stadig kun hjemme – også på login-siden gennem Kontrolrum.
- Kontrolrums adresse må ikke være `cloudflared`s adresse (TRUSTED_PROXIES). Spamfilteret afviser den, fordi alle på internettet kommer derfra.

---

## Slå adgang udefra fra igen

1. Slet den offentlige adresse (Public hostname) i tunnellen.
2. Tøm **Ekstern adresse** i spamfilteret.
3. Sæt `TRUSTED_PROXIES=` tom i `deploy/versions.env`, og kør `./deploy/recreate-filter.sh`.

Spamfilteret er derefter igen kun på det lokale netværk.
