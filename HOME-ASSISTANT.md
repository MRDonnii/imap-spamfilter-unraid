# Spamfilteret i Home Assistant

Spamfilteret kan vise dagens spam og status for hver postkasse i Home Assistant og sende en besked til telefonen, hvis der er et problem. Home Assistant henter tallene hvert 5. minut fra en lille API i filteret.

**Sikkerhed:**

- **Kun læsning.** API'en kan ikke ændre noget i filteret.
- **Kun tal og tilstande.** Der står ingen mailadresser, emner eller afsendernavne i svaret. Postkasserne står med deres id og visningsnavn.
- **Kun fra hjemmenetværket** (standard). Kald gennem Cloudflare-tunnellen eller en anden proxy bliver afvist, også med en gyldig nøgle, medmindre du har slået "Kun fra hjemmenetværket" fra på netop den nøgle.
- **Kun med en API-nøgle.** Filteret gemmer kun nøglens fingeraftryk (sha256) og de sidste 4 tegn. Selve nøglen vises én gang, når du laver den. Hvert program får sin egen nøgle, så du kan slette én uden at de andre holder op.
- **Ingen hints.** Mangler nøglen, er den forkert, eller kommer kaldet udefra, svarer filteret `404` som for en ukendt adresse. For mange forkerte forsøg fra samme IP spærres i 15 minutter.

## 1. Lav en API-nøgle

**I WebUI'en (2.11.0):** Konti og adgang → **Adgang for programmer** → **Ny API-nøgle**. Giv den navnet "Home Assistant", vælg **Kun læse**, og lad **Kun fra hjemmenetværket** være slået til. Kopiér linjen til `secrets.yaml` med det samme, for nøglen vises kun denne ene gang. Listen viser bagefter, hvornår og fra hvilken IP hver nøgle sidst blev brugt, og om nogen har prøvet med en forkert nøgle. Skraldespanden sletter én nøgle; de andre virker videre.

Havde du en nøgle fra en ældre version (`sfha_…`), er den flyttet over som "Home Assistant" med mærket **Flyttet** og virker uændret. Bruger Kontrolrum den samme nøgle, så lav en ekstra nøgle "Kontrolrum", og sæt den ind i Kontrolrum. Det er frivilligt.

**Fra kommandolinjen på Unraid** (fx hvis WebUI'en ikke kan nås):

```sh
docker exec -it spamfilter sfctl api-key create --name "Home Assistant"   # ny nøgle (vises én gang), Kun læse
docker exec -it spamfilter sfctl api-key list                             # alle nøgler, senest brugt, seneste afvisning
docker exec -it spamfilter sfctl api-key delete ID                        # slet én nøgle
```

`sfctl ha-token create|status|revoke` virker stadig og gælder nøglen med navnet "Home Assistant". Begge veje skrives i revisionsloggen.

Læg nøglen i Home Assistants `secrets.yaml`. Hele værdien skal stå i anførselstegn og begynde med `Bearer `:

```yaml
spamfilter_auth: "Bearer sf_...din nøgle..."
```

## 2. Læg pakken ind

Slå pakker til i `configuration.yaml`, hvis du ikke allerede har gjort det:

```yaml
homeassistant:
  packages: !include_dir_named packages
```

Gem pakken herunder som `packages/spamfilter.yaml`. Gå derefter til **Udviklerværktøjer → YAML → Tjek konfiguration**, og genstart Home Assistant.

Kortet i Indstillinger viser den samme pakke med jeres egne postkasser og filterets adresse, klar til at kopiere. Eksemplet her har de fem postkasser `bynet`, `molt`, `molt-inge`, `molt-handel` og `molt-sofie`.

**Ny postkasse? Hent pakken igen.** Pakken har kun sensorer for de postkasser, der fandtes, da den blev kopieret. Når der kommer en ny postkasse, så kopiér pakken igen fra **Indstillinger → Adgang for programmer** og erstat `packages/spamfilter.yaml` (genstart bagefter). Fra 2.12 slår `binary_sensor.spamfilter_pakken_skal_hentes_igen` til, når filteret har en postkasse, pakken ikke kender.

```yaml
# Spamfilter -> Home Assistant (kun læsning: tal og tilstande, ingen adresser eller emner)
# Sensorer for 5 postkasser: bynet, molt, molt-inge, molt-handel, molt-sofie.
# Kommer der en ny postkasse, så hent pakken igen (Indstillinger -> Adgang for programmer)
# og erstat denne fil - binary_sensor.spamfilter_pakken_skal_hentes_igen siger til.
# 1. secrets.yaml:  spamfilter_auth: "Bearer DIN-NØGLE"
# 2. configuration.yaml:
#      homeassistant:
#        packages: !include_dir_named packages
# 3. Gem denne fil som packages/spamfilter.yaml, tjek konfigurationen og genstart.
rest:
  - resource: http://192.168.1.10:18080/api/v1/ha
    headers:
      Authorization: !secret spamfilter_auth
    scan_interval: 300
    timeout: 30
    sensor:
      - name: "Spamfilter status"
        unique_id: spamfilter_status
        icon: mdi:shield-check
        value_template: "{{ 'OK' if value_json.ok else 'Problem' }}"
        json_attributes:
          - problems
          - version
          - bayes
          - lookalike
          - totals
      - name: "Spamfilter spam i dag"
        unique_id: spamfilter_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.totals.spam_today }}"
      - name: "Spamfilter scannet i dag"
        unique_id: spamfilter_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.totals.scanned_today }}"
      - name: "Spamfilter farlige mails i dag"
        unique_id: spamfilter_farlige_i_dag
        icon: mdi:alert-octagon
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.threats_today }}"
      - name: "Spamfilter nye lignende domæner"
        unique_id: spamfilter_nye_lignende_domaener
        icon: mdi:web-check
        value_template: "{{ value_json.lookalike.new_registrations }}"
      # Postkasse: bynet
      - name: "Spamfilter bynet spam i dag"
        unique_id: spamfilter_bynet_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['bynet'].spam_today }}"
        json_attributes_path: "$.accounts['bynet']"
        json_attributes:
          - display_name
          - spam_7d
          - spam_by_user_today
          - released_today
          - threats_today
      - name: "Spamfilter bynet scannet i dag"
        unique_id: spamfilter_bynet_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['bynet'].scanned_today }}"
      - name: "Spamfilter bynet status"
        unique_id: spamfilter_bynet_status
        icon: mdi:mailbox
        value_template: "{{ value_json.accounts['bynet'].state_label }}"
        json_attributes_path: "$.accounts['bynet']"
        json_attributes:
          - display_name
          - state
          - mode_label
          - threshold
          - login_ok
          - last_activity
      # Postkasse: molt
      - name: "Spamfilter molt spam i dag"
        unique_id: spamfilter_molt_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt'].spam_today }}"
        json_attributes_path: "$.accounts['molt']"
        json_attributes:
          - display_name
          - spam_7d
          - spam_by_user_today
          - released_today
          - threats_today
      - name: "Spamfilter molt scannet i dag"
        unique_id: spamfilter_molt_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt'].scanned_today }}"
      - name: "Spamfilter molt status"
        unique_id: spamfilter_molt_status
        icon: mdi:mailbox
        value_template: "{{ value_json.accounts['molt'].state_label }}"
        json_attributes_path: "$.accounts['molt']"
        json_attributes:
          - display_name
          - state
          - mode_label
          - threshold
          - login_ok
          - last_activity
      # Postkasse: molt-inge
      - name: "Spamfilter molt-inge spam i dag"
        unique_id: spamfilter_molt_inge_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-inge'].spam_today }}"
        json_attributes_path: "$.accounts['molt-inge']"
        json_attributes:
          - display_name
          - spam_7d
          - spam_by_user_today
          - released_today
          - threats_today
      - name: "Spamfilter molt-inge scannet i dag"
        unique_id: spamfilter_molt_inge_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-inge'].scanned_today }}"
      - name: "Spamfilter molt-inge status"
        unique_id: spamfilter_molt_inge_status
        icon: mdi:mailbox
        value_template: "{{ value_json.accounts['molt-inge'].state_label }}"
        json_attributes_path: "$.accounts['molt-inge']"
        json_attributes:
          - display_name
          - state
          - mode_label
          - threshold
          - login_ok
          - last_activity
      # Postkasse: molt-handel
      - name: "Spamfilter molt-handel spam i dag"
        unique_id: spamfilter_molt_handel_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-handel'].spam_today }}"
        json_attributes_path: "$.accounts['molt-handel']"
        json_attributes:
          - display_name
          - spam_7d
          - spam_by_user_today
          - released_today
          - threats_today
      - name: "Spamfilter molt-handel scannet i dag"
        unique_id: spamfilter_molt_handel_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-handel'].scanned_today }}"
      - name: "Spamfilter molt-handel status"
        unique_id: spamfilter_molt_handel_status
        icon: mdi:mailbox
        value_template: "{{ value_json.accounts['molt-handel'].state_label }}"
        json_attributes_path: "$.accounts['molt-handel']"
        json_attributes:
          - display_name
          - state
          - mode_label
          - threshold
          - login_ok
          - last_activity
      # Postkasse: molt-sofie
      - name: "Spamfilter molt-sofie spam i dag"
        unique_id: spamfilter_molt_sofie_spam_i_dag
        icon: mdi:email-remove
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-sofie'].spam_today }}"
        json_attributes_path: "$.accounts['molt-sofie']"
        json_attributes:
          - display_name
          - spam_7d
          - spam_by_user_today
          - released_today
          - threats_today
      - name: "Spamfilter molt-sofie scannet i dag"
        unique_id: spamfilter_molt_sofie_scannet_i_dag
        icon: mdi:email-search
        unit_of_measurement: mails
        state_class: measurement
        value_template: "{{ value_json.accounts['molt-sofie'].scanned_today }}"
      - name: "Spamfilter molt-sofie status"
        unique_id: spamfilter_molt_sofie_status
        icon: mdi:mailbox
        value_template: "{{ value_json.accounts['molt-sofie'].state_label }}"
        json_attributes_path: "$.accounts['molt-sofie']"
        json_attributes:
          - display_name
          - state
          - mode_label
          - threshold
          - login_ok
          - last_activity
    binary_sensor:
      - name: "Spamfilter problem"
        unique_id: spamfilter_problem
        device_class: problem
        value_template: "{{ not value_json.ok }}"
      - name: "Spamfilter pakken skal hentes igen"
        unique_id: spamfilter_pakken_skal_hentes_igen
        device_class: update
        value_template: >-
          {{ value_json.account_ids is defined and
             (value_json.account_ids | sort) != ['bynet', 'molt', 'molt-handel', 'molt-inge', 'molt-sofie'] }}
```

Pakken laver disse enheder. Navnene giver entity-id'erne, fx `sensor.spamfilter_molt_sofie_spam_i_dag`.

| Enhed | Viser |
| --- | --- |
| `sensor.spamfilter_status` | `OK` eller `Problem`. Attributten `problems` er listen med korte danske tekster. |
| `binary_sensor.spamfilter_problem` | `on`, når der er mindst ét problem (enhedsklasse *problem*). |
| `binary_sensor.spamfilter_pakken_skal_hentes_igen` | `on`, når filteret har en postkasse, som pakken ikke har sensorer for (2.12). Hent pakken igen. |
| `sensor.spamfilter_spam_i_dag` / `_scannet_i_dag` | Summen for alle postkasser i dag. |
| `sensor.spamfilter_farlige_mails_i_dag` | Farlige mails (virus, phishing, farlige filer, efterligninger), der er stoppet i dag. |
| `sensor.spamfilter_nye_lignende_domaener` | Nye domæner, der ligner jeres, og som ikke er markeret som set endnu. |
| `sensor.spamfilter_<postkasse>_spam_i_dag` | Unikke mails, der er havnet i mappen Spamfilter i dag. Det er det samme tal som på postkassens kort på Oversigt. Attributter: `spam_7d` (de seneste 7 dage, ældste først), `spam_by_user_today`, `released_today` og `threats_today`. |
| `sensor.spamfilter_<postkasse>_scannet_i_dag` | Antal mails, der er scannet i dag. |
| `sensor.spamfilter_<postkasse>_status` | Fx `Aktiv`, `Login fejler` eller `På pause`. Attributter: `mode_label` (Overvåg/Markér/Filtrér), `threshold`, `login_ok` og `last_activity`. |

Tallene nulstilles ved midnat (dansk tid). Med `state_class: measurement` gemmer Home Assistant historikken, så `statistics-graph` kan vise et søjlediagram pr. dag.

## 3. Push-besked ved problemer

Læg automationen i `automations.yaml`, eller opret den i UI'et og vælg **Redigér i YAML**. Ret `notify.mobile_app_din_telefon` til din telefon. Du finder navnet under **Udviklerværktøjer → Handlinger** ved at søge efter `notify.mobile_app`. Automationen sender en besked, når der har været et problem i 10 minutter, og når filteret ikke har svaret i 15 minutter (fx hvis containeren er stoppet).

```yaml
# Push-besked, når spamfilteret har et problem eller ikke svarer.
# Ret notify.mobile_app_din_telefon til din egen telefon (Udviklerværktøjer -> Handlinger).
- alias: Spamfilter - besked ved problem
  id: spamfilter_problem_push
  mode: single
  triggers:
    - trigger: state
      entity_id: binary_sensor.spamfilter_problem
      to: "on"
      for: { minutes: 10 }
    - trigger: state
      entity_id: sensor.spamfilter_status
      to: "unavailable"
      for: { minutes: 15 }
  actions:
    - action: notify.mobile_app_din_telefon
      data:
        title: Spamfilter
        message: >-
          {% set p = state_attr('sensor.spamfilter_status', 'problems') %}
          {% if states('sensor.spamfilter_status') == 'unavailable' %}Spamfilteret svarer ikke.
          {% elif p %}{{ p | join(', ') }}{% else %}Spamfilteret melder et problem.{% endif %}
```

## 4. Kort til dashboardet

### Ejerens side (alle postkasser)

Tilføj kortet med **Redigér dashboard → Tilføj kort → Manuel**, og indsæt:

```yaml
type: vertical-stack
cards:
  - type: tile
    entity: binary_sensor.spamfilter_problem
    name: Spamfilter
    icon: mdi:shield-check
    vertical: false
  - type: markdown
    visibility:
      - condition: state
        entity: binary_sensor.spamfilter_problem
        state: "on"
    content: |
      {% for p in state_attr('sensor.spamfilter_status', 'problems') or [] %}
      - **{{ p }}**
      {% endfor %}
  - type: glance
    title: Spam i dag
    columns: 5
    entities:
      - entity: sensor.spamfilter_bynet_spam_i_dag
        name: bynet
      - entity: sensor.spamfilter_molt_spam_i_dag
        name: molt
      - entity: sensor.spamfilter_molt_inge_spam_i_dag
        name: Inge
      - entity: sensor.spamfilter_molt_handel_spam_i_dag
        name: Handel
      - entity: sensor.spamfilter_molt_sofie_spam_i_dag
        name: Sofie
  - type: statistics-graph
    title: Spam pr. dag
    chart_type: bar
    period: day
    days_to_show: 14
    stat_types:
      - max
    entities:
      - entity: sensor.spamfilter_spam_i_dag
        name: Alle postkasser
  - type: entities
    entities:
      - entity: sensor.spamfilter_farlige_mails_i_dag
        name: Farlige mails stoppet i dag
      - entity: sensor.spamfilter_nye_lignende_domaener
        name: Nye domæner, der ligner jeres
      - entity: sensor.spamfilter_bynet_status
        name: bynet
      - entity: sensor.spamfilter_molt_status
        name: molt
```

### Sofies side (kun hendes postkasse)

```yaml
type: vertical-stack
cards:
  - type: tile
    entity: sensor.spamfilter_molt_sofie_spam_i_dag
    name: Spam fanget i dag
    icon: mdi:email-remove
  - type: tile
    entity: sensor.spamfilter_molt_sofie_status
    name: Spamfilter
    icon: mdi:shield-check
  - type: statistics-graph
    title: Spam pr. dag
    chart_type: bar
    period: day
    days_to_show: 7
    stat_types:
      - max
    entities:
      - entity: sensor.spamfilter_molt_sofie_spam_i_dag
        name: Spam
  - type: markdown
    content: |
      {% set uge = state_attr('sensor.spamfilter_molt_sofie_spam_i_dag', 'spam_7d') or [] %}
      **{{ uge | sum }}** spam de seneste 7 dage.
      Spam ligger i mappen **Spamfilter** i din mail. Intet bliver slettet.
```

Sådan gør du det samme for de andre: skift `molt_sofie` ud med postkassens id (bindestreger bliver til `_`).

## 5. Svaret fra API'en

`GET http://192.168.1.10:18080/api/v1/ha` med headeren `Authorization: Bearer <nøgle>`. Eksempel (forkortet):

```json
{
  "version": "2.4.0",
  "generated_at": "2026-10-22T18:05:00+02:00",
  "ok": false,
  "problems": ["Login fejler for Inge"],
  "problem_count": 1,
  "bayes": {"active": true, "spam": 512, "ham": 1840},
  "threats_today": 1,
  "lookalike": {"new_registrations": 0, "last_run": "2026-10-22T03:12:40+02:00"},
  "antivirus": {"state": "ok", "signatures_age_hours": 5.2},
  "mailcheck": {"status": "warn", "errors": 0, "warnings": 2, "last_run": "2026-10-22T05:01:12+02:00"},
  "accounts": {
    "molt-sofie": {
      "display_name": "Sofie", "state": "idle", "state_label": "Aktiv",
      "mode": "move", "mode_label": "Filtrér", "enabled": true, "threshold": 10.0,
      "scanned_today": 38, "spam_today": 4, "spam_by_user_today": 1, "released_today": 0,
      "threats_today": 0, "spam_7d": [3, 6, 2, 5, 4, 7, 4],
      "last_activity": "2026-10-22T18:04:31+02:00", "login_ok": true
    }
  },
  "totals": {"scanned_today": 214, "spam_today": 19, "spam_by_user_today": 2, "released_today": 1,
             "threats_today": 1, "spam_7d": [15, 22, 18, 25, 17, 30, 19]}
}
```

**Felter:**

- **`ok`** er `true`, når listen `problems` er tom.
- **`problems`** er korte danske tekster, fx:
  - "Login fejler for …"
  - "Forbindelsesfejl på …"
  - "… svarer ikke"
  - "Flytning er sat på pause for …"
  - "Konfigurationen kan ikke indlæses"
  - "Filteret svarer ikke (hovedløkken står stille)"
  - "rspamd svarer ikke – scanning og læring venter"
  - "N farlige mails ligger stadig i indbakken hos …"
  - "N flytninger fejlede det seneste døgn"
  - "Nyt domæne ligner pinsikbing.example". Selve det lignende domæne sendes aldrig.
  - "Antivirus (ClamAV) svarer ikke – mails scannes uden virustjek"
  - "Antivirus (ClamAV) har ikke fået nye virussignaturer i over 3 dage"

  Postkasser på pause tæller ikke som et problem.
- **`spam_today`** er unikke mails, der er havnet i mappen Spamfilter i dag. Det tæller både filterets flytninger (også ved genscanning) og mails, brugeren selv har flyttet derhen. En mail, der er flyttet to gange, tæller kun én gang. **`spam_by_user_today`** er den del, brugeren selv har flyttet.
- **`spam_7d`** viser de samme tal for de seneste 7 kalenderdage, ældste først. Det sidste tal er i dag.
- **`bayes.active`** er `null`, hvis rspamd ikke svarer.
- **`antivirus.state`** (2.7) er `ok`, `off` (slået fra med `SF_CLAMAV=0`), `waiting` (henter de første virussignaturer efter installationen), `down` (clamd svarer ikke) eller `stale` (signaturerne er over 3 dage gamle). `null` betyder ukendt (intet nyt sundhedstjek). **`antivirus.signatures_age_hours`** er signaturernes alder i timer.

## Fejlfinding

| Problem | Løsning |
| --- | --- |
| Sensorerne er *utilgængelige*, og loggen viser 404 | Tjek nøglen i `secrets.yaml` (husk `Bearer `). Kør `sfctl api-key list`. Står der en *seneste afvisning* fra Home Assistants IP, er nøglen forkert eller gammel. |
| 404, selv om nøglen er rigtig | Home Assistant skal kalde filteret direkte på LAN-adressen og ikke via den eksterne https-adresse. Home Assistants IP skal ligge i `LOCAL_NETWORKS` (standard: de private net 10/8, 172.16/12 og 192.168/16). |
| Spærret efter forkerte forsøg | Vent 15 minutter, eller kør `sfctl unlock --ip <Home Assistants IP>`. |
| Nøglen er lækket | Slet den under **Adgang for programmer** (eller kør `sfctl api-key delete ID`), og lav en ny. En lækket nøgle med Kun læse viser kun tal og virker kun fra hjemmenetværket. |
