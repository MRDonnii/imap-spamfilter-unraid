"""RSPAMD-CONFIG (2.2 B0-B5): the rspamd/local.d files and maps.d lists.

rspamd itself is not available in the test environment, so these tests pin
the config text (weights, multimap/composite definitions, map paths) and
exercise the map regexps through a PCRE -> Python translation. The real
validation against rspamd 4.2.2 (configtest, configdump, rspamc scans of
synthetic mails) was done once on the Unraid host in a throwaway rspamd
instance.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCAL_D = ROOT / "rspamd" / "local.d"
MAPS_D = LOCAL_D / "maps.d"
LIB_SH = ROOT / "deploy" / "lib.sh"
FILTER_DIR = ROOT / "filter"


def _rendered_local_d() -> Path:
    """local.d as rspamd sees it in the all-in-one container: the repository
    files + the own domains of the local site config (tests/site.yml),
    added at container start by deploy/aio/aio_render.py."""
    import shutil
    import sys
    import tempfile
    sys.path.insert(0, str(ROOT / "deploy" / "aio"))
    import aio_render  # noqa: PLC0415
    dst = Path(tempfile.mkdtemp(prefix="sf-localdr-")) / "local.d"
    shutil.copytree(LOCAL_D, dst)
    out = dst.parent / "site"
    aio_render.render_site(Path(__file__).with_name("site.yml"), out)
    aio_render.apply_site(dst, aio_render.load_site(out / "site.json"))
    return dst


RENDERED_D = _rendered_local_d()


def _filter_module(name: str):
    """Import a module from filter/ (engine / ui_kit) for the 2.6 checks."""
    import importlib
    import sys
    if str(FILTER_DIR) not in sys.path:
        sys.path.insert(0, str(FILTER_DIR))
    return importlib.import_module(name)

# Files in local.d that are deliberately NOT in SF_RSPAMD_FILES.
NOT_INSTALLED_AS_IS = {"redis.conf.template", "worker-controller.inc.template",  # rendered with secrets
                       "redis.conf", "worker-controller.inc",  # rendered copies (gitignored)
                       "fuzzy_check.conf", "fuzzy_check.conf.readonly",  # installed per ENABLE_FUZZY
                       "antivirus.conf.legacy"}  # 2.7 fix: installed as antivirus.conf on the 4-container layout


def sf_rspamd_files() -> list[str]:
    m = re.search(r"^SF_RSPAMD_FILES=\(([^)]*)\)", LIB_SH.read_text(), re.M)
    assert m, "SF_RSPAMD_FILES missing in deploy/lib.sh"
    return m.group(1).split()


def map_entries(name: str) -> list[str]:
    out = []
    for line in (RENDERED_D / "maps.d" / name).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def pcre(entry: str) -> re.Pattern:
    """rspamd regexp-map line (/pattern/flags) -> Python regex."""
    m = re.fullmatch(r"/(.*)/([a-zA-Z]*)", entry)
    assert m, f"not a /regexp/flags line: {entry!r}"
    pat = re.sub(r"\\x\{([0-9A-Fa-f]+)\}", lambda x: chr(int(x.group(1), 16)), m.group(1))
    return re.compile(pat, re.I if "i" in m.group(2) else 0)


def regexp_map(name: str) -> list[re.Pattern]:
    return [pcre(e) for e in map_entries(name)]


def matches(name: str, text: str) -> bool:
    return any(r.search(text) for r in regexp_map(name))


def blocks(conf: str) -> dict[str, str]:
    text = (RENDERED_D / conf).read_text(encoding="utf-8")
    return {m.group(1): m.group(2) for m in re.finditer(r"^([A-Z][A-Z0-9_]+)\s*\{(.*?)^\}", text, re.M | re.S)}


def opt(block: str, key: str) -> str:
    m = re.search(rf"^\s*{key}\s*=\s*(.+?);\s*$", block, re.M)
    assert m, key
    return m.group(1).strip().strip('"')


def group_weights() -> dict[str, tuple[str, float]]:
    """{symbol: (group, weight)} from groups.conf."""
    text = (LOCAL_D / "groups.conf").read_text(encoding="utf-8")
    out = {}
    for g in re.finditer(r'^group\s+"([^"]+)"\s*\{(.*?)^\}', text, re.M | re.S):
        for s in re.finditer(r'"([A-Z0-9_]+)"\s*\{\s*weight\s*=\s*(-?[\d.]+);', g.group(2)):
            assert s.group(1) not in out, f"{s.group(1)} defined twice"
            out[s.group(1)] = (g.group(1), float(s.group(2)))
    return out


def braces_balanced(text: str) -> bool:
    depth = 0
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        line = re.sub(r'"[^"]*"', '""', line)
        depth += line.count("{") - line.count("}")
        if depth < 0:
            return False
    return depth == 0


# ---------------------------------------------------------------- B0: deploy list

def test_every_local_d_conf_is_installed():
    """2.1 shipped groups.conf without installing it once; never again."""
    files = sf_rspamd_files()
    for f in files:
        assert (LOCAL_D / f).is_file(), f
    on_disk = {p.name for p in LOCAL_D.iterdir() if p.is_file()}
    assert on_disk - NOT_INSTALLED_AS_IS == set(files)
    for new in ("groups.conf", "multimap.conf", "composites.conf", "phishing.conf"):
        assert new in files


def test_conf_files_have_balanced_braces_and_no_secrets():
    for p in LOCAL_D.glob("*.conf"):
        text = p.read_text(encoding="utf-8")
        assert braces_balanced(text), p.name
        assert "password" not in text.lower() or p.name.endswith(".template"), p.name


def test_every_referenced_map_is_shipped():
    referenced = set()
    for conf in ("multimap.conf", "phishing.conf"):
        text = (LOCAL_D / conf).read_text(encoding="utf-8")
        for m in re.finditer(r'"\$LOCAL_CONFDIR/local\.d/maps\.d/([^"]+)"', text):
            referenced.add(m.group(1))
    shipped = {p.name for p in MAPS_D.iterdir()}
    assert referenced <= shipped
    # surbl-whitelist.inc.local is referenced by the stock modules.d/rbl.conf
    # (url_whitelist), not by our files.
    assert shipped - referenced == {"surbl-whitelist.inc.local"}


def test_map_files_syntax():
    for p in MAPS_D.iterdir():
        assert p.is_file() and not p.name.startswith(".")
        text = p.read_text(encoding="utf-8")
        assert text.endswith("\n"), p.name
        for line in map_entries(p.name):
            # One key per line: a literal space would split key and value,
            # "#" would start a comment.
            assert " " not in line and "\t" not in line and "#" not in line, (p.name, line)
            if p.suffix == ".re":
                assert re.fullmatch(r"/.+/[iu]*", line), (p.name, line)
                pcre(line)  # compiles


# ---------------------------------------------------------------- B1: weights

B1_WEIGHTS = {
    "URIBL_GREY": ("surbl", 0.5),
    "SEM_URIBL": ("surbl", 1.0),
    "DATE_IN_PAST": ("headers", 0.0),
    "FORGED_SENDER": ("headers", 0.0),
    "FORGED_RECIPIENTS": ("headers", 0.5),
    "MV_CASE": ("headers", 0.1),
    "FREEMAIL_REPLYTO_NEQ_FROM": ("headers", 1.0),
    "MISSING_MIMEOLE": ("headers", 0.5),
    "HFILTER_HELO_IP_A": ("hfilter", 0.5),
    "MIME_BAD_ATTACHMENT": ("mime_types", 1.0),  # 2.3 B17 / K2: was 2.0 in 2.2
    "URI_COUNT_ODD": ("url", 0.3),
    "SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE": ("url", 0.5),
    "MID_RHS_NOT_FQDN": ("Message ID", 0.1),
    "HIDDEN_TEXT": ("html", 2.0),
}


# 2.6 (A2): the filter's own fuzzy storage (fuzzy_check.conf.readonly rule "local").
A2_WEIGHTS = {"FUZZY_LOCAL_SPAM": ("fuzzy", 4.0)}


def test_groups_conf_weights_match_backlog_b1():
    assert group_weights() == {**B1_WEIGHTS, **A2_WEIGHTS}


def test_local_fuzzy_rule_writes_only_to_loopback():
    """2.6 (A2): the shared storage stays read-only; only our own storage
    on loopback is written (flag 100 = FUZZY_LOCAL_SPAM, campaigns.FUZZY_FLAG)."""
    import sys
    sys.path.insert(0, str(ROOT / "filter"))
    import campaigns

    text = (LOCAL_D / "fuzzy_check.conf.readonly").read_text(encoding="utf-8")
    assert braces_balanced(text)
    rules = dict(re.findall(r'^rule "([^"]+)" \{(.*?)^\}', text, re.M | re.S))
    assert set(rules) == {"rspamd.com", "local"}
    assert "read_only = yes;" in rules["rspamd.com"] and "servers" not in rules["rspamd.com"]
    assert 'servers = "127.0.0.1:11335";' in rules["local"] and "read_only = no;" in rules["local"]
    assert re.search(r"FUZZY_LOCAL_SPAM\s*\{[^}]*flag = (\d+);", rules["local"]).group(1) == str(campaigns.FUZZY_FLAG)
    assert "enabled = false;" in (LOCAL_D / "fuzzy_check.conf").read_text(encoding="utf-8")


def test_groups_conf_keeps_dmarc_reject_and_fresh15():
    text = (LOCAL_D / "groups.conf").read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for sym in ("DMARC_POLICY_REJECT", "SEM_URIBL_FRESH15", "RSPAMD_URIBL"):
        assert sym not in body, sym


# ---------------------------------------------------------------- B2a / B5: lists

def test_surbl_whitelist_owner_domains_not_platform():
    wl = set(map_entries("surbl-whitelist.inc.local"))
    assert wl == {"molt.example", "bynet.example", "pinsikbing.example", "gravisk.example", "hxcore.ol", "mailjet.com",
                  "kmail-lists.com", "klclick.com", "klclick1.com", "klclick2.com", "klclick3.com", "klaviyomail.com",
                  "shared.klaviyomail.com"}
    assert "vexar.example" not in wl  # multi-tenant platform: handled by the filter (B2b)


def test_phishing_conf_enables_openphish_and_exclusions():
    text = (LOCAL_D / "phishing.conf").read_text(encoding="utf-8")
    assert re.search(r"^openphish_enabled = true;$", text, re.M)
    assert re.search(r"^phishing_feed_exclusion_enabled = true;$", text, re.M)
    assert '"$LOCAL_CONFDIR/local.d/maps.d/phishing_feed_exclusion.inc"' in text
    assert "phishtank_enabled = false" not in text
    hosts = {re.match(r"https://([^/]+)/$", e).group(1) for e in map_entries("phishing_feed_exclusion.inc")}
    for dom in ("vexar.example", "gravisk.example", "pinsikbing.example"):
        assert dom in hosts and "www." + dom in hosts


# ---------------------------------------------------------------- B3/B4: multimap

def test_multimap_rules_definition():
    b = blocks("multimap.conf")
    assert set(b) == {"TH_FROM_BRAND_NAME", "TH_FROM_BRAND_DOMAIN", "TH_FROM_NAME_HOMOGLYPH",
                      "TH_LURE_SUBJECT", "TH_FROM_ABUSED_TLD", "TH_FROM_TLD_CN_RU",
                      "TH_SUBJECT_BRAND", "TH_LURE_SUBJECT_STRONG", "TH_PHISHARMY_URL", "TH_GOOGLE_RELAY_ENV"}
    want = {
        # Display-name rules MUST be type=header/From: a type=from rule only
        # gets the bare address in rspamd 4.2, so email:name is always empty
        # (verified with rspamc against 4.2.2).
        "TH_FROM_BRAND_NAME": dict(type="header", header="From", filter="email:name",
                                   regexp="true", map="th_brand_names.re", score=0.0),
        "TH_FROM_NAME_HOMOGLYPH": dict(type="header", header="From", filter="email:name",
                                       regexp="true", map="th_homoglyph.re", score=5.0),
        "TH_FROM_BRAND_DOMAIN": dict(type="from", extract_from="mime", filter="email:domain:tld",
                                     map="th_brand_domains.map", score=0.0),
        "TH_LURE_SUBJECT": dict(type="header", header="Subject", regexp="true",
                                map="th_lure_subjects.re", score=1.5),
        "TH_FROM_ABUSED_TLD": dict(type="from", extract_from="both", filter="email:domain",
                                   regexp="true", map="th_abused_tlds.re", score=5.0),
        "TH_FROM_TLD_CN_RU": dict(type="from", extract_from="both", filter="email:domain",
                                  regexp="true", map="th_tld_cn_ru.re", score=2.0),
        # 2.6 (A1)
        "TH_SUBJECT_BRAND": dict(type="header", header="Subject", regexp="true",
                                 map="th_subject_brands.re", score=0.0),
        "TH_LURE_SUBJECT_STRONG": dict(type="header", header="Subject", regexp="true",
                                       map="th_lure_subjects_strong.re", score=0.0),
        # 2.6 (A5): HTTP map, checked separately below
        "TH_PHISHARMY_URL": dict(type="url", score=3.0),
    }
    for sym, spec in want.items():
        blk = b[sym]
        for k, v in spec.items():
            if k == "score":
                assert float(opt(blk, "score")) == v, sym
            elif k == "map":
                assert opt(blk, "map") == f"$LOCAL_CONFDIR/local.d/maps.d/{v}", sym
            else:
                assert opt(blk, k) == v, (sym, k)
        # one_shot: several matching addresses (envelope + header) must not
        # multiply the score.
        assert opt(blk, "one_shot") == "true", sym
        assert opt(blk, "group") == "spamfilter_own", sym
        assert opt(blk, "description")
        if "regexp" not in spec:
            assert not re.search(r"^\s*regexp\s*=", blk, re.M), sym


def test_composites_definition():
    b = blocks("composites.conf")
    assert set(b) == {"TH_BRAND_SPOOF", "TH_LURE_COMBO", "TH_SUBJECT_BRAND_SPOOF", "TH_FREEMAIL_VIA_GOOGLE"}
    assert opt(b["TH_BRAND_SPOOF"], "expression") == "TH_FROM_BRAND_NAME & !TH_FROM_BRAND_DOMAIN"
    assert opt(b["TH_LURE_COMBO"], "expression") == (
        "TH_LURE_SUBJECT & (TH_BRAND_SPOOF | TH_FROM_NAME_HOMOGLYPH | TH_FROM_ABUSED_TLD)")
    assert float(opt(b["TH_BRAND_SPOOF"], "score")) == 5.0
    assert float(opt(b["TH_LURE_COMBO"], "score")) == 4.0
    assert opt(b["TH_SUBJECT_BRAND_SPOOF"], "expression") == (
        "TH_SUBJECT_BRAND & TH_LURE_SUBJECT_STRONG & (!TH_FROM_BRAND_DOMAIN | FREEMAIL_FROM) & !TH_BRAND_SPOOF")
    # Thresholds 6 / 7: brand + lure in the subject alone (2.5 + 1.5) stays below 5.
    assert float(opt(b["TH_SUBJECT_BRAND_SPOOF"], "score")) == 2.5
    assert float(opt(b["TH_SUBJECT_BRAND_SPOOF"], "score")) + float(
        opt(blocks("multimap.conf")["TH_LURE_SUBJECT"], "score")) < 5.0
    for blk in b.values():
        assert opt(blk, "policy") == "leave"
        assert opt(blk, "group") == "spamfilter_own"


# ---------------------------------------------------------------- map behaviour

@pytest.mark.parametrize("name", [
    "PostNord", "Post Nord Danmark", "DHL Statusdrift", "Viktor Jönsson - (DAO)", "GLS",
    "EasyPark AB", "Saphe A/S", "MobilePay Kundeservice", "Vipps MobilePay", "e-Boks",
    "MitID", "Skattestyrelsen", "Digital Post", "Netflix", "Spotify", "Apple", "Apple Support",
    "iCloud", "Microsoft account team", "Office 365", "Instagram_Support", "Facebook",
    "GoDaddy", "Punktum dk", "Zalando DK Kundesupportteam", "silvan.dk - Tilbudsafdeling",
    "Harald Nyborg", "Jem & Fix", "Danske Bank", "Lunar", "PayPal", "Klarna", "Telenor",
    "YouSee", "Norlys", "Coop", "Bilka", "Føtex", "Netto",
    "SKAT", "Skat Danmark", "skat.dk - Digital Post", "Meta", "Meta for Business", "Outlook",
    "Outlook Team", "Nexi", "Silvan", "UPS", "Salling Group", "Microsoft Outlook",
])
def test_brand_names_match(name):
    assert matches("th_brand_names.re", name)


@pytest.mark.parametrize("name", [
    "Sofie Hansen", "Apple Hansen Tømrer", "Postnummer service", "Bringe ApS", "Skatepark Aarhus",
    "Datamail", "Varmetherm", "Klubsport", "Kinzo", "Netværk Vest", "Metallica", "Daos Bistro",
    # 2.2 review: legitimate names that bare substrings used to hit
    "Salling Bank", "LexisNexis", "Nexia Danmark", "Silvana Jensen", "Meta Hansen",
    "Saxo Market Outlook", "Skat & Regnskab ApS", "Start-ups Denmark",
])
def test_brand_names_do_not_match(name):
    assert not matches("th_brand_names.re", name)


def test_brand_domains_are_registrable_domains_with_own_domains():
    doms = map_entries("th_brand_domains.map")
    assert len(doms) == len(set(doms))
    for d in doms:
        assert re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d), d
        assert not d.startswith(("www.", "mail.", "email.")), d
        assert d.count(".") == 1 or d.endswith(".co.uk"), d
    for d in ("molt.example", "bynet.example", "postnord.com", "postnord.dk", "mobilepay.dk", "easypark.net",
              "skat.dk", "e-boks.dk", "apple.com", "microsoft.com", "facebookmail.com",
              # 2.2 review: legitimate relatives of brands whose name they carry
              "coop365.dk", "betalingsservice.dk", "bring.se", "mobilepay.fi", "aws.com", "amazonaws.com"):
        assert d in doms, d
    assert "vexar.example" not in doms


@pytest.mark.parametrize("name,hit", [
    ("ΕasyΡark", True),            # Greek capital Epsilon / Rho
    ("Iոѕtagram_Support", True),   # Armenian vo + Cyrillic dze
    ("Рaypal", True),              # Cyrillic Er
    ("ɢoogle", True),              # IPA small capital G
    ("Søren Ærø", False),
    ("José Müller", False),
    ("Łukasz Żółć", False),
    ("Inge Molt", False),
])
def test_homoglyph_map(name, hit):
    assert matches("th_homoglyph.re", name) is hit


@pytest.mark.parametrize("subject", [
    "Dit betalingskort er udløbet",
    "DIT BETALINGSKORT ER UDLØBET",
    "Din pakke returneres om 3 hverdage – opdater adresse",
    "Problem med din seneste betaling.",
    "Vi mangler stadig din betaling [#7147428]",
    "Betaling kunne ikke gennemføres – opdater dine betalingsoplysninger",
    "din konto er sat på hold: Betalingsverifikation påkrævet",
    "📬 Forsendelsesmeddelelse – handling påkrævet 69208",
    "Hurtig handling påkrævet: Bekræft din pakke for at undgå returnering",
    "Vigtig opdatering vedrørende tilknyttede konti",
    "Vi har tilbagebetalt din ordre - Referencenummer: 123",
    "Dit særlige Makita-tilbud venter på dig",
    "En særlig makita-gave kun til dig",
    "Din gratis gave fra Harald Nyborg venter",
    "1. rykker inkl. inkassovarsel #1006914",
    "Your Spotify Premium payment needs attention",
    "Payment method update required",
    "Your storage is full",
    "Account suspended",
])
def test_lure_subjects_match(subject):
    assert matches("th_lure_subjects.re", subject)


@pytest.mark.parametrize("subject", [
    "Ordrebekræftelse #1234", "Månedsfaktura", "Faktura 2026-10 fra Datamail",
    "Fødselsdagen fortsætter", "Nyhedsbrev oktober", "Middag på lørdag", "RE: tilbud på tag",
    "Generalforsamling", "Din ordre er afsendt",
])
def test_lure_subjects_do_not_match(subject):
    assert not matches("th_lure_subjects.re", subject)


@pytest.mark.parametrize("domain", [
    "lastchance.guru", "fast-foode.homes", "zoo-friends.help", "zelo-hotel.xyz",
    "loms.jambyl.su", "sofia000.fun", "x.top", "a.b.icu", "Promo.XYZ",
])
def test_abused_tlds_hit(domain):
    assert matches("th_abused_tlds.re", domain)


@pytest.mark.parametrize("domain", [
    "vexar.example", "mail.vexar.example", "molt.example", "x.cloud", "y.life", "z.delivery",
    "guru.dk", "xyz.com", "help.dk", "homes.co.uk", "company.online",
])
def test_abused_tlds_miss(domain):
    assert not matches("th_abused_tlds.re", domain)


def test_abused_tld_list_never_contains_legit_tlds():
    (entry,) = map_entries("th_abused_tlds.re")
    tlds = set(re.search(r"\(([^)]*)\)", entry).group(1).split("|"))
    assert not tlds & {"shop", "cloud", "life", "delivery", "dk", "com", "net", "org", "eu", "cn", "ru"}
    assert {"homes", "guru", "help", "su", "xyz", "vip", "top", "icu"} <= tlds


@pytest.mark.parametrize("domain,hit", [
    ("factory-parts.cn", True), ("lime.stransauto.ru", True), ("x.com.cn", True),
    ("cnn.com", False), ("ru.dk", False), ("molt.example", False),
])
def test_cn_ru_map(domain, hit):
    assert matches("th_tld_cn_ru.re", domain) is hit


def test_brand_names_header_documents_the_working_multimap_type():
    head = (MAPS_D / "th_brand_names.re").read_text(encoding="utf-8").split("\n/", 1)[0]
    assert "type=header" in head and "header=From" in head
    assert "type=from, extract_from" not in head
    assert re.search(r'TH_FROM_BRAND_NAME \{[^}]*type = "header";', (LOCAL_D / "multimap.conf").read_text(), re.S)


# ---------------------------------------------------------------- 2.6 A1: brand in the subject

def test_regexp_maps_never_put_ascii_word_boundaries_next_to_danish_letters():
    """rspamd compiles map regexps with PCRE UTF but without UCP: \\b and \\w
    are ASCII-only there, so '\\børsted' can never match (Python's re is
    Unicode-aware and would hide that)."""
    for p in MAPS_D.glob("*.re"):
        for e in map_entries(p.name):
            assert not re.search(r"\\b[^\x00-\x7f]|[^\x00-\x7f]\\b", e), (p.name, e)


SUBJECT_BRAND_HITS = [
    "EasyPark AB-Opdater dine betalingsoplysninger",
    "Vigtig Information: Forbind din MobilePay til MitID",
    "Din medlemsbonus fra Tryg er på vej",
    "Saphe - betalingen kunne ikke gennemføres",
    "[PostNord] Fuldfør venligst dine oplysninger om pakke",
    "Danske Bank: bekræft dine kontooplysninger", "Nordea", "Jyske Bank", "Sydbank", "Lunar",
    "Arbejdernes Landsbank", "Spar Nord", "Nykredit", "Realkredit Danmark", "Alka", "Topdanmark",
    "Codan", "Gjensidige", "If Skadeforsikring", "TDC Erhverv", "YouSee", "Telenor", "Telia",
    "3 Danmark", "Norlys", "Andel Energi", "Ørsted: din regning", "EWII", "DSB", "Rejsekort",
    "e-Boks", "SKAT: du har penge til gode", "Skattestyrelsen", "Netflix", "Apple ID", "Microsoft 365",
    "UPS", "GLS", "DHL Express", "Bring", "DAO", "Netto", "Føtex", "MitID", "Klarna", "PayPal", "Vipps",
]


@pytest.mark.parametrize("subject", SUBJECT_BRAND_HITS)
def test_subject_brands_match(subject):
    assert matches("th_subject_brands.re", subject)


@pytest.mark.parametrize("subject", [
    "Din ordre er afsendt", "Ugens tilbud", "Møde i morgen", "Faktura fra Gravisk",
    "Tryggve har delt et album", "Tryg betaling med kort", "Køb trygt hos os", "Tryghed i hjemmet",
    "Hej skat, ses vi i aften?", "Skat & Regnskab ApS: årsrapport", "Betaling netto 8 dage",
    "Nettopris på tilbud", "Ups! Noget gik galt", "Tre gode grunde til at komme", "If you missed it",
    "Bring din ven med", "Basketball nets til salg", "Peter Ørstedsvej 4", "Ørstedparken",
    "Appleby Garden", "Salling Bank årsmøde", "Middag på lørdag", "Generalforsamling",
    "Lunarstorm-genforening", "Top 3 Danmarks bedste strande",
])
def test_subject_brands_do_not_match(subject):
    assert not matches("th_subject_brands.re", subject)


def _esld(domain: str) -> str:
    parts = domain.lower().split(".")
    return ".".join(parts[-3:] if domain.endswith(".co.uk") else parts[-2:])


def subject_spoof(subject: str, from_domain: str, *, display: str = "", freemail: bool = False) -> bool:
    """Python model of the TH_SUBJECT_BRAND_SPOOF composite (expression
    taken from composites.conf; '&' '|' '!' -> and / or / not)."""
    brand_domain = _esld(from_domain) in set(map_entries("th_brand_domains.map"))
    brand_name = bool(display) and matches("th_brand_names.re", display)
    syms = {
        "TH_SUBJECT_BRAND": matches("th_subject_brands.re", subject),
        "TH_LURE_SUBJECT": matches("th_lure_subjects.re", subject),
        "TH_LURE_SUBJECT_STRONG": matches("th_lure_subjects_strong.re", subject),
        "TH_FROM_BRAND_DOMAIN": brand_domain,
        "FREEMAIL_FROM": freemail,
        "TH_BRAND_SPOOF": brand_name and not brand_domain,
    }
    expr = opt(blocks("composites.conf")["TH_SUBJECT_BRAND_SPOOF"], "expression")
    py = re.sub(r"[A-Z][A-Z0-9_]+", lambda m: f"syms[{m.group(0)!r}]", expr)
    py = py.replace("&", " and ").replace("|", " or ").replace("!", " not ")
    return bool(eval(py, {"syms": syms}))  # noqa: S307 - test-only, our own config text


@pytest.mark.parametrize("subject,domain", [
    # Real phishing that slipped through in 2.5 (brand only in the subject).
    ("EasyPark AB-Opdater dine betalingsoplysninger", "send.reviewmgr.com"),
    ("Vigtig Information: Forbind din MobilePay til MitID", "bestair.w4l.club"),
    ("Din medlemsbonus fra Tryg er på vej", "privatelelmiszernagyfuged.hu"),
    ("Saphe - betalingen kunne ikke gennemføres", "mail-saphe-dk.com"),
    ("[PostNord] Fuldfør venligst dine oplysninger om pakke", "track-pn.info"),
])
def test_real_subject_phishing_hits_the_composite(subject, domain):
    assert subject_spoof(subject, domain)


def test_subject_composite_exemptions():
    # The brand's own domain (or a subdomain of it) is never a spoof.
    assert not subject_spoof("Din medlemsbonus fra Tryg er på vej", "tryg.dk")
    assert not subject_spoof("Saphe - betalingen kunne ikke gennemføres", "mail.saphe.com")
    assert not subject_spoof("EasyPark: opdater dine betalingsoplysninger", "easypark.net")
    # Brand domains that are freemail (outlook.com for Microsoft) do not exempt.
    assert subject_spoof("MobilePay: betalingen kunne ikke gennemføres", "outlook.com", freemail=True)
    # A brand without a lure, or a lure without a brand: 0 points from here.
    assert not subject_spoof("Nyt fra PostNord: vores åbningstider i julen", "nyhedsbrev.dk")
    assert not subject_spoof("Betalingen kunne ikke gennemføres", "webshop.dk")
    # Display name already a brand spoof: TH_BRAND_SPOOF / TH_LURE_COMBO score it, no stacking.
    assert not subject_spoof("PostNord: din pakke kan ikke leveres", "goteamup.com", display="PostNord")


@pytest.mark.parametrize("subject", [
    # Normal order / shipping / newsletter subjects with a brand in them.
    "Din ordre er afsendt med PostNord", "Din pakke er på vej med GLS", "Ugens tilbud i Netto",
    "Spar 20 % når du betaler med MobilePay", "Ordrebekræftelse #1234 – betalt med MobilePay",
    "Oplysninger om din levering med PostNord", "Din pakke er leveret i DAO-pakkeshop",
    "Nyhedsbrev: Tryg tips til vinterdæk", "Faktura fra Gravisk – betales via Nets",
])
def test_brand_subjects_from_shops_are_not_spoofs(subject):
    assert not subject_spoof(subject, "webshop.dk")


def subject_score(subject: str, from_domain: str, **kw) -> float:
    """What the subject rules alone add: TH_LURE_SUBJECT + TH_SUBJECT_BRAND_SPOOF."""
    mm, comp = blocks("multimap.conf"), blocks("composites.conf")
    score = float(opt(mm["TH_LURE_SUBJECT"], "score")) if matches("th_lure_subjects.re", subject) else 0.0
    if subject_spoof(subject, from_domain, **kw):
        score += float(opt(comp["TH_SUBJECT_BRAND_SPOOF"], "score"))
    return score


@pytest.mark.parametrize("subject", [
    # Legitimate brand subjects with a generic lure, from a third party's
    # domain (a reseller, a local store, a payment provider's merchant).
    "Din refusion via MobilePay er på vej", "Handling påkrævet: din Klarna-betaling",
    "Din pakke kan ikke leveres – kontakt PostNord", "Din medlemsbonus fra Coop er på vej",
    "Udbytte fra Danske Bank er på vej", "Peter Ørsted: handling påkrævet",
])
def test_legit_brand_lure_subjects_stay_well_below_the_threshold(subject):
    assert subject_score(subject, "lokal-butik.dk") < 5.0  # thresholds 6 / 7
    if "medlemsbonus" not in subject:  # the Tryg wave: a strong lure, see th_lure_subjects_strong.re
        assert not subject_spoof(subject, "lokal-butik.dk"), subject
    # From Coop's own chains the member bonus is never a spoof.
    assert not subject_spoof("Din medlemsbonus fra Coop er på vej", "superbrugsen.dk")


@pytest.mark.parametrize("subject", [
    "Peter Ørsted: handling påkrævet", "Re: møde med Peter Ørsted", "H.C. Ørsted Gymnasiet: skolestart",
    "Hans Christian Ørsted-prisen", "Ørstedsvej 4", "Ørstedparken",
])
def test_orsted_as_a_name_is_not_the_brand(subject):
    assert not matches("th_subject_brands.re", subject)


@pytest.mark.parametrize("subject", [
    "Ørsted: din regning", "[Ørsted] Opdater dine betalingsoplysninger", "Besked fra Ørsted",
    "Ørsted Kundeservice: din konto er spærret", "Re: Ørsted", "Faktura fra orsted.dk",
])
def test_orsted_as_the_company_is_the_brand(subject):
    assert matches("th_subject_brands.re", subject)


@pytest.mark.parametrize("subject", [
    "EasyPark AB-Opdater dine betalingsoplysninger", "Vigtig Information: Forbind din MobilePay til MitID",
    "Din medlemsbonus fra Tryg er på vej", "Saphe - betalingen kunne ikke gennemføres",
    "Ubetalt fragt på din forsendelse", "Din konto er spærret", "Bekræft din identitet",
    "Opdater venligst din betalingsmetode", "Verificer din konto",
])
def test_strong_lures_match_and_are_also_plain_lures(subject):
    assert matches("th_lure_subjects_strong.re", subject)
    assert matches("th_lure_subjects.re", subject)


@pytest.mark.parametrize("subject", [
    "Din refusion er på vej", "Udbytte er på vej", "Din bonus er på vej", "Handling påkrævet",
    "Din pakke kan ikke leveres", "Forsendelsen kræver handling påkrævet", "1. rykker – sagen går til inkasso",
    "Tilbagebetaling af depositum", "Toldgebyr for din pakke", "Du har vundet",
])
def test_generic_lures_are_not_strong(subject):
    assert matches("th_lure_subjects.re", subject)
    assert not matches("th_lure_subjects_strong.re", subject)


def test_every_strong_lure_pattern_is_also_a_plain_lure_pattern():
    plain = set(map_entries("th_lure_subjects.re"))
    for e in map_entries("th_lure_subjects_strong.re"):
        assert e in plain, e


@pytest.mark.parametrize("name", [
    "Tryg", "Tryg Forsikring", "Alka", "Alka Forsikring", "If", "If Skadeforsikring", "Topdanmark",
    "Codan Forsikring", "Gjensidige", "Nykredit", "Realkredit Danmark", "Arbejdernes Landsbank",
    "3", "3 Danmark", "Andel Energi", "Ørsted", "Ørsted Kundeservice", "EWII", "DSB", "Rejsekort",
])
def test_new_display_name_brands_match(name):
    assert matches("th_brand_names.re", name)


@pytest.mark.parametrize("name", [
    "Tryggve Hansen", "Tryg Alarm ApS", "Tryghedsgruppen Nyt", "Alka Sharma", "What If Studio",
    "Peter Ørsted", "H.C. Ørsted Gymnasiet", "Tre Falke Tømrer", "Johan 3D-print", "Andelsboligforeningen",
])
def test_new_display_name_brands_do_not_match(name):
    assert not matches("th_brand_names.re", name)


def test_new_brand_domains_are_listed():
    doms = set(map_entries("th_brand_domains.map"))
    for d in ("tryg.dk", "alka.dk", "topdanmark.dk", "codan.dk", "gjensidige.dk", "if.dk", "nykredit.dk",
              "rd.dk", "al-bank.dk", "3.dk", "andelenergi.dk", "orsted.dk", "ewii.dk", "dsb.dk",
              "rejsekort.dk", "saphe.com", "easypark.net", "danskebank.dk", "sparnord.dk"):
        assert d in doms, d


@pytest.mark.parametrize("subject", [
    "Opdater dine betalingsoplysninger", "Opdater venligst din betalingsmetode",
    "Bekræft dine kontooplysninger", "Verificer venligst dine kontooplysninger",
    "Forbind din MobilePay til MitID", "Tilknyt din konto til MitID",
    "Bekræft din identitet", "Verificer din konto", "Din konto vil blive lukket",
    "Fuldfør venligst dine oplysninger om pakke", "Ubetalt fragt på din forsendelse",
    "Din medlemsbonus fra Tryg er på vej", "Din refusion er på vej", "1. rykker – sagen går til inkasso",
])
def test_new_lure_subjects_match(subject):
    assert matches("th_lure_subjects.re", subject)


@pytest.mark.parametrize("subject", [
    "Din pakke er på vej", "Din ordre #1234 er på vej", "Oplysninger om din levering",
    "Bekræft din e-mailadresse", "Bekræft din konto", "Bekræftelse: kontoen er oprettet",
    "Opdater din app", "Forbindelsen til MitID er genoprettet", "Ugens tilbud", "Møde i morgen",
    "Din pakke er leveret", "Faktura fra Gravisk", "Velkommen som medlem",
])
def test_new_lure_subjects_do_not_match(subject):
    assert not matches("th_lure_subjects.re", subject)


# ---------------------------------------------------------------- 2.6 A5: Phishing Army feed

def _phisharmy() -> str:
    return blocks("multimap.conf")["TH_PHISHARMY_URL"]


def _phisharmy_host_filter() -> re.Pattern:
    flt = opt(_phisharmy(), "filter")
    assert flt.startswith("regexp:")
    return pcre(flt[len("regexp:"):])


def feed_checks(host: str) -> bool:
    """Python model of rspamd's 'regexp:' URL filter: the host is looked
    up in the feed only when the pattern returns it (whole match)."""
    m = _phisharmy_host_filter().search(host)
    return bool(m) and m.group(0) == host


def test_phisharmy_rule_definition():
    blk = _phisharmy()
    assert opt(blk, "type") == "url"
    assert float(opt(blk, "score")) == 3.0  # well below the thresholds 6 / 7
    assert opt(blk, "one_shot") == "true" and opt(blk, "group") == "spamfilter_own"
    m = re.search(r"^\s*map\s*=\s*\{(.*?)^\s*\};", blk, re.M | re.S)
    assert m, "map must be an object (url + poll)"
    assert re.search(r'^\s*url = "https://phishing\.army/download/phishing_army_blocklist\.txt";$', m.group(1), re.M)
    poll = int(re.search(r"^\s*poll = (\d+);$", m.group(1), re.M).group(1))
    assert 12 * 3600 <= poll <= 24 * 3600  # polite; rspamd caps it at 8 h with Last-Modified
    flt = opt(blk, "filter")
    # UCL: "$" would start a variable, a backslash an escape sequence.
    assert "$" not in flt and "\\" not in flt


def test_phisharmy_is_url_reputation_but_not_hard_phishing_evidence():
    engine = _filter_module("filter")
    contacts = _filter_module("contacts")
    services = _filter_module("services")
    sym = "TH_PHISHARMY_URL"
    assert not sym.startswith("PHISHED_")  # the PHISHED_ prefix means hard phishing evidence
    assert sym not in engine.THREAT_PHISH
    assert engine.classify_threat([sym]) == (None, None)
    # URL reputation: blocks the B2 own-platform offset, rescans may catch a late listing.
    assert engine.url_reputation_hits([sym]) == [sym]
    assert sym in engine.reputation_symbols([sym])
    # ... but no ham guard, no lost known-contact bonus, no Bayes repair.
    assert sym not in engine.HAM_GUARD_SYMBOLS and not sym.startswith(engine.HAM_GUARD_PREFIXES)
    assert not sym.startswith(contacts.HARD_EXCEPTION_PREFIXES)
    assert services._repair_hits({sym}) == []
    assert engine.ham_guard_reason(None, "a", symbols=[{"n": sym, "s": 3.0}], final=3.0,
                                   rspamd_score=3.0) is None


def test_phisharmy_never_checks_owner_hosts_or_platform_roots():
    excluded = {re.match(r"https://([^/]+)/$", e).group(1) for e in map_entries("phishing_feed_exclusion.inc")}
    roots = {"hubs.ly", "conta.cc", "dub.sh", "wixsite.com", "www.wixsite.com", "bit.ly", "t.co", "mailchi.mp",
             "list-manage.com", "sites.google.com", "molt.example", "www.bynet.example", "VEXAR.EXAMPLE"}
    for host in excluded | roots:
        assert not feed_checks(host), host


@pytest.mark.parametrize("host", [
    "evil-login.com", "www.evil-login.com", "mitid-verify.top", "evil.wixsite.com", "x.us1.list-manage.com",
    "shop.vexar.example", "gravisk.example.evil.com", "vexar.example-login.com", "hubs.lyx.com", "tco.example",
    "amiprotected.it",
])
def test_phisharmy_checks_other_hosts(host):
    assert feed_checks(host)


# ---------------------------------------------------------------- 2.6: UI texts

def test_every_own_rspamd_symbol_has_a_danish_text():
    """The UI must never show a raw rule name for our own rules."""
    kit = _filter_module("ui_kit")
    own = set(blocks("multimap.conf")) | set(blocks("composites.conf"))
    for sym in own:
        text_ = kit.explain_symbol(sym)
        assert sym in kit.SYMBOL_TEXT and "_" not in text_, sym
    for sym in ("TH_SUBJECT_BRAND_SPOOF", "TH_PHISHARMY_URL"):
        assert kit.plain_reason(sym)
    for sym in ("TH_SUBJECT_BRAND", "TH_LURE_SUBJECT_STRONG", "TH_GOOGLE_RELAY_ENV"):
        assert kit.plain_reason(sym) is None  # score 0, never a reason by itself
    spoof = {"n": "TH_SUBJECT_BRAND_SPOOF", "s": 2.5, "o": []}
    assert kit.explain_symbol_detail(spoof, sender="Info <x@privatelelmiszernagyfuged.hu>").endswith(
        "men mailen kommer fra privatelelmiszernagyfuged.hu")
    assert kit.explain_symbol_detail(spoof) == kit.SYMBOL_TEXT["TH_SUBJECT_BRAND_SPOOF"]
    pa = kit.explain_symbol_detail({"n": "TH_PHISHARMY_URL", "s": 3.0, "o": ["mitid-verify.top"]})
    assert pa == "Link til mitid-verify.top, som står på en liste over phishing-sider (Phishing Army)"


# ---------------------------------------------------------------- 2.7: ClamAV

def _antivirus_rule() -> str:
    text = (LOCAL_D / "antivirus.conf").read_text(encoding="utf-8")
    m = re.search(r"^clamav\s*\{(.*?)^\}", text, re.M | re.S)
    assert m, "clamav { } rule missing"
    return m.group(1)


def test_antivirus_conf_is_a_fail_open_clamav_rule_on_the_unix_socket():
    assert "antivirus.conf" in sf_rspamd_files()
    text = (LOCAL_D / "antivirus.conf").read_text(encoding="utf-8")
    assert braces_balanced(text)
    rule = _antivirus_rule()
    assert opt(rule, "type") == "clamav"
    assert opt(rule, "servers") == "/run/spamfilter/clamav/clamd.sock"  # no host:port, no TCP
    assert opt(rule, "symbol") == "CLAM_VIRUS" and opt(rule, "symbol_fail") == "CLAM_VIRUS_FAIL"
    assert opt(rule, "scan_mime_parts") == "true"
    assert 10_000_000 <= int(opt(rule, "max_size")) <= 25_000_000
    # one try, well inside rspamd's 8 s task timeout (options.inc)
    assert float(opt(rule, "timeout")) * (1 + int(opt(rule, "retransmits"))) < 8
    code = re.sub(r"#.*", "", text)
    # post-delivery filtering: no SMTP action, no reject, no score here; the engine decides
    for word in ("action", "reject", "score", "whitelist", "patterns"):
        assert not re.search(rf"^\s*{word}\s*=", code, re.M), word
    assert "CLAM_VIRUS" not in group_weights() and "CLAM_VIRUS_FAIL" not in group_weights()


def test_clamav_symbols_map_to_the_virus_threat_and_the_fail_symbol_is_no_verdict():
    eng = _filter_module("filter")
    kit = _filter_module("ui_kit")
    rule = _antivirus_rule()
    hit, fail = opt(rule, "symbol"), opt(rule, "symbol_fail")
    assert hit in eng.THREAT_VIRUS
    sig = [{"n": hit, "s": 0.0, "o": ["Win.Test.EICAR_HDB-1"]}]
    assert eng.classify_threat({hit}, sig) == ("virus", "Win.Test.EICAR_HDB-1")
    # a virus is never force-passable (no 'Altid igennem', never released by a plain user)
    assert "virus" not in eng.THREAT_FORCE_PASSABLE
    assert hit in eng.HAM_GUARD_SYMBOLS
    # clamd down / too slow: no threat, no URL reputation, no zap knowledge, no spam reason
    assert eng.classify_threat({fail}) == (None, None)
    assert eng.url_reputation_hits([fail]) == [] and eng.reputation_symbols([fail]) == set()
    assert kit.plain_reason(fail) is None
    assert kit.plain_reason(hit) == kit.PLAIN_VIRUS
    for sym in (hit, fail):
        assert sym in kit.SYMBOL_TEXT and "_" not in kit.explain_symbol(sym), sym


def test_local_fuzzy_storage_worker_is_started():
    """2.7.5: rspamd 4.2 disables the fuzzy worker by default (count = -1),
    so rule "local" (127.0.0.1:11335) needs our worker-fuzzy.inc."""
    text = (LOCAL_D / "worker-fuzzy.inc").read_text()
    assert re.search(r"^count\s*=\s*1;", text, re.M)
    assert re.search(r'^backend\s*=\s*"redis";', text, re.M)
    assert re.search(r'^allow_update\s*=\s*\["127\.0\.0\.1", "::1"\];', text, re.M)
    assert "bind_socket" not in text  # loopback pin lives in the image's override.d
    assert "worker-fuzzy.inc" in sf_rspamd_files()
    assert 'servers = "127.0.0.1:11335";' in (LOCAL_D / "fuzzy_check.conf.readonly").read_text()


def test_google_relayed_freemail_phishing():
    """2.7.6: unknown Gmail senders relayed by maestro.bounces.google.com
    (4 of 4 seen were account/file phishing). Known contacts keep their
    -2..-4 trust bonus from the filter, so a friend's share stays below 6."""
    mm = (LOCAL_D / "multimap.conf").read_text()
    block = mm[mm.index("TH_GOOGLE_RELAY_ENV {"):]
    block = block[:block.index("}") + 1]
    assert 'type = "from";' in block and 'extract_from = "smtp";' in block and "score = 0.0;" in block
    assert map_entries("th_google_relay_env.map") == ["maestro.bounces.google.com"]
    comp = (LOCAL_D / "composites.conf").read_text()
    c = comp[comp.index("TH_FREEMAIL_VIA_GOOGLE {"):]
    c = c[:c.index("}") + 1]
    assert 'expression = "TH_GOOGLE_RELAY_ENV & FREEMAIL_FROM";' in c and "score = 7.0;" in c
