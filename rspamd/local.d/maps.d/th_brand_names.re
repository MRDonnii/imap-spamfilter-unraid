# spamfilter 2.2 (B3): brand names in the From DISPLAY NAME (multimap
# TH_FROM_BRAND_NAME, type=header, header=From, filter=email:name - see
# multimap.conf for why it must NOT be type=from: that never fires).
# One PCRE per line, /pattern/flags ("i" = case-insensitive, "u" = UTF-8).
# Never use a literal space or "#" inside a pattern (map syntax): write \s.
# A hit alone scores 0; it only counts through the composite
# TH_BRAND_SPOOF = brand name AND the From domain is NOT in
# th_brand_domains.map.
# Keep patterns word-bounded or anchored: a bare substring also hits
# unrelated names (Silvana, LexisNexis, Saxo Market Outlook, Start-ups,
# Skat & Regnskab ApS, the first name Meta, Salling Bank).
# Parcel carriers
/post\s*nord/iu
/\bgls\b/iu
/\bdao\b/iu
/\bbring\b/iu
/\bdhl\b/iu
/(?<!-)\bups\b/iu
/fed\s*ex/iu
# Parking, tolls, payments
/easy\s*park/iu
/brobizz/iu
/\bsaphe\b/iu
/mobile\s*pay|vipps/iu
/\bnets\b|dankort|\bnexi\b/iu
/paypal/iu
/klarna/iu
# Public sector, identity
/e-?boks/iu
/mit\s*id|nem\s*id/iu
/skattestyrelsen|\bskat\.dk\b|^\W*skat(\s*(danmark|online|kundeservice|support|info))?\W*$/iu
/borger\.dk|digital\s*post|mit\.dk/iu
# Streaming, IT, social
/netflix/iu
/spotify/iu
/^\W*(apple|icloud)(\s*(id|support|pay|store|kundeservice|billing|music|one|team))?\W*$/iu
/microsoft|office\s*365|^\W*outlook(\.com)?(\s*(team|support|security|account|konto|mail))?\W*$/iu
/instagram|facebook|^\W*meta(\s*(for\s*business|business|support|verified|ads|platforms|team|pay|security))?\W*$/iu
/godaddy/iu
/punktum|dk\s*hostmaster/iu
/amazon/iu
/\btemu\b/iu
/\btrustpilot\b/iu
/\bcnn\b/iu
# Retail
/zalando/iu
/\bsilvan\b/iu
/harald\s*nyborg/iu
/jem\s*&?\s*fix/iu
/bauhaus/iu
/elgiganten/iu
/\bikea\b/iu
/\bmakita\b/iu
/\bcoop\b/iu
/\bsalling\b(?!\s*bank)|\bbilka\b|\bnetto\b|f[øo]tex/iu
# Banks
/nordea/iu
/danske\s*bank/iu
/jyske\s*bank/iu
/sydbank/iu
/spar\s*nord/iu
/djurslands\s*bank/iu
/\blunar\b/iu
# 2.6 (A1): more banks, insurance, telecom/energy and transport.
/arbejdernes\s*landsbank|\bal-bank\b/iu
/nykredit/iu
/realkredit\s*danmark/iu
# Insurance. Tryg, Alka and If are also ordinary words / first names /
# parts of small firms' names ("Tryg Alarm ApS", "Alka Sharma", "What If
# Studio"), so only the bare brand (with a service word) counts.
/^\W*tryg(\s*(forsikring|kundeservice|kundecenter|skade|danmark))?\W*$/iu
/^\W*alka(\s*(forsikring|kundeservice|kundecenter|skade))?\W*$/iu
/^\W*if(\s*(skadeforsikring|forsikring|insurance|kundeservice))?\W*$/iu
/topdanmark/iu
/\bcodan\b/iu
/gjensidige/iu
# Telecom and energy. Ørsted is a common surname ("Peter Ørsted"):
# bare brand only. rspamd's \b is ASCII-only, so no \b next to ø.
/telenor|telia|yousee|\bnorlys\b|\btdc\b/iu
/^\W*3(\s*(danmark|kundeservice))?\W*$|\b3\s*danmark\b/iu
/andel\s*energi/iu
/^\W*(ørsted|orsted)(\s*(kundeservice|kundecenter|salg|energi|danmark))?\W*$/iu
/\bewii\b/iu
# Transport
/\bdsb\b|rejsekort/iu
