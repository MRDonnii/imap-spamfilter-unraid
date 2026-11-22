# spamfilter 2.6 (A1): brand names in the SUBJECT (multimap
# TH_SUBJECT_BRAND, type=header, header=Subject). A hit alone scores 0; it
# only counts through the composite TH_SUBJECT_BRAND_SPOOF = brand in the
# subject AND a strong lure subject (th_lure_subjects_strong.re) AND the
# From domain is not in th_brand_domains.map. Phishing that keeps the brand out of the
# display name: "EasyPark AB-Opdater dine betalingsoplysninger" from
# send.reviewmgr.com, "Din medlemsbonus fra Tryg er på vej" from a .hu
# domain.
#
# A separate list, not th_brand_names.re: several display-name patterns
# are anchored ^...$ (Apple, Outlook, SKAT, Meta) and never match inside a
# sentence, and a subject is free text, so words that are only safe as a
# whole display name need extra care here:
#  - Danish words: "skat" (tax / darling), "tryg" (safe), "netto" (net
#    amount, "netto 8 dage" in every dunning letter), "tre" (three), "ups"
#    (oops), "if", "bring" ("Bring din ven med"), "nets". These are
#    case-sensitive (no "i" flag) or need a qualifier ("3 Danmark",
#    "If Forsikring") or a lookahead.
#  - rspamd compiles these with PCRE UTF but without UCP: \b and \w are
#    ASCII-only. Never put \b next to æ/ø/å (it would never match): use
#    (?<![a-zæøå0-9]) / (?![a-zæøå0-9]) instead (test-enforced).
# One PCRE per line, /pattern/flags ("i" = case-insensitive, "u" = UTF-8).
# Never use a literal space or "#" inside a pattern (map syntax): write \s.
# Parcel carriers
/post\s*nord/iu
/\bgls\b/iu
/\bDAO\b|\bdao365\b/u
/\bBring\b(?!\s+(din|dit|dine|en|et|jer|os|dem|med|a|an|the|your|me|it|us|them|back|home|friends?)\b)/u
/\bdhl\b/iu
/\bUPS\b/u
/fed\s*ex/iu
# Parking, tolls, transport, payments
/easy\s*park/iu
/brobizz/iu
/\bsaphe\b/iu
/\bDSB\b|rejsekort/iu
/mobile\s*pay|\bvipps\b/iu
/\bNets\b/u
/dankort|\bnexi\b/iu
/paypal/iu
/klarna/iu
# Public sector, identity
/e-?boks/iu
/\bmit\s*id\b|\bnem\s*id\b/iu
/skattestyrelsen|\bskat\.dk\b/iu
/\bSKAT\b/u
/borger\.dk|digital\s*post|\bmit\.dk\b/iu
# Streaming, IT, social
/netflix/iu
/spotify/iu
/\bapple\b|icloud/iu
/microsoft|office\s*365|\boutlook\b/iu
/instagram|facebook/iu
/godaddy/iu
/punktum\.dk|dk\s*hostmaster/iu
/amazon/iu
/\btemu\b/iu
# Retail (gift / prize lures)
/zalando/iu
/\bsilvan\b/iu
/harald\s*nyborg/iu
/jem\s*&?\s*fix/iu
/bauhaus/iu
/elgiganten/iu
/\bikea\b/iu
/\bmakita\b/iu
/\bcoop\b/iu
/\bsalling\b(?!\s*bank)|\bbilka\b|f[øo]tex/iu
/\b(Netto|NETTO)\b(?!\s*\d)/u
# Banks
/nordea/iu
/danske\s*bank/iu
/jyske\s*bank/iu
/sydbank/iu
/spar\s*nord/iu
/djurslands\s*bank/iu
/\blunar\b/iu
/arbejdernes\s*landsbank|\bal-bank\b/iu
/nykredit/iu
/realkredit\s*danmark/iu
# Insurance. "Tryg" only with a capital T and not as the adjective in
# front of a noun ("Tryg betaling", "Tryg handel"); \b keeps "Tryghed",
# "trygt" and the first name "Tryggve" out.
/\bTryg\b(?!\s+(betaling|handel|levering|køb|e-?handel)(?![a-zæøå]))|\bTRYG\b/u
/\balka\b/iu
/topdanmark/iu
/\bcodan\b/iu
/gjensidige/iu
/\bIf\s+(Skadeforsikring|Forsikring|forsikring|Insurance)\b|\bif\.dk\b/u
# Telecom and energy
/telenor|\btelia\b|yousee|\bnorlys\b|\btdc\b/iu
/\b3\s*danmark\b|\b3\.dk\b/iu
/andel\s*energi/iu
# Ørsted only as the company, never a person's or a street's name ("Peter
# Ørsted", "H.C. Ørsted Gymnasiet", "Ørstedsvej"): at the start of the
# subject, after a delimiter ("[Ørsted]", "Re: Ørsted"), after
# "fra/hos/til/af/om", or with a company word after it.
/(^|[\[(|:–-]\s*|(?<![a-zæøå0-9])(fra|from|hos|til|af|om)\s+)ørsted(?![a-zæøå0-9])|orsted\.dk|ørsted\s+(salg|service|kundeservice|energi|a.s)(?![a-zæøå0-9])/iu
/\bewii\b/iu
