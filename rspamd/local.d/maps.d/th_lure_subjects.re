# spamfilter 2.2 (B3): Danish/English payment, parcel, account and prize
# lures in the Subject. Multimap TH_LURE_SUBJECT: only +1.5 on its own
# (Klarna, Nabu Casa, Likvido ... send such subjects legitimately); +4.0
# more via the composite TH_LURE_COMBO when the sender is also a brand
# spoof, a homoglyph name or an abused TLD. 2.6 (A1): the strong subset
# (th_lure_subjects_strong.re, keep in sync) adds +2.5 via
# TH_SUBJECT_BRAND_SPOOF when the subject itself names a brand
# (th_subject_brands.re) and the sender is not the brand's own domain.
# A lure here must never be a normal order / shipping notification
# ("Din ordre er afsendt", "Oplysninger om din levering").
# One PCRE per line; never a literal space or "#" inside a pattern: use \s.
# Payment
/betalingskort\s+er\s+udløbet/iu
/betaling(en)?\s+(kunne\s+ikke|mislykkedes|er\s+afvist|fejlede)/iu
/problem\s+med\s+din\s+(seneste\s+)?betaling/iu
/opdater\s+(dine\s+)?(betalings|kort)oplysninger/iu
/betalingsverifikation/iu
/mangler\s+stadig\s+din\s+betaling/iu
# 2.6 (A1): real Danish brand-in-subject phishing
/opdater\S*\s+(venligst\s+)?(dine\s+|din\s+)?(betalings|kort|konto)(oplysninger|metode|kort)/iu
/(bekræft|bekræfte|verificer|verificere|fuldfør|fuldføre)\s+(venligst\s+)?(dine\s+)?kontooplysninger/iu
/payment\s+(method\s+)?(has\s+expired|failed|update\s+required|needs\s+attention)/iu
/renewal\s+issue/iu
# Subscription and account
/abonnement(et)?\s+er\s+(sat\s+på\s+pause|suspenderet|udløbet)/iu
/konto(en)?\s+er\s+(sat\s+på\s+hold|låst|spærret|suspenderet)/iu
/account\s+(suspended|on\s+hold|locked)/iu
/your\s+(storage|cloud|files).*(full|deleted|deletion|syncing)/iu
/vigtig\s+opdatering\s+vedrørende/iu
/(forbind|forbinde|tilknyt|tilknytte|knyt|link)\s+(venligst\s+)?(din|dit|jeres)\s.{1,40}?(til|med)\s+mit\s*id/iu
/(bekræft|bekræfte|verificer|verificere)\s+(venligst\s+)?din\s+identitet/iu
/(verificer|verificere)\s+(venligst\s+)?din\s+konto/iu
/konto(en)?\s+(vil\s+blive|bliver)\s+(lukket|deaktiveret|spærret|suspenderet|slettet)/iu
# Parcel and customs
/bekræft\s+(din|modtagelsen\s+af\s+din)\s+pakke/iu
/pakke(n)?\s+(returneres|tilbageholdes|kan\s+ikke\s+leveres)/iu
/leveringsundtagelse/iu
/forsendelse(n)?\s.*?(handling\s+påkrævet|kontrol)/iu
/handling\s+påkrævet/iu
/toldgebyr/iu
/fuldfør(e)?\s.{0,40}?oplysninger/iu
/ubetalt\s+(fragt|told|gebyr|forsendelsesgebyr)/iu
# Debt collection and refunds
/rykker\s.*inkasso/iu
/inkassovarsel/iu
/tilbagebetal(t|ing)/iu
# Prizes and gifts
/(gave|tilbud|præmie|værktøjssæt)\S*.{0,30}(venter|kun\s+til\s+dig)/iu
/du\s+kan\s+modtage\s+(et|en)/iu
/du\s+har\s+vundet/iu
/medlemsbonus/iu
/(bonus|refusion|tilbagebetaling|udbytte)\s.{0,30}?(er\s+)?på\s+vej/iu
