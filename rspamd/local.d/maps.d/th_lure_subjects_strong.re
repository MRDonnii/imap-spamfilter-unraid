# spamfilter 2.6 (A1): the STRONG lures - a subset of th_lure_subjects.re
# (every subject here also hits TH_LURE_SUBJECT, test-enforced). Multimap
# TH_LURE_SUBJECT_STRONG scores 0; it only counts through the composite
# TH_SUBJECT_BRAND_SPOOF (brand in the subject + strong lure + a sender
# that is not the brand's own domain).
# Only subjects that ASK for payment/account details, identity or MitID,
# or claim a failed payment, unpaid freight or a blocked account. Never
# the generic lures that shops, banks and carriers send legitimately:
# "... er på vej" (refusion, udbytte, bonus), "handling påkrævet",
# "pakken kan ikke leveres", refunds, debt collection.
# One PCRE per line; never a literal space or "#" inside a pattern: use \s.
# Payment details and failed payments
/opdater\S*\s+(venligst\s+)?(dine\s+|din\s+)?(betalings|kort|konto)(oplysninger|metode|kort)/iu
/(bekræft|bekræfte|verificer|verificere|fuldfør|fuldføre)\s+(venligst\s+)?(dine\s+)?kontooplysninger/iu
/fuldfør(e)?\s.{0,40}?oplysninger/iu
/betalingskort\s+er\s+udløbet/iu
/betaling(en)?\s+(kunne\s+ikke|mislykkedes|er\s+afvist|fejlede)/iu
/payment\s+(method\s+)?(has\s+expired|failed|update\s+required|needs\s+attention)/iu
/ubetalt\s+(fragt|told|gebyr|forsendelsesgebyr)/iu
# Account, identity, MitID
/konto(en)?\s+er\s+(sat\s+på\s+hold|låst|spærret|suspenderet)/iu
/konto(en)?\s+(vil\s+blive|bliver)\s+(lukket|deaktiveret|spærret|suspenderet|slettet)/iu
/account\s+(suspended|on\s+hold|locked)/iu
/(forbind|forbinde|tilknyt|tilknytte|knyt|link)\s+(venligst\s+)?(din|dit|jeres)\s.{1,40}?(til|med)\s+mit\s*id/iu
/(bekræft|bekræfte|verificer|verificere)\s+(venligst\s+)?din\s+identitet/iu
/(verificer|verificere)\s+(venligst\s+)?din\s+konto/iu
# Member bonus: the insurance phishing wave ("Din medlemsbonus fra Tryg er
# på vej" from a .hu domain). A genuine bonus mail comes from the brand's
# own domain (th_brand_domains.map), which exempts it from the composite.
/medlemsbonus/iu
