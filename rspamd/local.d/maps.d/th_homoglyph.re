# spamfilter 2.2 (B3): IPA, Greek, Cyrillic, Armenian and Coptic code points
# in the From DISPLAY NAME ("ΕasyΡark" with Greek capitals). Multimap
# TH_FROM_NAME_HOMOGLYPH (+5.0). A genuine Greek or Cyrillic personal
# name would also hit (none in 15,000 production headers); use an allow
# rule for such a sender.
/[\x{0250}-\x{02AF}\x{0370}-\x{03FF}\x{0400}-\x{04FF}\x{0530}-\x{058F}\x{2C80}-\x{2CFF}]/u
