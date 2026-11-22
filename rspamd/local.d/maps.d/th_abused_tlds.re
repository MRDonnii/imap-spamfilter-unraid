# spamfilter 2.2 (B4): sender domains (envelope and From header) on new
# TLDs that spam campaigns rotate through every week. Multimap
# TH_FROM_ABUSED_TLD (+5.0).
# NEVER add .shop, .cloud or .life (legitimate use, e.g. shop platforms);
# .delivery was removed after a probably legitimate hit.
/\.(homes|guru|help|su|xyz|vip|top|icu|cyou|sbs|cfd|bond|rest|lol|quest|monster|buzz|autos|boats|yachts|beauty|hair|makeup|skin|mom|christmas|watch|pics|day|fun|click|gq|tk|ml|cf|ga|zip|mov|country|stream|loan|racing|win|bid|review|date|faith|party|science|cricket|accountant|men|kim|xin)$/i
