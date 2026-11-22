# 2.7.5: the filter's OWN fuzzy storage (rule "local" in fuzzy_check.conf,
# filled by filter/campaigns.py via the controller's /fuzzyadd). rspamd 4.2
# no longer starts the fuzzy worker by default (count = -1), so every scan
# asked a port nobody listened on. Hashes live in the same Redis as Bayes
# (local.d/redis.conf); the bind stays on loopback (override.d pin in the
# all-in-one image); only the host itself may add or remove hashes.
count = 1;
backend = "redis";
expire = 90d;
allow_update = ["127.0.0.1", "::1"];
