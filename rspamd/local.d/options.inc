# All DNS goes through the in-stack Unbound (spamfilter-unbound), which
# caches and forwards to the LAN resolver 192.168.1.1 (the only resolver
# reachable from the spamnet bridge). That forwarder can be slow on cold
# lookups, so each try waits longer and retries less: worst case is about
# 2 s x (1 + 2 retransmits), well inside rspamd's task timeout. More
# concurrent requests per task keep URL/RBL-heavy mails from being cut off.
dns_max_requests = 128;
# 2.12 (#25): rspamd's default task timeout (8 s) is shorter than what one
# heavy mail can legitimately need (DNS ~6 s, ClamAV 6 s, URL redirector,
# neural, fuzzy - up to ~21 s seen): such a task was cut off without all
# symbols. 25 s stays below the filter's own HTTP timeout (30 s).
task_timeout = 25s;
dns {
    nameserver = ["spamfilter-unbound"];
    timeout = 2s;
    sockets = 16;
    retransmits = 2;
}
