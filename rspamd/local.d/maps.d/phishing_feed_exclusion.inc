# spamfilter 2.2 (B5): hosts that are never reported as PHISHED_OPENPHISH /
# PHISHED_PHISHTANK (they get PHISHED_EXCLUDED, weight 0, instead).
# rspamd parses each line as a URL and compares the EXACT host, so www.
# variants are listed separately. The owner's own hosts (webshops and the
# platform root of the local site config, config/site.yml) are added to the
# rendered copy at container start (deploy/aio/aio_render.py); sub-shops on a
# multi-tenant platform (<shop>.<platform>) are deliberately NOT excluded.
