"""Fake host tools for the deploy script tests (INFRA role).

`install_fake_bin(dir)` writes executable `docker`, `curl` and `notify`
stand-ins into *dir*. They keep their state in JSON files named by env
vars, so a bash script under test can be pointed at them via PATH:

- FAKE_DOCKER_STATE: {"containers": {name: {...}}, "images": [..]}
- FAKE_DOCKER_CALLS: one line per docker invocation (args joined by space)
- FAKE_NEW_HEALTH:   health status of containers created by `docker run`
- FAKE_DOCKER_EXEC:  JSON {"<container> <first exec arg>": "<stdout>"}
- FAKE_DOCKER_LOGS:  JSON {"<container>": "<log text>"}
- FAKE_CURL_BODY:    body printed by curl (unset -> curl fails, exit 7)
- FAKE_NOTIFY_LOG:   notify appends its arguments here

2.4 (all-in-one) additions:
- state "image_labels": {image: {label: value}} - shown by `image inspect`
  and inherited by containers `docker run` creates (as Docker does)
- state "networks": {name: [container, ...]} - when present, `network
  inspect/rm/create` and `ps --filter network=` use it
- container "health_log": Output of the last HEALTHCHECK run
- `docker exec` skips -u/--user/-e/-i/-t options before the container name;
  FAKE_DOCKER_EXEC keys "<container> <arg1> <arg2>" win over "<container> <arg1>"
- container "restart" (set by `run --restart` / `update --restart`) is shown
  as HostConfig.RestartPolicy.Name (default unless-stopped); "run_args" keeps
  the options `docker run` got; `kill` stops like `stop`
- FAKE_RUN_HEARTBEAT: `docker run -d` writes "<now> boot" into this file
- FAKE_CURL_MAP:     JSON {url suffix: body} (else FAKE_CURL_BODY)
- FAKE_CURL_CODES:   JSON {url suffix: code} for `curl -w %{http_code}`;
                     "<suffix>+auth" applies when a bearer token came on stdin
- FAKE_CURL_CALLS:   curl appends its argv here (token must never appear)
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

_DOCKER = r'''
import json, os, sys, time

state_path = os.environ["FAKE_DOCKER_STATE"]
with open(state_path) as fh:
    st = json.load(fh)
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_CALLS"], "a") as fh:
    fh.write(" ".join(args) + "\n")

def save():
    with open(state_path, "w") as fh:
        json.dump(st, fh)

def die(msg, rc=1):
    sys.stderr.write(msg + "\n")
    sys.exit(rc)

C = st.setdefault("containers", {})
if args and args[0] == "container":
    args = args[1:]
cmd, rest = (args[0], args[1:]) if args else ("", [])

def inspect_obj(name):
    c = C[name]
    health = {}
    if c.get("health"):
        health = {"Health": {"Status": c["health"],
                             "Log": [{"Output": c["health_log"]}] if c.get("health_log") else []}}
    return {
        "Name": "/" + name,
        "Image": "sha256:" + c["image"].replace(":", "_"),
        "RestartCount": c.get("restart_count", 0),
        "State": {"Running": c["running"], "Status": "running" if c["running"] else "exited",
                  "StartedAt": c.get("started_at", "2026-10-20T10:00:00.000000000Z"), **health},
        "Config": {"Image": c["image"], "User": c.get("user", ""), "Labels": c.get("labels", {})},
        "HostConfig": {"RestartPolicy": {"Name": c.get("restart", "unless-stopped")}},
    }

if cmd == "inspect":
    fmt = None
    if rest and rest[0] == "-f":
        fmt, rest = rest[1], rest[2:]
    name = rest[0]
    if name not in C:
        die("Error: No such container: " + name)
    obj = inspect_obj(name)
    if fmt == "{{.Image}}":
        print(obj["Image"])
    elif fmt == "{{.State.Running}}":
        print("true" if obj["State"]["Running"] else "false")
    elif fmt and "range $k, $v := .Config.Labels" in fmt:
        print("".join(f"{k}={v} " for k, v in obj["Config"]["Labels"].items()))
    elif fmt and "spamfilter.layout" in fmt:
        print(obj["Config"]["Labels"].get("spamfilter.layout", "<no value>"))
    else:
        print(json.dumps([obj]))
elif cmd == "image":
    sub, ref = rest[0], rest[-1]
    if sub == "inspect":
        if ref in st.get("images", []) or os.environ.get("FAKE_ALL_IMAGES") == "1":
            labels = st.get("image_labels", {}).get(ref, {})
            print(json.dumps([{"Id": "sha256:" + ref.replace(":", "_"), "Size": 734003200,
                               "RepoDigests": [ref.split(":")[0] + "@sha256:" + "ab" * 32],
                               "Config": {"Labels": labels, "Volumes": st.get("image_volumes", {}).get(ref)}}]))
        else:
            die("Error: No such image: " + ref)
    elif sub == "ls":
        # docker image ls --format '{{.Repository}}:{{.Tag}}' REPO
        repo = rest[-1] if len(rest) > 1 and not rest[-1].startswith("{{") else None
        for img in st.get("images", []):
            if repo is None or img.startswith(repo + ":"):
                print(img)
    elif sub == "rm":
        if ref not in st.get("images", []):
            die("Error: No such image: " + ref)
        users = [n for n, c in C.items() if c["image"] == ref]
        if users:
            die("Error response from daemon: conflict: unable to remove repository reference "
                + ref + " (must force) - container " + users[0] + " is using its referenced image")
        st["images"].remove(ref); save()
elif cmd == "info":
    print("{}")
elif cmd == "network":
    nets = st.get("networks")
    if nets is not None:
        sub, net = rest[0], rest[-1]
        if sub == "inspect":
            if net not in nets:
                die("Error: No such network: " + net)
            print(json.dumps([{"Name": net, "Containers": {}}]))
        elif sub == "rm":
            if net not in nets:
                die("Error: No such network: " + net)
            del nets[net]; save()
        elif sub == "create":
            nets[net] = []; save()
elif cmd == "pull":
    st.setdefault("images", []).append(rest[-1]); save()
elif cmd == "build":
    tag = rest[rest.index("-t") + 1] if "-t" in rest else rest[-1]
    st.setdefault("images", []).append(tag); save()
elif cmd in ("stop", "kill"):
    if rest[-1] not in C:
        die("Error: No such container: " + rest[-1])
    C[rest[-1]]["running"] = False; save()
elif cmd == "start":
    C[rest[-1]]["running"] = True; save()
elif cmd == "restart":
    C[rest[-1]]["running"] = True; save()
elif cmd == "rename":
    old, new = rest
    if new in C:
        die("Error: name in use: " + new)
    C[new] = C.pop(old); save()
elif cmd == "update":
    if "--restart" in rest and rest[-1] in C:
        C[rest[-1]]["restart"] = rest[rest.index("--restart") + 1]; save()
elif cmd == "rm":
    name = rest[-1]
    if name not in C:
        die("Error: No such container: " + name)
    del C[name]; save()
elif cmd == "run":
    opts = rest
    name, labels, user, restart, i = None, {}, "", "no", 0
    flags_with_value = {"--name", "--network", "--restart", "--stop-timeout", "--log-driver",
        "--log-opt", "-e", "--memory", "--cpus", "--pids-limit", "--user", "--cap-drop",
        "--cap-add", "--security-opt", "--health-cmd", "--health-interval", "--health-timeout",
        "--health-retries", "--health-start-period", "--health-start-interval", "-v", "-p",
        "--label", "--entrypoint", "--sysctl", "--tmpfs", "--add-host"}
    while i < len(opts):
        o = opts[i]
        if o in flags_with_value:
            v = opts[i + 1]
            if o == "--name": name = v
            if o == "--label":
                k, _, val = v.partition("="); labels[k] = val
            if o == "--user": user = v
            if o == "--restart": restart = v
            i += 2
        elif o.startswith("-"):
            i += 1
        else:
            break
    image = opts[i]
    if name is None:
        sys.exit(0)  # throwaway --rm container
    if name in C:
        die("Error: Conflict. The container name is already in use: " + name)
    labels = dict(st.get("image_labels", {}).get(image, {}), **labels)
    C[name] = {"image": image, "running": True, "labels": labels, "user": user, "restart": restart,
               "run_args": opts[:i],
               "health": os.environ.get("FAKE_NEW_HEALTH", "healthy"),
               "health_log": os.environ.get("FAKE_NEW_HEALTH_LOG", ""),
               "started_at": time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())}
    save()
    hb = os.environ.get("FAKE_RUN_HEARTBEAT")
    if hb:
        with open(hb, "w") as fh:
            fh.write(f"{int(time.time()) + 5} boot\n")
    print("0123456789ab")
elif cmd == "logs":
    print(json.loads(os.environ.get("FAKE_DOCKER_LOGS", "{}")).get(rest[-1], ""))
elif cmd == "ps":
    names = list(C)
    if "--filter" in rest:
        flt = rest[rest.index("--filter") + 1]
        if flt.startswith("network="):
            members = (st.get("networks") or {}).get(flt.split("=", 1)[1], [])
            names = [n for n in names if n in members]
    if "--format" in rest and rest[rest.index("--format") + 1] == "{{.Image}}":
        print("\n".join(C[n]["image"] for n in names))
    else:
        print("\n".join(names))
elif cmd == "exec":
    while rest and rest[0] in ("-u", "--user", "-e", "-i", "-t", "-it", "-ti"):
        rest = rest[2:] if rest[0] in ("-u", "--user", "-e") else rest[1:]
    name, first = rest[0], rest[1]
    table = json.loads(os.environ.get("FAKE_DOCKER_EXEC", "{}"))
    out = table.get(" ".join(rest[:3])) if len(rest) > 2 else None
    if out is None:
        out = table.get(name + " " + first)
    if out is None:
        sys.exit(1)
    print(out)
else:
    die("fake docker: unsupported " + " ".join(args), 2)
'''

_CURL = r'''
import json, os, sys
args = sys.argv[1:]
if os.environ.get("FAKE_CURL_CALLS"):
    with open(os.environ["FAKE_CURL_CALLS"], "a") as fh:
        fh.write(" ".join(args) + "\n")
url = next((a for a in args if a.startswith("http")), "")
auth = False
if "@-" in args:
    auth = "Bearer " in sys.stdin.read()
def lookup(env):
    table = json.loads(os.environ.get(env, "{}"))
    plain = sorted((k for k in table if not k.endswith("+auth")), key=len, reverse=True)
    for suffix in plain:
        if url.endswith(suffix):
            if auth and suffix + "+auth" in table:
                return table[suffix + "+auth"]
            return table[suffix]
    return None
body = lookup("FAKE_CURL_MAP")
if body is None:
    body = os.environ.get("FAKE_CURL_BODY")
if "-w" in args:
    code = lookup("FAKE_CURL_CODES")
    if code is None:
        code = "200" if body is not None else "000"
    sys.stdout.write(str(code))
    sys.exit(0 if code != "000" else 7)
if body is None:
    sys.stderr.write("curl: (7) Failed to connect\n")
    sys.exit(7)
print(body)
'''

_NOTIFY = r'''
import os, sys
with open(os.environ["FAKE_NOTIFY_LOG"], "a") as fh:
    fh.write("\t".join(sys.argv[1:]) + "\n")
'''


def _write_tool(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_fake_bin(bindir: Path) -> None:
    bindir.mkdir(parents=True, exist_ok=True)
    _write_tool(bindir / "docker", _DOCKER)
    _write_tool(bindir / "curl", _CURL)
    _write_tool(bindir / "notify", _NOTIFY)


def write_state(path: Path, containers: dict, images: list[str] | None = None) -> None:
    path.write_text(json.dumps({"containers": containers, "images": images or []}))


def read_state(path: Path) -> dict:
    return json.loads(path.read_text())


def base_env(tmp: Path, bindir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{env.get('PATH', '/usr/bin:/bin')}",
        FAKE_DOCKER_STATE=str(tmp / "docker-state.json"),
        FAKE_DOCKER_CALLS=str(tmp / "docker-calls.log"),
        FAKE_NOTIFY_LOG=str(tmp / "notify.log"),
        SF_NOTIFY_BIN=str(bindir / "notify"),
        SF_LOCK_FILE=str(tmp / "deploy.lock"),
        SF_BACKUP_LOCK=str(tmp / "backup.lock"),
        SF_MONITOR_LOCK=str(tmp / "monitor.lock"),
        # the LAN address the WebUI port is bound to (operations/site.env on a server)
        WEBUI_BIND="192.168.1.10",
    )
    env.pop("FAKE_CURL_BODY", None)
    return env
