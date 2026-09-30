#!/usr/bin/env python3
"""Generate an Alice<->Bob conversation history against a running dev-stack.

Drives the moat-cli HTTP API, the same surface moat-beacon uses, so anything
this reproduces is reproducible in a Beacon scenario. Its job is to build the
*background state* a manual pass needs — enough traffic to hit scale-dependent
bugs — so the human only does the judgment parts.

    .claude/skills/local-test/scripts/dev-stack.sh up
    .claude/skills/local-test/scripts/seed-history.py --messages 1000

Leaves both devices running (unless --stop) so you can pair a third device
against the result and watch history sync at that scale.
"""

import argparse
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

# skill lives at <repo>/.claude/skills/local-test/scripts/
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), *[os.pardir] * 4))
RUN_DIR = "/tmp/moat-dev-stack"
PDS = "http://127.0.0.1:4000"

WORDS = """the quick brown fox jumps over a lazy dog while we talk about
protocol design lunch plans the weather deployment timing test fixtures
encryption keys and whatever else comes to mind today tomorrow later""".split()


def req(method, url, body=None, timeout=60, raw=False):
    data = None
    headers = {}
    if body is not None:
        if raw:
            data = body
            headers["Content-Type"] = "application/octet-stream"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        raw_body = resp.read()
        return json.loads(raw_body) if raw_body else {}


def wait_for(fn, what, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.25)
    raise SystemExit(f"timed out waiting for {what}")


class Device:
    def __init__(self, name, handle, port, state_dir, pds, keep_state):
        self.name, self.handle, self.port = name, handle, port
        self.base = f"http://127.0.0.1:{port}"
        self.state_dir, self.pds, self.keep_state = state_dir, pds, keep_state
        self.proc = None

    def start(self):
        if not self.keep_state:
            shutil.rmtree(self.state_dir, ignore_errors=True)
        log = open(f"{RUN_DIR}/{self.name}.log", "w")
        self.proc = subprocess.Popen(
            [f"{ROOT}/target/debug/moat", "-s", self.state_dir,
             "--pds-url", self.pds, "--http", f"127.0.0.1:{self.port}"],
            stdout=log, stderr=subprocess.STDOUT,
        )
        wait_for(lambda: req("GET", f"{self.base}/status") is not None,
                 f"{self.name} HTTP")

    def login(self):
        req("POST", f"{self.base}/login",
            {"handle": self.handle, "password": "x"})
        wait_for(lambda: req("GET", f"{self.base}/status")["logged_in"],
                 f"{self.name} login")

    def status(self):
        return req("GET", f"{self.base}/status")

    def watch(self, handle):
        req("POST", f"{self.base}/watch", {"handle": handle})

    def conversations(self):
        return req("GET", f"{self.base}/conversations")

    def start_conversation(self, handle):
        return req("POST", f"{self.base}/conversations",
                   {"recipient_handle": handle})["group_id"]

    def send(self, gid, text):
        req("POST", f"{self.base}/conversations/{gid}/messages", {"text": text})

    def send_image(self, gid, data):
        req("POST", f"{self.base}/conversations/{gid}/messages/image",
            data, raw=True)

    def react(self, gid, message_id, emoji):
        req("POST",
            f"{self.base}/conversations/{gid}/messages/{message_id}/reactions",
            {"emoji": emoji})

    def messages(self, gid):
        return req("GET", f"{self.base}/conversations/{gid}/messages")

    def poll(self):
        try:
            req("POST", f"{self.base}/poll", timeout=120)
        except Exception:
            pass

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# A 1x1 PNG — smallest thing that exercises the blob path end to end.
TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000100ffff03000006000557bfabd400"
    "00000049454e44ae426082"
)


def sentence(rng):
    n = rng.randint(3, 14)
    return " ".join(rng.choice(WORDS) for _ in range(n))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--messages", type=int, default=200,
                   help="total messages across both directions (default 200)")
    p.add_argument("--burst", type=int, default=20,
                   help="also send one uninterrupted run of N from Alice "
                        "(the tag-window check; default 20)")
    p.add_argument("--images", type=int, default=2)
    p.add_argument("--reactions", type=int, default=5)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--pds", default=PDS)
    p.add_argument("--alice-port", type=int, default=9101)
    p.add_argument("--bob-port", type=int, default=9102)
    p.add_argument("--keep-state", action="store_true",
                   help="append to existing device state instead of wiping it")
    p.add_argument("--converge-timeout", type=int, default=600,
                   help="seconds to wait for both sides to agree (default 600)")
    p.add_argument("--stop", action="store_true",
                   help="stop both devices when done (default: leave running)")
    args = p.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(RUN_DIR, exist_ok=True)

    alice = Device("alice", "alice.postern.test", args.alice_port,
                   "/tmp/moat-alice", args.pds, args.keep_state)
    bob = Device("bob1", "bob.postern.test", args.bob_port,
                 "/tmp/moat-bob1", args.pds, args.keep_state)

    try:
        req("GET", f"{args.pds}/xrpc/com.atproto.server.describeServer", timeout=5)
    except Exception:
        raise SystemExit("dev-stack not reachable — run dev-stack.sh up first")

    print(f"Starting devices (alice :{args.alice_port}, bob :{args.bob_port})...")
    for d in (alice, bob):
        d.start()
        d.login()
    print(f"  alice {alice.status()['did']}  drawbridge="
          f"{alice.status()['drawbridge_connected']}")
    print(f"  bob   {bob.status()['did']}  drawbridge="
          f"{bob.status()['drawbridge_connected']}")

    bob.watch(alice.handle)
    alice.watch(bob.handle)

    existing = alice.conversations()
    if args.keep_state and existing:
        gid = existing[0]["id"]
        print(f"Reusing conversation {gid}")
    else:
        gid = alice.start_conversation(bob.handle)
        print(f"Created conversation {gid}")

        # Bob only picks the invite up on a poll; the idle interval is far
        # longer than this wait, so drive it rather than waiting it out.
        def bob_sees_it():
            bob.poll()
            return any(c["id"] == gid for c in bob.conversations())

        wait_for(bob_sees_it, "bob to see the conversation", timeout=120)
        print("Bob joined the conversation.")

    # ── the bulk history ────────────────────────────────────────────────
    total = args.messages
    print(f"\nSending {total} messages (alternating)...")
    lat = []
    t0 = time.time()
    for i in range(total):
        sender = alice if i % 2 == 0 else bob
        s = time.time()
        sender.send(gid, f"[{i:05d}] {sentence(rng)}")
        lat.append(time.time() - s)
        if (i + 1) % 50 == 0:
            el = time.time() - t0
            print(f"  {i+1:5d}/{total}  {el:6.1f}s  "
                  f"{(i+1)/el:5.1f} msg/s  last-50 p50="
                  f"{statistics.median(lat[-50:])*1000:.0f}ms")
    bulk_elapsed = time.time() - t0

    # ── images ──────────────────────────────────────────────────────────
    for i in range(args.images):
        (alice if i % 2 == 0 else bob).send_image(gid, TINY_PNG)
    if args.images:
        print(f"Sent {args.images} images.")

    # ── the uninterrupted burst (the (K) tag-window check) ──────────────
    if args.burst:
        print(f"Sending an uninterrupted burst of {args.burst} from Alice...")
        for i in range(args.burst):
            alice.send(gid, f"[burst {i+1:02d}/{args.burst}]")

    # ── converge ────────────────────────────────────────────────────────
    # `send` returns once the message is queued locally; the PDS publish and
    # the peer's fetch happen after. So the number that matters at scale is
    # how long both sides take to agree, not how fast sends returned.
    #
    # Images are excluded from the target: the blob upload is asynchronous and
    # the sender's own copy reads "[image — processing…]" until it lands, so
    # counting them here reports a delivery failure that is really an upload
    # still in flight. They get their own check below.
    expected = total + args.burst
    print(f"\nConverging (expecting {expected} on both sides)...")
    conv_t0 = time.time()
    last_counts, stable_since = None, None
    converged = False

    # Every seeded text message carries a "[00042]" / "[burst 03/20]" tag.
    # Counting those rather than rows keeps images (and anything else the
    # client renders as a message) out of the comparison.
    def seeded(msgs):
        return [m for m in msgs
                if m["content"].startswith("[")
                and ("burst" in m["content"][:8]
                     or m["content"][1:6].isdigit())]

    while time.time() - conv_t0 < args.converge_timeout:
        alice.poll(); bob.poll()
        a_msgs, b_msgs = alice.messages(gid), bob.messages(gid)
        counts = (len(seeded(a_msgs)), len(seeded(b_msgs)))
        if counts == (expected, expected):
            converged = True
            break
        # Stop early if both sides have been quiet for a while: that is a real
        # stall, not slowness, and waiting out the full timeout hides it.
        if counts == last_counts:
            if stable_since and time.time() - stable_since > 30:
                break
        else:
            last_counts, stable_since = counts, time.time()
        print(f"  alice {counts[0]:5d}  bob {counts[1]:5d}  "
              f"{time.time()-conv_t0:6.1f}s")
        time.sleep(3)
    converge_elapsed = time.time() - conv_t0
    a_msgs, b_msgs = alice.messages(gid), bob.messages(gid)
    if args.reactions and b_msgs:
        targets = [m for m in b_msgs if not m["is_own"]][-args.reactions:]
        for m in targets:
            bob.react(gid, m["message_id"], rng.choice("👍🎉🔥😀✅"))
        print(f"Bob reacted to {len(targets)} messages.")
        for _ in range(2):
            alice.poll(); bob.poll(); time.sleep(2)
        a_msgs, b_msgs = alice.messages(gid), bob.messages(gid)

    # ── report ──────────────────────────────────────────────────────────
    print(f"""
Seeded.

  Conversation   {gid}
  Sent           {total} alternating + {args.burst} burst
                 (+ {args.images} images, counted separately)
  Alice sees     {len(seeded(a_msgs))} seeded ({len(a_msgs)} rows total)
  Bob sees       {len(seeded(b_msgs))} seeded ({len(b_msgs)} rows total)
  Enqueue        {total/bulk_elapsed:.1f} msg/s over {bulk_elapsed:.0f}s """
          f"""(p50 {statistics.median(lat)*1000:.0f}ms, """
          f"""max {max(lat)*1000:.0f}ms) — local queue, not delivery
  Converge       {'yes' if converged else 'NO'} in {converge_elapsed:.0f}s""")

    # Name what is missing. A count alone cannot distinguish "still catching
    # up" from "these specific messages are gone".
    def tags(msgs):
        return {m["content"].split("]")[0] + "]" for m in seeded(msgs)}

    only_a, only_b = tags(a_msgs) - tags(b_msgs), tags(b_msgs) - tags(a_msgs)
    burst_seen = sum(1 for m in b_msgs if m["content"].startswith("[burst"))
    if args.burst:
        print(f"  Burst on Bob   {burst_seen}/{args.burst} "
              f"{'OK' if burst_seen == args.burst else '<-- MISSING'}")

    if args.images:
        def img_count(msgs):
            return sum(1 for m in msgs
                       if "image" in m["content"].lower()
                       or not m["content"].startswith("["))
        pending = sum(1 for m in a_msgs if "processing" in m["content"].lower())
        print(f"  Images         alice {img_count(a_msgs)} / bob "
              f"{img_count(b_msgs)} of {args.images} sent"
              + (f"  ({pending} still uploading)" if pending else ""))

    if not converged:
        print("\n  !! Did not converge.")
        for label, missing in (("Bob is missing", only_a),
                               ("Alice is missing", only_b)):
            if missing:
                s = sorted(missing)
                print(f"     {label} {len(s)}: {', '.join(s[:10])}"
                      f"{' ...' if len(s) > 10 else ''}")
        print("     Re-poll by hand before calling it a bug; if it persists, "
              "that is a finding worth a Beacon scenario.")

    if args.stop:
        for d in (alice, bob):
            d.stop()
        print("\nDevices stopped.")
    else:
        print(f"""
Devices left running:
  alice  http://127.0.0.1:{args.alice_port}   /tmp/moat-alice
  bob    http://127.0.0.1:{args.bob_port}   /tmp/moat-bob1

Pair a third device against this history and watch sync at scale:
  cargo run -p moat-cli -- -s /tmp/moat-bob2 --pds-url {args.pds}
  (press 'p', then paste the code into Bob's Devices popup on :{args.bob_port}
   via POST /pair/confirm, then POST /pair/approve)""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
