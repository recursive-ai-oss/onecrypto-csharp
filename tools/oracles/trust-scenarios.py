#!/usr/bin/env python3
"""Generates the OpenPGP trust-model scenarios and records what the reference tools say about them.

Every scenario is a small web of trust made of throwaway keys: certificates, certifications (with trust depth, amount, regular
expressions, expiry), revocations and the question to ask. Keys and certifications are made with the Sequoia `sq` command line (and
GnuPG for revoking a third-party certification, which `sq` cannot do); the expectations are what the tools print:

  generate  <out>  --sq SQ --gpg GPG         make <out>/<scenario>/{certs.pgp,scenario.json}
  expect-sq <out>  --sq SQ                   add <out>/<scenario>/expected.sq-<version>.json   (flow model: `sq pki authenticate`)
  expect-gpg <out> --gpg GPG                 add <out>/<scenario>/expected.gnupg-<version>.json (classic model: --with-colons validity)

Only the committed outputs are needed to run the tests; the tools are needed to regenerate them. Everything happens in throwaway homes
under $TMPDIR; no existing keyring or agent is touched.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile

DAY = 86400
T0 = 1735689600  # 2025-01-01T00:00:00Z: every key is created now
REF = T0 + 151 * DAY  # 2025-06-01: the default reference time
CERT_AT = T0 + 31 * DAY  # 2025-02-01: the default time of a certification


def iso(t):
    return subprocess.run(["date", "-u", "-d", "@%d" % t, "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True, check=True).stdout.strip()


def uid_of(name, domain="example.org"):
    return "%s <%s@%s>" % (name.capitalize(), name, domain)


# --------------------------------------------------------------------------------------------------------------------------------
# Scenario description. A scenario is built with these small helpers; nothing here runs a tool.
class S:
    def __init__(self, name, text, kind):
        self.name, self.text, self.kind = name, text, kind  # kind: "flow" or "classic"
        self.keys = {}      # name -> dict(uids=[...], expires=..., revoked=...)
        self.steps = []     # ordered operations
        self.roots = []     # flow: root names ; classic: ultimate names
        self.ownertrust = {}  # classic: name -> letter
        self.queries = []   # (target, uid, ref time)
        self.gpg_args = []  # classic: extra gpg options (--marginals-needed ...)

    def key(self, name, uids=None, expires=None, domain="example.org", at=T0):
        self.keys[name] = dict(uids=uids or [uid_of(name, domain)], expires=expires, at=at)
        return self

    def cert(self, by, to, uid=None, at=CERT_AT, amount=None, depth=None, domains=(), regexes=(), expires=None, local=False, nonrevocable=False, add_uid=False):
        self.steps.append(dict(op="cert", by=by, to=to, uid=uid, at=at, amount=amount, depth=depth, domains=list(domains), regexes=list(regexes),
                               expires=expires, local=local, nonrevocable=nonrevocable, add_uid=add_uid))
        return self

    def revoke_cert(self, by, to, uid=None, at=CERT_AT + DAY):
        self.steps.append(dict(op="revcert", by=by, to=to, uid=uid, at=at))
        return self

    def revoke_key(self, name, reason="compromised", at=CERT_AT + 10 * DAY):
        self.steps.append(dict(op="revkey", name=name, reason=reason, at=at))
        return self

    def revoke_uid(self, name, uid=None, at=CERT_AT + 10 * DAY):
        self.steps.append(dict(op="revuid", name=name, uid=uid, at=at))
        return self

    def root(self, *names):
        self.roots += names
        return self

    def trust(self, **levels):
        self.ownertrust.update(levels)
        return self

    def ask(self, target, uid=None, at=REF):
        self.queries.append((target, uid, at))
        return self

    def gpg(self, *args):
        self.gpg_args += args
        return self


def random_web(name, seed, kind):
    """A random web of nine certificates: edges, trust depths, amounts and domain scopes drawn from a seeded generator."""
    import random
    rnd = random.Random(seed * 7919 + (1 if kind == "flow" else 2))
    n = 9
    names = ["k%d" % i for i in range(n)]
    s = S(name, "a random web of %d certificates (seed %d)" % (n, seed), kind)
    for i, k in enumerate(names):
        s.key(k, domain="corp.example" if i % 3 == 1 else "example.org", expires="60d" if i > 1 and rnd.random() < 0.08 else None)
    depths = [0, 0, 0, 1, 1, 2, 3, 255] if kind == "flow" else [0, 0, 0, 0, 1, 1, 2]
    amounts = [30, 60, 60, 90, 120, 120, 120]
    for i in range(n):
        for j in range(n):
            if i == j or rnd.random() > 0.22:
                continue
            d = rnd.choice(depths)
            a = rnd.choice(amounts)
            dom = ["corp.example"] if d > 0 and rnd.random() < 0.2 else []
            when = CERT_AT + rnd.choice([0, 0, 2, 5]) * DAY
            lapse = iso(when + 30 * DAY) if rnd.random() < 0.08 else None
            if kind == "flow" or d > 0:
                s.cert(names[i], names[j], depth=d, amount=a, domains=dom, at=when, expires=lapse)
            else:
                s.cert(names[i], names[j], at=when, expires=lapse)
    for k in names[2:]:
        r = rnd.random()
        if r < 0.06:
            s.revoke_key(k, "compromised", at=CERT_AT + 40 * DAY)
        elif r < 0.10:
            s.revoke_key(k, "retired", at=CERT_AT + 40 * DAY)
    if kind == "flow":
        s.root(*([names[0], names[1]] if rnd.random() < 0.3 else [names[0]]))
    else:
        s.root(names[0])
        lv = {names[0]: "u"}
        for k in names[1:]:
            lv[k] = rnd.choice(["f", "m", "m", "n", "q", "q"])
        s.trust(**lv)
    for k in names[1:]:
        s.ask(k)
    return s


def flow_scenarios():
    out = []

    def f(name, text):
        s = S(name, text, "flow")
        out.append(s)
        return s

    f("f01-direct", "a root certifies b's user ID").key("a").key("b").cert("a", "b").root("a").ask("b")
    f("f02-partial-amount", "a certifies b with amount 60: partially authenticated").key("a").key("b").cert("a", "b", amount=60).root("a").ask("b")
    s = f("f03-two-partial-paths", "two introducers at amount 60 each certify t: the paths add up to 120")
    for k in "axyt":
        s.key(k)
    s.cert("a", "x", depth=1, amount=120).cert("a", "y", depth=1, amount=120).cert("x", "t", amount=60).cert("y", "t", amount=60).root("a").ask("t")
    s = f("f04-chain-depth-enough", "a -> b(depth 2) -> c(depth 1) -> t: depths allow it")
    for k in "abct":
        s.key(k)
    s.cert("a", "b", depth=2).cert("b", "c", depth=1).cert("c", "t").root("a").ask("t").ask("c")
    s = f("f05-depth-exhausted", "a trusts b to depth 1 only; b's introducer c cannot be followed")
    for k in "abct":
        s.key(k)
    s.cert("a", "b", depth=1).cert("b", "c", depth=1).cert("c", "t").root("a").ask("t").ask("c")
    s = f("f06-depth-capped", "the draft's example: each certification asks for depth 2 but earlier ones cap it")
    for k in ["alice", "bob", "carol", "dave", "ed"]:
        s.key(k)
    s.cert("alice", "bob", depth=2).cert("bob", "carol", depth=2).cert("carol", "dave", depth=2).cert("dave", "ed", depth=2).root("alice")
    s.ask("bob").ask("carol").ask("dave").ask("ed")
    s = f("f07-unlimited-depth", "depth 255 means no limit")
    for k in "abcdt":
        s.key(k)
    s.cert("a", "b", depth=255).cert("b", "c", depth=255).cert("c", "d", depth=255).cert("d", "t").root("a").ask("t")
    s = f("f08-amount-min-first-edge", "the path carries the smallest amount: a -> b at 60, b -> t at 120 gives 60")
    for k in "abt":
        s.key(k)
    s.cert("a", "b", depth=1, amount=60).cert("b", "t").root("a").ask("t")
    s = f("f09-amount-min-last-edge", "a -> b at 120, b -> t at 30 gives 30")
    for k in "abt":
        s.key(k)
    s.cert("a", "b", depth=1).cert("b", "t", amount=30).root("a").ask("t")
    s = f("f10-draft-example-5-1", "the draft's worked example: alice -> bob(2/100) -> carol -> dave -> ed and bob -> ed at 30")
    for k in ["alice", "bob", "carol", "dave", "ed"]:
        s.key(k)
    s.cert("alice", "bob", depth=2, amount=100).cert("bob", "carol", depth=255).cert("carol", "dave", depth=255).cert("dave", "ed").cert("bob", "ed", amount=30)
    s.root("alice").ask("ed")
    s = f("f11-backward-better", "the draft's backward-propagation example: the longer-capped branch is avoided, giving 120")
    for k in ["root", "a", "b", "c", "d", "target"]:
        s.key(k)
    s.cert("root", "a", depth=255).cert("a", "b", depth=255, amount=1).cert("a", "c", depth=2).cert("b", "d", depth=255).cert("c", "d", depth=1).cert("d", "target").root("root").ask("target")
    s = f("f12-forward-better", "the draft's second example, where a forward search would do better")
    for k in ["root", "a", "b", "c", "target"]:
        s.key(k)
    s.cert("root", "a", depth=3).cert("a", "b", depth=2).cert("b", "c", depth=1).cert("a", "c", depth=1, amount=60).cert("c", "target").root("root").ask("target")
    s = f("f13-cycle", "a, b certify each other with unlimited depth; b certifies t")
    for k in "abt":
        s.key(k)
    s.cert("a", "b", depth=255).cert("b", "a", depth=255).cert("b", "t").root("a").ask("t").ask("a")
    s = f("f14-unreachable", "t is certified by b, but nothing connects the root to b")
    for k in "abt":
        s.key(k)
    s.cert("b", "t").cert("t", "b", depth=255).root("a").ask("t")
    s = f("f15-regex-domain-match", "a trusts ca only for corp.example; t's user ID is in that domain")
    s.key("a").key("ca").key("t", domain="corp.example")
    s.cert("a", "ca", depth=255, domains=["corp.example"]).cert("ca", "t").root("a").ask("t")
    s = f("f16-regex-domain-mismatch", "the same, but t's user ID is in another domain")
    s.key("a").key("ca").key("t", domain="other.example")
    s.cert("a", "ca", depth=255, domains=["corp.example"]).cert("ca", "t").root("a").ask("t")
    s = f("f17-regex-intermediate-not-matched", "the draft's example: the expression need not match the intermediate introducer")
    s.key("ed").key("ca", domain="nsa.gov").key("fbi", domain="fbi.gov").key("paul", domain="nsa.gov")
    s.cert("ed", "ca", depth=255, domains=["nsa.gov"]).cert("ca", "fbi", depth=1).cert("fbi", "paul").root("ed").ask("paul").ask("fbi")
    s = f("f18-two-expressions", "two domains on one certification: the second matches")
    s.key("a").key("ca").key("t", domain="two.example")
    s.cert("a", "ca", depth=255, domains=["one.example", "two.example"]).cert("ca", "t").root("a").ask("t")
    s = f("f19-raw-regex", "a raw expression anchored on the email domain")
    s.key("a").key("ca").key("t", domain="raw.example").key("u", domain="other.example")
    s.cert("a", "ca", depth=255, regexes=[r"<[^>]+@raw\.example>$"]).cert("ca", "t").cert("ca", "u").root("a").ask("t").ask("u")
    s = f("f20-regex-on-last-edge", "a regular expression on the final certification restricts it too")
    s.key("a").key("b").key("t", domain="in.example").key("u", domain="out.example")
    s.cert("a", "b", depth=1).cert("b", "t", depth=0, domains=["in.example"]).cert("b", "u", depth=0, domains=["in.example"]).root("a").ask("t").ask("u")
    s = f("f21-revoked-certification", "the certification is revoked after it was made")
    s.key("a").key("t")
    s.cert("a", "t").revoke_cert("a", "t", at=CERT_AT + 20 * DAY).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 10 * DAY)
    s = f("f22-expired-certification", "the certification expired before the reference time")
    s.key("a").key("t")
    s.cert("a", "t", expires=iso(CERT_AT + 30 * DAY)).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 10 * DAY)
    s = f("f23-future-certification", "the certification is made after the reference time")
    s.key("a").key("t")
    s.cert("a", "t", at=CERT_AT + 300 * DAY).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 301 * DAY)
    s = f("f24-issuer-key-revoked-hard", "the issuer's key was revoked as compromised after certifying: no certification of it counts")
    s.key("a").key("b").key("t")
    s.cert("a", "b", depth=1).cert("b", "t").revoke_key("b", "compromised", at=CERT_AT + 40 * DAY).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 10 * DAY)
    s = f("f25-issuer-key-retired", "the issuer's key was retired after certifying: certifications made before still count")
    s.key("a").key("b").key("t")
    s.cert("a", "b", depth=1).cert("b", "t").revoke_key("b", "retired", at=CERT_AT + 40 * DAY).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 10 * DAY)
    s = f("f27-issuer-expired-after", "the issuer's key expired after it certified: the certification still counts")
    s.key("a").key("b", expires="60d").key("t")
    s.cert("a", "b", depth=1).cert("b", "t").root("a").ask("t", at=REF).ask("t", at=CERT_AT + 10 * DAY)
    s = f("f28-newer-replaces-older", "a newer certification by the same issuer replaces the older one (120 then 30)")
    s.key("a").key("t")
    s.cert("a", "t", at=CERT_AT).cert("a", "t", at=CERT_AT + 5 * DAY, amount=30).root("a").ask("t").ask("t", at=CERT_AT + 2 * DAY)
    s = f("f29-amount-zero-overrides", "a newer certification with amount 0 withdraws the earlier one")
    s.key("a").key("t")
    s.cert("a", "t", at=CERT_AT).cert("a", "t", at=CERT_AT + 5 * DAY, amount=0).root("a").ask("t")
    s = f("f30-user-id-revoked", "the target revoked the user ID")
    s.key("a").key("t")
    s.cert("a", "t").revoke_uid("t", at=CERT_AT + 10 * DAY).root("a").ask("t", at=REF).ask("t", at=CERT_AT + 5 * DAY)
    s = f("f31-root-itself", "the root's own self-signed user ID")
    s.key("a").root("a").ask("a")
    s = f("f32-introducer-self-certifies-other-uid", "a makes b an introducer; b's second user ID is certified only by b itself")
    s.key("a").key("b", uids=[uid_of("b"), "Bee <bee@example.org>"])
    s.cert("a", "b", uid=uid_of("b"), depth=1).root("a").ask("b", uid=uid_of("b")).ask("b", uid="Bee <bee@example.org>")
    s = f("f33-not-self-signed-uid", "a certifies a user ID that b never signed itself")
    s.key("a").key("b")
    s.cert("a", "b", uid="Extra <extra@example.org>", add_uid=True).root("a").ask("b", uid="Extra <extra@example.org>").ask("b")
    s = f("f34-two-roots", "two roots, only one reaches t")
    for k in "abt":
        s.key(k)
    s.key("c")
    s.cert("b", "t", amount=60).cert("a", "b", depth=1).root("a", "c").ask("t")
    s = f("f35-uncertified-uid", "nothing certifies the second user ID")
    s.key("a").key("t", uids=[uid_of("t"), "Tee <tee@example.org>"])
    s.cert("a", "t", uid=uid_of("t")).root("a").ask("t", uid="Tee <tee@example.org>").ask("t", uid=uid_of("t"))
    s = f("f36-local-certification", "a certification marked not exportable still counts for the local user")
    s.key("a").key("t")
    s.cert("a", "t", local=True).root("a").ask("t")
    s = f("f37-diamond-flow", "a diamond whose paths share the final certification: capacity of the shared edge limits the sum")
    for k in "axyt":
        s.key(k)
    s.cert("a", "x", depth=2, amount=120).cert("a", "y", depth=2, amount=120).cert("x", "y", depth=1, amount=120).cert("x", "t", amount=70).cert("y", "t", amount=70).root("a").ask("t")
    s = f("f38-greedy-trap", "paths that need rerouting to reach the maximum flow")
    for k in "abcdt":
        s.key(k)
    s.cert("a", "b", depth=3, amount=60).cert("a", "c", depth=3, amount=60).cert("b", "d", depth=2, amount=60).cert("c", "d", depth=2, amount=60).cert("b", "t", amount=60).cert("d", "t", amount=60).root("a").ask("t")
    s = f("f39-bridge", "a bridge between two branches")
    for k in "abxyt":
        s.key(k)
    s.cert("a", "x", depth=3, amount=60).cert("a", "y", depth=3, amount=60).cert("x", "y", depth=2, amount=60).cert("x", "t", amount=60).cert("y", "t", amount=60).root("a").ask("t")
    s = f("f40-multi-uid-edges", "two certifications of different user IDs of the same introducer count as separate edges")
    s.key("a").key("b", uids=[uid_of("b"), "Bee <bee@example.org>"]).key("t")
    s.cert("a", "b", uid=uid_of("b"), depth=1, amount=60).cert("a", "b", uid="Bee <bee@example.org>", depth=1, amount=60).cert("b", "t").root("a").ask("t")
    s = f("f41-issuer-root-revoked", "the root's own key is revoked")
    s.key("a").key("t").cert("a", "t").revoke_key("a", "compromised", at=CERT_AT + 40 * DAY).root("a").ask("t").ask("a")
    s = f("f42-target-key-revoked", "the target's key is revoked after it was certified")
    s.key("a").key("t").cert("a", "t").revoke_key("t", "compromised", at=CERT_AT + 40 * DAY).root("a").ask("t")
    s = f("f43-tsig-then-plain", "a newer plain certification replaces the earlier delegation")
    for k in "abt":
        s.key(k)
    s.cert("a", "b", depth=2, at=CERT_AT).cert("a", "b", at=CERT_AT + 5 * DAY).cert("b", "t").root("a").ask("b").ask("t")
    for seed in range(1, 31):
        out.append(random_web("f%02d-random-%d" % (43 + seed, seed), seed, "flow"))
    return out


def classic_scenarios():
    out = []

    def c(name, text):
        s = S(name, text, "classic")
        out.append(s)
        return s

    def keys(s, names):
        for n in names:
            s.key(n)
        return s

    s = keys(c("c01-ultimate-signs", "an ultimately trusted key signs b"), "ab").cert("a", "b").trust(a="u").root("a").ask("b").ask("a")
    s = keys(c("c02-full-introducer", "a (ultimate) signs b, b (full) signs t"), "abt").cert("a", "b").cert("b", "t").trust(a="u", b="f").ask("t").ask("b")
    s = keys(c("c03-one-marginal", "a (ultimate) signs b, b (marginal) signs t: one marginal is not enough"), "abt").cert("a", "b").cert("b", "t").trust(a="u", b="m").ask("t")
    s = keys(c("c04-three-marginals", "three marginal introducers sign t"), "abcdet")
    s.cert("a", "b").cert("a", "c").cert("a", "d").cert("b", "t").cert("c", "t").cert("d", "t").trust(a="u", b="m", c="m", d="m").ask("t")
    s = keys(c("c05-two-marginals", "two marginal introducers sign t"), "abcdt")
    s.cert("a", "b").cert("a", "c").cert("b", "t").cert("c", "t").trust(a="u", b="m", c="m").ask("t")
    s = keys(c("c06-full-and-marginals", "one full introducer is enough"), "abcdt")
    s.cert("a", "b").cert("a", "c").cert("b", "t").trust(a="u", b="f", c="m").ask("t")
    s = keys(c("c07-never-trusted", "an introducer marked never trusted does not count"), "abt").cert("a", "b").cert("b", "t").trust(a="u", b="n").ask("t")
    s = keys(c("c08-undefined-trust", "an introducer with undefined owner trust does not count"), "abt").cert("a", "b").cert("b", "t").trust(a="u", b="q").ask("t")
    s = keys(c("c09-chain-default-depth", "a chain of full introducers: the default maximum depth is 5"), "abcdefgh")
    for x, y in zip("abcdefg", "bcdefgh"):
        s.cert(x, y)
    s.trust(a="u", b="f", c="f", d="f", e="f", f="f", g="f", h="f").ask("b").ask("c").ask("d").ask("e").ask("f").ask("g").ask("h")
    s = keys(c("c10-chain-depth-2", "the same chain with --max-cert-depth 2"), "abcdef")
    for x, y in zip("abcde", "bcdef"):
        s.cert(x, y)
    s.trust(a="u", b="f", c="f", d="f", e="f", f="f").gpg("--max-cert-depth", "2").ask("b").ask("c").ask("d").ask("e")
    s = keys(c("c11-marginals-needed-2", "--marginals-needed 2 makes two marginals enough"), "abcdt")
    s.cert("a", "b").cert("a", "c").cert("b", "t").cert("c", "t").trust(a="u", b="m", c="m").gpg("--marginals-needed", "2").ask("t")
    s = keys(c("c12-completes-needed-2", "--completes-needed 2: one full introducer is then only marginal"), "abct")
    s.cert("a", "b").cert("a", "c").cert("b", "t").trust(a="u", b="f", c="f").gpg("--completes-needed", "2").ask("t")
    s = keys(c("c13-completes-needed-2-both", "--completes-needed 2 with two full introducers"), "abct")
    s.cert("a", "b").cert("a", "c").cert("b", "t").cert("c", "t").trust(a="u", b="f", c="f").gpg("--completes-needed", "2").ask("t")
    s = keys(c("c14-tsig-full", "a trust signature (level 1, amount 120) makes b a full introducer without owner trust"), "abt")
    s.cert("a", "b", depth=1, amount=120).cert("b", "t").trust(a="u").ask("b").ask("t")
    s = keys(c("c15-tsig-marginal", "a trust signature with amount 60 makes b a marginal introducer"), "abt")
    s.cert("a", "b", depth=1, amount=60).cert("b", "t").trust(a="u").ask("t")
    s = keys(c("c16-tsig-level-2", "a -> b (level 2) -> c (level 1) -> t"), "abct")
    s.cert("a", "b", depth=2, amount=120).cert("b", "c", depth=1, amount=120).cert("c", "t").trust(a="u").ask("c").ask("t")
    s = keys(c("c17-tsig-level-1-chain", "a -> b (level 1) -> c (level 1): c is valid, its signatures do not extend"), "abct")
    s.cert("a", "b", depth=1, amount=120).cert("b", "c", depth=1, amount=120).cert("c", "t").trust(a="u").ask("c").ask("t")
    s = c("c18-tsig-domain-match", "the trust signature is restricted to corp.example and t is in that domain")
    s.key("a").key("b").key("t", domain="corp.example").cert("a", "b", depth=1, domains=["corp.example"]).cert("b", "t").trust(a="u").ask("t").ask("b")
    s = c("c19-tsig-domain-mismatch", "the trust signature is restricted to corp.example and t is elsewhere")
    s.key("a").key("b").key("t", domain="other.example").cert("a", "b", depth=1, domains=["corp.example"]).cert("b", "t").trust(a="u").ask("t").ask("b")
    s = keys(c("c20-signer-revoked", "the signer's key is revoked"), "abt").cert("a", "b").cert("b", "t").revoke_key("b", "compromised", at=CERT_AT + 40 * DAY).trust(a="u", b="f").ask("t").ask("b")
    s = c("c21-signer-expired", "the signer's key has expired")
    s.key("a").key("b", expires="60d").key("t").cert("a", "b").cert("b", "t").trust(a="u", b="f").ask("t").ask("b")
    s = keys(c("c22-certification-expired", "the root's certification of b expired"), "abt")
    s.cert("a", "b", expires=iso(CERT_AT + 30 * DAY)).cert("b", "t").trust(a="u", b="f").ask("b").ask("t").ask("b", at=CERT_AT + 10 * DAY)
    s = keys(c("c23-certification-revoked", "the root's certification of b was revoked"), "abt")
    s.cert("a", "b").revoke_cert("a", "b", at=CERT_AT + 20 * DAY).cert("b", "t").trust(a="u", b="f").ask("b").ask("t")
    s = keys(c("c24-target-key-revoked", "the signed key is revoked"), "ab").cert("a", "b").revoke_key("b", "compromised", at=CERT_AT + 40 * DAY).trust(a="u").ask("b")
    s = c("c25-target-key-expired", "the signed key has expired")
    s.key("a").key("b", expires="60d").cert("a", "b").trust(a="u").ask("b")
    s = keys(c("c26-uid-revoked", "the target revoked its user ID"), "ab").cert("a", "b").revoke_uid("b", at=CERT_AT + 10 * DAY).trust(a="u").ask("b")
    s = keys(c("c27-future-certification", "the certification is dated after the reference time"), "ab").cert("a", "b", at=CERT_AT + 300 * DAY).trust(a="u").ask("b")
    s = c("c28-two-uids", "only one of two user IDs is signed")
    s.key("a").key("b", uids=[uid_of("b"), "Bee <bee@example.org>"]).cert("a", "b", uid=uid_of("b")).trust(a="u").ask("b", uid=uid_of("b")).ask("b", uid="Bee <bee@example.org>")
    s = keys(c("c29-unsigned", "no certification at all"), "ab").trust(a="u").ask("b")
    s = keys(c("c30-ultimate-nonroot", "a second ultimately trusted key signs b"), "abt").cert("b", "t").trust(a="u", b="u").ask("t")
    s = keys(c("c31-cycle", "b and c sign each other; a signs b"), "abct").cert("a", "b").cert("b", "c").cert("c", "b").cert("c", "t").trust(a="u", b="f", c="f").ask("t").ask("c")
    s = keys(c("c32-marginal-chain", "a marginally valid key with full owner trust signs t"), "abct")
    s.cert("a", "c").cert("b", "c").cert("c", "t").trust(a="u", b="m", c="f").ask("c").ask("t")
    s = keys(c("c33-marginal-valid-introducer", "b is valid only marginally (one marginal signer): can it introduce?"), "abct")
    s.cert("a", "b", depth=0).cert("b", "c").cert("c", "t").trust(a="m", b="f", c="f").ask("b").ask("c").ask("t")
    s = keys(c("c34-never-on-target", "owner trust never on the target does not change its validity"), "ab").cert("a", "b").trust(a="u", b="n").ask("b")
    s = keys(c("c35-marginal-count-mixed", "two marginals and one never"), "abcdt")
    s.cert("a", "b").cert("a", "c").cert("a", "d").cert("b", "t").cert("c", "t").cert("d", "t").trust(a="u", b="m", c="m", d="n").ask("t")
    s = c("c36-tsig-amounts", "trust signatures of amount 30, 59, 60, 90, 119 and 120: which ones lend trust")
    for amount in (30, 59, 60, 90, 119, 120):
        i = str(amount)
        s.key("i" + i).key("t" + i).cert("a", "i" + i, depth=1, amount=amount).cert("i" + i, "t" + i).ask("t" + i)
    s.key("a").trust(a="u")
    s = keys(c("c37-marginal-valid-full-trust", "b is only marginally valid but has full owner trust: does b's certification count"), "amb c t".replace(" ", ""))
    s.cert("a", "m").cert("m", "b").cert("b", "c").trust(a="u", m="m", b="f").ask("b").ask("c")
    s = keys(c("c38-tsig-with-owner-trust", "b has a level-1 trust signature from a and also full owner trust: its own trust signature on c is not capped"), "abcdt")
    s.cert("a", "b", depth=1, amount=120).cert("b", "c", depth=1, amount=120).cert("c", "t").trust(a="u", b="f").ask("c").ask("t")
    s = keys(c("c39-tsig-vs-never", "a trust signature on b, but b is marked never trusted"), "abt")
    s.cert("a", "b", depth=1, amount=120).cert("b", "t").trust(a="u", b="n").ask("t")
    s = keys(c("c40-tsig-vs-marginal", "a full trust signature on b, who has only marginal owner trust"), "abt")
    s.cert("a", "b", depth=1, amount=120).cert("b", "t").trust(a="u", b="m").ask("t")
    s = keys(c("c41-marginal-signer-tsig", "a signer with marginal owner trust gives a full trust signature"), "amxt")
    s.cert("a", "m").cert("m", "x", depth=1, amount=120).cert("x", "t").trust(a="u", m="m").ask("x").ask("t")
    s = keys(c("c42-three-marginal-tsigs", "three trust signatures of amount 60 add up"), "abcdt")
    s.cert("a", "b", depth=1, amount=60).cert("a", "c", depth=1, amount=60).cert("a", "d", depth=1, amount=60).cert("b", "t").cert("c", "t").cert("d", "t").trust(a="u").ask("t")
    s = keys(c("c43-tsig-level-3-chain", "a -> b (level 3) -> c (level 3) -> d (level 3) -> e: levels are capped hop by hop"), "abcdet")
    s.cert("a", "b", depth=3).cert("b", "c", depth=3).cert("c", "d", depth=3).cert("d", "e", depth=3).cert("e", "t").trust(a="u").ask("b").ask("c").ask("d").ask("e").ask("t")
    s = keys(c("c44-ultimate-revoked", "an ultimately trusted key that is revoked signs b"), "ab")
    s.cert("a", "b").revoke_key("a", "compromised", at=CERT_AT + 40 * DAY).trust(a="u").ask("a").ask("b")
    s = keys(c("c45-tsig-then-plain", "a newer plain certification replaces the earlier trust signature"), "abt")
    s.cert("a", "b", depth=1, amount=120, at=CERT_AT).cert("a", "b", at=CERT_AT + 5 * DAY).cert("b", "t").trust(a="u").ask("b").ask("t")
    s = c("c46-two-domains-and-nesting", "a trust signature restricted to two domains; a second-level one restricted to one")
    s.key("a").key("b").key("c").key("t1", domain="one.example").key("t2", domain="two.example").key("t3", domain="three.example")
    s.cert("a", "b", depth=2, domains=["one.example", "two.example"]).cert("b", "c", depth=1, domains=["one.example"]).cert("c", "t1").cert("c", "t2").cert("c", "t3").cert("b", "t2").cert("b", "t3").trust(a="u").ask("t1").ask("t2").ask("t3")
    s = keys(c("c47-full-count-mixed-needs", "--completes-needed 2 --marginals-needed 2 with one full and one marginal"), "abcdt")
    s.cert("a", "b").cert("a", "c").cert("b", "t").cert("c", "t").trust(a="u", b="f", c="m").gpg("--completes-needed", "2", "--marginals-needed", "2").ask("t")
    s = keys(c("c48-depth-1", "--max-cert-depth 1: only keys certified directly by an ultimate key"), "abct")
    s.cert("a", "b").cert("b", "c").cert("c", "t").trust(a="u", b="f", c="f").gpg("--max-cert-depth", "1").ask("b").ask("c")
    s = keys(c("c49-owner-trust-then-tsig", "b has full owner trust and no trust signature on it; b's own level-1 trust signature on c"), "abct")
    s.cert("a", "b").cert("b", "c", depth=1, amount=120).cert("c", "t").trust(a="u", b="f").ask("c").ask("t")
    s = c("c50-two-domains-second", "a trust signature with two domain expressions; the second one matches")
    s.key("a").key("b").key("t1", domain="one.example").key("t2", domain="two.example").key("t3", domain="three.example")
    s.cert("a", "b", depth=1, domains=["one.example", "two.example"]).cert("b", "t1").cert("b", "t2").cert("b", "t3").trust(a="u").ask("t1").ask("t2").ask("t3")
    s = c("c51-two-raw-expressions", "the same with two raw expressions")
    s.key("a").key("b").key("t1", domain="one.example").key("t2", domain="two.example")
    s.cert("a", "b", depth=1, regexes=[r"<[^>]+@one\.example>$", r"<[^>]+@two\.example>$"]).cert("b", "t1").cert("b", "t2").trust(a="u").ask("t1").ask("t2")
    s = keys(c("c52-expired-ultimate", "an ultimately trusted key that has expired signs b"), "b")
    s.key("a", expires="60d").cert("a", "b").trust(a="u").ask("a").ask("b")
    for tag, rx in (("a", r"<[^>]+@one\.example>$"), ("b", r"<[^>]+[@.]one\.example>$"), ("c", r"one\.example>$"), ("d", r"@one\.example"), ("e", r"^T1"), ("f", r"(one|two)\.example")):
        s = c("c53%s-raw-expression" % tag, "one raw expression on the trust signature: %s" % rx)
        s.key("a").key("b").key("t1", domain="one.example").key("t2", domain="two.example")
        s.cert("a", "b", depth=1, regexes=[rx]).cert("b", "t1").cert("b", "t2").trust(a="u").ask("t1").ask("t2")
    s = c("c54-three-domains", "three domain expressions; only the third matches")
    s.key("a").key("b").key("t", domain="three.example")
    s.cert("a", "b", depth=1, domains=["one.example", "two.example", "three.example"]).cert("b", "t").trust(a="u").ask("t")
    probes = [r"@one\.example", r"one\.example", r"one.example", r"<tee@one\.example>", r"<tee@one\.example>$", r"<[^>]+@one\.example>", r"[^>]+@one\.example>$", r"<[^>]*@one\.example>$",
              r"<[^>]+[@.]one\.example>$", r"[@.]one\.example>$", r"\.example>$", r"example>$", r">$", r"^Tee", r"Tee", r"Tee One", r"(one)\.example", r"one|two", r"<tee", r".*", r"[a-z]+@one", r"tee@one", r"e@o",
              r"<[^>]+@one\.example>$".replace("+", "*"), r"<.+@one\.example>$", r"t.e@one", r"tee\@one", r"T\ee", r"tee@one\.example>"]
    s = c("c55-regex-probes", "which expressions GnuPG accepts on a trust signature for the user ID 'Tee One <tee@one.example>'")
    s.key("a").trust(a="u")
    for i, rx in enumerate(probes):
        s.key("b%d" % i).key("t%d" % i, uids=["Tee One <tee@one.example>"])
        s.cert("a", "b%d" % i, depth=1, regexes=[rx]).cert("b%d" % i, "t%d" % i, uid="Tee One <tee@one.example>")
        s.ask("t%d" % i, uid="Tee One <tee@one.example>")
    s.text += " | " + " ## ".join("%d=%s" % (i, rx) for i, rx in enumerate(probes))
    for seed in range(1, 31):
        out.append(random_web("c%02d-random-%d" % (79 + seed, seed), seed, "classic"))
    return out


# --------------------------------------------------------------------------------------------------------------------------------
class Tools:
    def __init__(self, sq=None, gpg=None):
        self.sq, self.gpg = sq, gpg

    def run(self, argv, binary=False, **kw):
        return subprocess.run(argv, capture_output=True, text=not binary, **kw)


def fpr_of(tools, path):
    r = tools.run([tools.sq, "packet", "dump", path])
    m = re.search(r"Fingerprint: ([0-9A-F]{40})", r.stdout)
    return m.group(1)


def sqcmd(tools, home, t, *args):
    r = tools.run([tools.sq, "--home", home, "--batch", "--time", iso(t), *args])
    if r.returncode != 0:
        raise RuntimeError("sq %s failed: %s" % (" ".join(args), r.stderr[-600:]))
    return r


def build(tools, s, work):
    home = os.path.join(work, "sqhome")
    os.makedirs(os.path.join(work, "k"))
    cur = {}   # name -> current public certificate file
    fp = {}
    n = [0]

    def nxt():
        n[0] += 1
        return os.path.join(work, "k", "step%03d.pgp" % n[0])

    for name, k in s.keys.items():
        key = os.path.join(work, "k", name + ".key")
        args = ["key", "generate", "--own-key", "--without-password", "--cipher-suite", "cv25519", "--output", key, "--rev-cert", key + ".rev"]
        for u in k["uids"]:
            args += ["--userid", u]
        if k["expires"]:
            args += ["--expiration", k["expires"]]
        sqcmd(tools, home, k["at"], *args)
        cert = key + ".cert"
        sqcmd(tools, home, k["at"], "key", "delete", "--cert-file", key, "--output", cert)
        cur[name] = cert
        fp[name] = fpr_of(tools, cert)
    keyfile = lambda name: os.path.join(work, "k", name + ".key")
    for st in s.steps:
        op = st["op"]
        if op == "cert":
            target_uid = st["uid"] or s.keys[st["to"]]["uids"][0]
            out = nxt()
            uidopt = ["--add-userid" if st["add_uid"] else "--userid", target_uid]
            if st["depth"] is None and not st["domains"] and not st["regexes"]:
                args = ["pki", "vouch", "add"]
            else:
                args = ["pki", "vouch", "authorize"]
            args += ["--certifier-file", keyfile(st["by"]), "--cert-file", cur[st["to"]], *uidopt, "--output", out]
            if st["amount"] is not None:
                args += ["--amount", str(st["amount"])]
            if args[2] == "authorize":
                d = st["depth"] if st["depth"] is not None else 1
                args += ["--depth", str(d)]
                if not st["domains"] and not st["regexes"]:
                    args += ["--unconstrained"]
                for dom in st["domains"]:
                    args += ["--domain", dom]
                for rx in st["regexes"]:
                    args += ["--regex", rx]
            if st["expires"]:
                args += ["--expiration", st["expires"]]
            if st["local"]:
                args += ["--local"]
            if st["nonrevocable"]:
                args += ["--non-revocable"]
            sqcmd(tools, home, st["at"], *args)
            cur[st["to"]] = out
        elif op == "revkey":
            out = nxt()
            sqcmd(tools, home, st["at"], "key", "revoke", "--cert-file", cur[st["name"]], "--revoker-file", keyfile(st["name"]), "--reason", st["reason"], "--message", "test", "--output", out + ".rev")
            cur[st["name"]] = merge(tools, home, fp[st["name"]], cur[st["name"]], out + ".rev", out)
        elif op == "revuid":
            out = nxt()
            uid = st["uid"] or s.keys[st["name"]]["uids"][0]
            sqcmd(tools, home, st["at"], "key", "userid", "revoke", "--cert-file", cur[st["name"]], "--revoker-file", keyfile(st["name"]), "--userid", uid, "--reason", "retired", "--message", "test", "--output", out + ".rev")
            cur[st["name"]] = merge(tools, home, fp[st["name"]], cur[st["name"]], out + ".rev", out)
        elif op == "revcert":
            cur[st["to"]] = gpg_revoke_cert(tools, work, keyfile(st["by"]), cur[st["to"]], fp[st["to"]], st["at"], st["uid"] or s.keys[st["to"]]["uids"][0])
    return cur, fp


def merge(tools, home, fingerprint, base, extra, out):
    """Joins a revocation (which sq writes as a bare packet set) into the certificate it belongs to, through a scratch certificate store."""
    scratch = home + "-merge"
    shutil.rmtree(scratch, ignore_errors=True)
    for f in (base, extra):
        r = tools.run([tools.sq, "--home", scratch, "--batch", "cert", "import", f])
        if r.returncode != 0:
            raise RuntimeError("import failed: " + r.stderr[-300:])
    r = tools.run([tools.sq, "--home", scratch, "--batch", "cert", "export", "--cert", fingerprint], binary=True)
    open(out, "wb").write(r.stdout)
    shutil.rmtree(scratch, ignore_errors=True)
    return out


def gpg_revoke_cert(tools, work, issuer_key, cert, target_fpr, at, uid):
    g = os.path.join(work, "gh%d" % at)
    os.makedirs(g, mode=0o700, exist_ok=True)
    base = [tools.gpg, "--homedir", g, "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback"]
    subprocess.run(base + ["--import", issuer_key], capture_output=True)
    subprocess.run(base + ["--import", cert], capture_output=True)
    # find the uid index
    lst = subprocess.run(base + ["--list-keys", "--with-colons", target_fpr], capture_output=True, text=True).stdout
    uids = [l.split(":")[9] for l in lst.splitlines() if l.startswith("uid:")]
    idx = uids.index(uid) + 1
    ts = subprocess.run(["date", "-u", "-d", "@%d" % at, "+%Y%m%dT%H%M%S"], capture_output=True, text=True).stdout.strip()
    script = "uid %d\nrevsig\ny\ny\n0\n\ny\nsave\n" % idx
    e = subprocess.run(base + ["--faked-system-time", ts, "--command-fd", "0", "--edit-key", target_fpr], input=script, capture_output=True, text=True)
    out = os.path.join(work, "k", "rev%d.pgp" % at)
    r = subprocess.run(base + ["--export", target_fpr], capture_output=True)
    if not r.stdout:
        raise RuntimeError("gpg could not revoke the certification: " + e.stderr[-500:] + lst[-300:])
    open(out, "wb").write(r.stdout)
    shutil.rmtree(g, ignore_errors=True)
    return out


def binary(tools, path):
    """The file's OpenPGP packets without ASCII armor (sq writes armor by default; the test data is binary)."""
    data = open(path, "rb").read()
    if data.lstrip().startswith(b"-----BEGIN"):
        r = subprocess.run([tools.sq, "packet", "dearmor"], input=data, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("dearmor failed: " + r.stderr.decode()[-300:])
        return r.stdout
    return data


def write_scenario(tools, s, outdir):
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as work:
        cur, fp = build(tools, s, work)
        d = os.path.join(outdir, s.name)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        with open(os.path.join(d, "certs.pgp"), "wb") as f:
            for name in s.keys:
                f.write(binary(tools, cur[name]))
        meta = dict(name=s.name, text=s.text, kind=s.kind,
                    keys={n: dict(fingerprint=fp[n], userIds=k["uids"]) for n, k in s.keys.items()},
                    roots=[fp[r] for r in s.roots], ownertrust={fp[n]: v for n, v in s.ownertrust.items()},
                    gpgArgs=s.gpg_args,
                    queries=[dict(target=fp[t], targetName=t, userId=(u or s.keys[t]["uids"][0]), at=a) for t, u, a in s.queries])
        json.dump(meta, open(os.path.join(d, "scenario.json"), "w"), indent=1)


# --------------------------------------------------------------------------------------------------------------------------------
def sq_version(tools):
    return tools.run([tools.sq, "version"]).stdout.split()[1] if tools.run([tools.sq, "version"]).stdout else "unknown"


def expect_sq(tools, outdir):
    v = tools.run([tools.sq, "version"]); ver = "sq-" + re.search(r"(\d+\.\d+\.\d+)", v.stdout + v.stderr).group(1)
    for name in sorted(os.listdir(outdir)):
        d = os.path.join(outdir, name)
        meta = json.load(open(os.path.join(d, "scenario.json")))
        if meta["kind"] != "flow":
            continue
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as work:
            home = os.path.join(work, "h")
            r = tools.run([tools.sq, "--home", home, "--batch", "cert", "import", os.path.join(d, "certs.pgp")])
            results = []
            for q in meta["queries"]:
                args = [tools.sq, "--home", home, "--batch", "--time", iso(q["at"])]
                for root in meta["roots"]:
                    args += ["--trust-root", root]
                args += ["pki", "authenticate", "--cert", q["target"], "--userid", q["userId"], "--show-paths", "--gossip"]
                r = tools.run(args)
                results.append(dict(query=q, exit=r.returncode, stdout=r.stdout, stderr=r.stderr[-400:]))
        json.dump(dict(oracle=ver, results=results), open(os.path.join(d, "expected.%s.json" % ver), "w"), indent=1)


def expect_gpg(tools, outdir):
    ver = "gnupg-" + re.search(r"(\d+\.\d+\.\d+)", tools.run([tools.gpg, "--version"]).stdout).group(1)
    for name in sorted(os.listdir(outdir)):
        d = os.path.join(outdir, name)
        meta = json.load(open(os.path.join(d, "scenario.json")))
        if meta["kind"] != "classic":
            continue
        results = []
        listed = {}   # reference time -> parsed listing: one GnuPG home per time is enough for every query at that time
        for q in meta["queries"]:
            if q["at"] not in listed:
                with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as work:
                    g = os.path.join(work, "g")
                    os.makedirs(g, mode=0o700)
                    faked = subprocess.run(["date", "-u", "-d", "@%d" % q["at"], "+%Y%m%dT%H%M%S"], capture_output=True, text=True).stdout.strip()
                    base = [tools.gpg, "--homedir", g, "--batch", "--no-tty", "--faked-system-time", faked, "--trust-model", "pgp", *meta["gpgArgs"]]
                    subprocess.run(base + ["--import", os.path.join(d, "certs.pgp")], capture_output=True)
                    ot = "".join("%s:%s:\n" % (fp, {"q": 2, "n": 3, "m": 4, "f": 5, "u": 6}[lv]) for fp, lv in meta["ownertrust"].items())
                    subprocess.run(base + ["--import-ownertrust"], input=ot, capture_output=True, text=True)
                    subprocess.run(base + ["--check-trustdb"], capture_output=True)
                    r = subprocess.run(base + ["--list-keys", "--with-colons", "--fixed-list-mode"], capture_output=True, text=True)
                    keys, cur = {}, None
                    for line in r.stdout.splitlines():
                        f = line.split(":")
                        if f[0] == "pub":
                            cur = dict(pub=f[1], uids=[], fpr=None)
                        elif f[0] == "fpr" and cur is not None and cur["fpr"] is None:
                            cur["fpr"] = f[9]
                            keys[f[9]] = cur
                        elif f[0] == "uid" and cur is not None:
                            cur["uids"].append(dict(userId=f[9], validity=f[1]))
                    listed[q["at"]] = (keys, r.stderr[-300:])
            keys, err = listed[q["at"]]
            k = keys.get(q["target"], dict(pub=None, uids=[]))
            results.append(dict(query=q, pub=k["pub"], uids=k["uids"], stderr=err))
        json.dump(dict(oracle=ver, results=results), open(os.path.join(d, "expected.%s.json" % ver), "w"), indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["generate", "expect-sq", "expect-gpg"])
    ap.add_argument("out")
    ap.add_argument("--sq")
    ap.add_argument("--gpg")
    ap.add_argument("--only")
    a = ap.parse_args()
    tools = Tools(a.sq, a.gpg)
    if a.mode == "generate":
        for s in flow_scenarios() + classic_scenarios():
            if a.only and not re.search(a.only, s.name):
                continue
            write_scenario(tools, s, a.out)
            print("generated", s.name, file=sys.stderr)
    elif a.mode == "expect-sq":
        expect_sq(tools, a.out)
    else:
        expect_gpg(tools, a.out)


if __name__ == "__main__":
    main()
