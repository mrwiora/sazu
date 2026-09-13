# Prerequisites for porting SAZU to a DNS server codebase

SAZU (Self-Authenticated Zone Update) is meant to eventually be
implementable across major open-source DNS servers, not just one. This is
a checklist of what a candidate codebase should already offer — or make
easy to add — before starting a port, distilled from experience actually
building SAZU against real DNS server codebases. Treat it as a readiness
assessment to run against a codebase *before* committing to a port, not as
an implementation plan.

For each item: what to check, and why it matters specifically for SAZU
(not DNS servers in general).

## 1. Wire-format extensibility

Can the codebase parse and encode `DNSKEY`, `RRSIG`, `DS`, and (ideally)
`NSEC`/`NSEC3` RDATA, or would that need to be added? Does record decoding
work on raw byte slices rather than only ever producing a fully-typed
in-memory model — i.e., can you get at the *exact bytes* of a message as
received? RFC 2931 SIG(0) signs literal wire bytes, not a re-serialization
of parsed fields; a codebase that always round-trips through its own
encoder before you can inspect a message will fight you here. Also check
whether the RR type enum and RDATA decoder are structured so adding a new
type is a contained, additive change (a `match` arm) rather than a
pervasive one.

## 2. RFC 2136 dynamic UPDATE support

Does the server already parse/handle UPDATE messages (even if it rejects
them today), or is that from scratch? Either is workable, but "from
scratch" means budgeting real time for all 5 prerequisite forms and 4
update forms, plus their wire-format quirks (empty RDATA as a wildcard,
the `NONE`/`ANY` class overloads) — this is a full implementation pass in
its own right, worth its own dedicated test suite rather than a quick
patch bolted onto whatever query-parsing code already exists.

## 3. A pluggable authentication point for UPDATE

Is there already a hook where an incoming UPDATE gets authenticated (TSIG,
ACL, anything), or does authentication have to be threaded in from
scratch alongside everything else? SAZU's entire trust model rides on
SIG(0) verification happening *before* any prerequisite or update op is
applied — a codebase that applies updates inline while parsing, with no
clean pre-apply checkpoint, needs restructuring before SAZU can be bolted
on safely.

## 4. Cryptographic library availability

Is there already a maintained, audited crypto dependency in the project
(e.g. `ring`, OpenSSL bindings, libsodium) that supports RSA-SHA256/512,
ECDSA P-256/P-384, and Ed25519 verification? SIG(0) and DNSSEC RRSIG
verification need all three algorithm families to interoperate with
real-world keys and real TLDs. Pay specific attention to key encoding
mismatches between the DNS wire format and the crypto library's API — DNS
elliptic-curve public keys are raw concatenated X||Y coordinates with no
format tag, while most general-purpose crypto libraries expect a leading
`0x04` (SEC1 uncompressed point) or a full ASN.1/SPKI wrapper. This is a
one-line fix once you know to look for it, but a silent, hard-to-diagnose
failure if you don't.

## 5. EDNS(0) DO-bit control on outbound queries

Can the resolver's outbound queries (the ones it sends to other servers,
not the ones it answers) be told to set the DNSSEC OK bit? The
chain-of-trust cross-check needs RRSIGs returned alongside DNSKEY/DS
answers, which most authoritative servers only include when asked with DO
set. If the existing resolver's query-building code has no such knob,
decide up front whether to extend it (touches a hot path used by every
normal query) or write isolated, validation-only query functions instead
(more code, zero risk to existing traffic) — this is a real fork in the
road, not a detail.

## 6. A live zone-mutation API

Can a single RRset be added, replaced, or deleted in an already-loaded,
already-serving zone, without reloading the whole zone from a file or
database? Many authoritative implementations treat zone data as
effectively immutable after load (reload-from-disk is the only "update"
path) — that model is incompatible with SAZU, which needs sub-second
application of a signed update to already-serving data. Check specifically
for: (a) a mutation API scoped to one RRset, not the whole zone, and (b) a
concurrency model that lets that mutation happen safely while other
threads/tasks are answering read queries against the same zone
(`RwLock`/similar over the zone store, not a full-zone copy-on-write that
would make frequent small updates expensive).

## 7. A policy hook for first-contact zone creation

SAZU's first-contact case is a signed update for a zone the server has
never heard of before — should the server create that zone on the fly
(and if so, what SOA/NS does it synthesize), or does every zone need to be
provisioned out-of-band first? This is a product decision the codebase
needs to have *a place* for, not a cryptographic one — check whether
zone-creation is a first-class, callable operation, or something that only
happens via startup-time config parsing.

## 8. Root trust anchor / DNSSEC validation scaffolding

Does the codebase already carry hardcoded root trust anchors or any
DNSSEC signature validation code (even a recursive-resolver-side
validator) to build on, or is the whole chain-of-trust check starting from
zero? Existing scaffolding — even partial or stubbed — saves real time and
usually means someone already made the "how do we keep trust anchors
updatable" decision you'd otherwise have to make fresh.

## 9. Opcode dispatch extensibility

Is there one clear place where an incoming message's opcode (Query,
Update, Notify, ...) is switched on, or is opcode handling implicit /
scattered (e.g. a fast path that only checks the QR bit and assumes
everything else is a query)? The latter is a latent correctness bug
independent of SAZU — an UPDATE message sent to a server that doesn't
check opcode gets silently misinterpreted rather than rejected — and it's
worth fixing before adding SAZU on top, not after.

## 10. Abuse-prevention / rate-limiting hooks

Is there an existing per-source-IP rate limiter or ACL layer that new
logic can register against, or would SAZU's abuse-prevention rules (e.g.
throttling repeated "no DS published for this key" attempts) need their
own bespoke mechanism? Reusing an existing framework is strongly
preferable — a second, parallel rate-limiting system is its own source of
bugs.

## 11. A library/binary (or module/executable) separation

Can the wire-format and cryptographic code be reused from a *second*,
independent binary — a minimal test client and a minimal test authority —
without duplicating it or dragging in the whole server? Building and
exercising SAZU's crypto against synthetic keys and a stub parent zone,
completely offline from any production traffic, is what makes a port's
test suite trustworthy without ever touching real DNS infrastructure. A
codebase where everything is internal to a single monolithic binary, with
no importable package/library boundary around the wire-format and crypto
code, needs a refactor first — splitting that code out into its own
reusable module — before this kind of testing is possible.

## 12. License and contribution norms

Is the codebase's license (and, if relevant, its CLA/contribution process)
compatible with adding and eventually upstreaming a security-sensitive
protocol extension? Worth confirming before investing implementation time,
given the stated goal of this project is a SAZU implementation usable
across multiple servers, not a permanent fork of any one of them.
