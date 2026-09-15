# SAZU

**Self-Authenticated Zone Update** — a client-held signer pushes DNSSEC-signed zone content to a hoster that never sees the private key, authenticated by nothing but the update's own signature.

*Design Document · split-signing DNSSEC*

| | |
|---|---|
| Status | Proposal, v1.5 |
| Scope | Client signer → hoster ingestion |
| Assumes | single active signer per zone |
| Auth | SIG(0) only, decided (§9.1) |
| Carriers | 7.2 raw DNS + 7.3 HTTPS, both supported |

> **Abstract**
>
> SAZU authenticates every message with a single mechanism — SIG(0) (RFC 2931) signing a standard RFC 2136 dynamic update — and supports two equally valid carriers for that same message: raw DNS wire format, or the identical content re-encoded as JSON per RFC 8427 for delivery over plain HTTPS. Neither carrier changes what's decided; §9.1 records why SIG(0) alone, not TSIG, is the authentication mechanism. What no carrier gets you out of is one specific piece of server logic: today's DNS servers assume *they* generate RRSIG records on update (RFC 3007 §CN says so explicitly) and will strip or refuse foreign ones. Accepting a client-signed RRSIG instead of generating your own is the one deliberate, custom deviation this design makes on purpose — not a gap in the standard, a policy choice.

> **Why "SAZU"**
>
> The name describes the mechanism, not a brand: every message in this design — first contact (§10.2), an ordinary push (§6), a key rollover (§10.4) — authenticates itself using the key it already carries, rather than a separately provisioned secret or account. "Self-authenticated" is literal, not marketing.

## Contents

1. [Goals](#1-goals)
2. [Non-goals](#2-non-goals)
3. [Threat model](#3-threat-model)
4. [Two independent design axes](#4-two-independent-design-axes)
5. [The update bundle](#5-the-update-bundle)
6. [Server-side acceptance algorithm](#6-server-side-acceptance-algorithm)
7. [Transport variants](#7-transport-variants)
8. [Comparison](#8-comparison)
9. [Recommendation](#9-recommendation)
10. [Key bootstrap & rollover](#10-key-bootstrap--rollover)
11. [Delegation-change monitoring & alerting](#11-delegation-change-monitoring--alerting)
12. [Operational concerns](#12-operational-concerns)
13. [Open questions](#13-open-questions)
14. [Deferred to post-PoC](#14-deferred-to-post-poc)

---

## 1. Goals

- The client (you) holds the ZSK/KSK and computes every RRSIG. The hoster never receives, generates, or stores private key material.
- The client runs **no listening service** — no open inbound port, no daemon, no always-on process. A cron job or a CI pipeline step is enough.
- The hoster's server only needs to *accept, verify, and serve* — it does not sign anything itself.
- Authorization to publish is anchored in **possession of the signing key**, not (only) a separately provisioned secret that has to be rotated on its own schedule.
- Prefer wire formats and authentication mechanisms that already have IETF numbers and existing client tooling, over inventing new ones.

## 2. Non-goals

- Multi-signer DNSSEC (RFC 8901) — this document assumes one signer of record per zone, not two providers signing independently.
- Zone transfer (AXFR/IXFR) as the primary mechanism — that's the pull-based hidden-primary pattern covered in the earlier comparison; this document is the push-based alternative.
- Automated parent-side DS updates (RFC 7344 / CDS-CDNSKEY) — relevant to key rollover, referenced in §10, but not designed here.

## 3. Threat model

| Actor | Trusted for | Not trusted for |
|---|---|---|
| You (signer) | Holding the ZSK/KSK, deciding what the zone should contain | — |
| Hoster | Availability, anycast, answering queries correctly for what it was given | Publishing content that didn't come from you, tampering with content in transit or storage |
| Network attacker | — | Injecting updates, replaying a stale-but-still-valid signed update to roll the zone back |
| A leaked API key / TSIG secret | — | Should *not* be sufficient on its own to publish arbitrary content — the RRSIG check is the hard backstop, transport auth is defense-in-depth |

The consequence: transport authentication (TSIG/SIG(0)/mTLS) answers *"is this sender allowed to talk to the update endpoint at all"*; it must not be treated as answering *"is this content valid to publish."* Only a DNSSEC signature check against the zone's own DNSKEY answers the second question. Both checks run on every accepted variant.

> **Explicitly out of scope — compromise of the parent**
>
> Everything above assumes the parent/registry's delegation (NS) and DS record for the zone are themselves trustworthy. If an attacker instead compromises the registrar or registry relationship and rewrites *both* NS and DS, they've redirected the entire delegation to their own infrastructure — no part of this protocol is even in the request path anymore, because a validating resolver only ever checks "does the current DS match the current DNSKEY right now," with no memory of what it was yesterday. A cryptographically clean takeover at the parent is indistinguishable from a legitimate key rotation to every validator on earth, including this protocol's own §10.2 bootstrap check. Nothing at the push-protocol layer can fix that, because the parent relationship is the root of authority this zone's entire chain of trust is anchored to. The real mitigations live one layer up: Registry Lock (out-of-band confirmation for any NS/DS/contact change at the registry, specifically survives a compromised registrar account), hardened registrar-account access (hardware MFA, no email-based recovery), and independent monitoring of your own live delegation so an unannounced change is caught fast rather than never. RFC 5011 shows the shape a protocol-level defense against this *could* take — a mandatory 30-day hold-down before a resolver accepts a new root trust anchor, so a single flash compromise can't flip trust — but that mechanism exists only at the root; no equivalent hold-down is mandated between a registry and an ordinary delegated zone.
>
> **The accepted position:** the parent chain is trusted at the exact moment of first contact (§10.2) — that trust decision has to be made somewhere, and the chain of trust up to the root is the least-bad place to make it. If the parent is tampered with *after* first contact, this is a detection problem, not a prevention problem: §11's watch loop exists specifically to notice a divergence between what was authorized at bootstrap and what the parent says now, and alert the registered contact (§10.6) when it happens. This document does not try to make that divergence impossible — only to make it loud.
>
> **On the hoster's own database:** the infrastructure is assumed secure — that's a precondition of running any of this, not something the protocol re-derives. If it's tampered with anyway (an insider, a breach, a bug), the claim "the signatures won't validate against the parent, so it's fine" is *half* true and needs stating precisely rather than accepted as a full answer: for a DNSSEC-*validating* resolver, a database rewrite that doesn't also compromise the parent (§3, above) does degrade to a visible, self-limiting failure — SERVFAIL, not a silent lie — because the tampered content's signatures won't match the real chain of trust. But for the still-substantial population of *non-validating* resolvers and clients, nothing in this protocol catches a direct database rewrite at all — they trust whatever DNS answer arrives, validated or not, and a compromised database serves them tampered content with no visible symptom. So: real containment for validating consumers, no protection at all for non-validating ones. Ordinary database hygiene — least-privilege access, no direct write path outside the push-acceptance code, its own audit log — remains necessary; this protocol was never going to be what provides it.

## 4. Two independent design axes

The three variants in §7 differ only in **transport**. A second axis — how deeply the server inspects content before publishing — is orthogonal and applies identically to all three:

| Level | Server does | Catches | Cost |
|---|---|---|---|
| 0 — Trust the pipe | Authenticates the transaction (TSIG/SIG(0)), stores attached RRs verbatim | Nothing content-wise | None |
| 1 — Sanity check | + Checks RRSIG inception/expiration window, algorithm number, key tag reference exists | Expired or malformed signatures, wrong key | Low — no crypto library needed |
| 2 — Full verification | + Cryptographically verifies each RRSIG against the pinned DNSKEY | Bad signatures, tampering, corrupted RDATA | Real work — a from-scratch DNSSEC validator, not something to stub out |

> **Decision**
>
> Level 2 — full cryptographic verification — is mandatory, unconditionally. There is no server-side mode that accepts content without verifying it. SIG(0) alone proves who sent a transaction, never that the zone content it carries would actually validate for a real DNSSEC resolver once served, which is the one property this whole design exists to guarantee; accepting content nothing has checked is never a legitimate operating mode. Levels 0 and 1 are recorded above for comparison — they name what a partial check would look like and why it would be cheaper — not as accepted alternatives.

## 5. The update bundle

All three variants carry the same logical content, because all three are, underneath, an RFC 2136 UPDATE transaction. RFC 2136 already defines the two properties a naive custom protocol would have to invent from scratch: a **prerequisite** section for optimistic concurrency, and an atomic **update** section.

| RFC 2136 section | Carries | Purpose |
|---|---|---|
| Zone | Zone name + class | Which zone this transaction targets |
| Prerequisite | `SOA serial == last-known-serial` | Built-in staleness/replay guard — rejects the update if the hoster's state has moved since you last read it. No custom "manifest signature" needed. |
| Update — delete | A retired key's own DNSKEY entry (§10.4/§10.9) | The one case content removal still needs an explicit op: everything else is superseded by the next full push's replace-on-apply rule (below), not deleted piecemeal |
| Update — add | Every record in the zone, their RRSIGs, a freshly computed NSEC/NSEC3 chain + RRSIGs, bumped SOA + its RRSIG, or (a trust-establishing message, §10.9) the KSK+ZSK DNSKEY RRset alone | The actual signed content |
| Additional | SIG(0) record | Transaction authentication (added automatically by `nsupdate`) |

> **Decision: full-zone push only**
>
> Every push carries the zone's complete, authoritative content — there is no differential/partial update mode. The Update section's adds are the zone's entire current state, full stop; the hoster treats them as an authoritative replacement, purging anything previously served that the new push doesn't re-assert (§6 step 5) rather than requiring the client to enumerate deletions itself. An ordinary RFC 2136 add is never itself a deletion, so without this rule a name dropped from one push to the next would simply linger being served forever; the replace-on-full-push rule closes that outright rather than leaving it to each client's own care.
>
> A differential push (only the changed RRsets, plus whichever NSEC/NSEC3 records their insertion or removal touches) was considered and rejected. It has one structural failure mode a full-zone push doesn't: detecting that a name was *removed* requires the signer to know the zone's complete current name set, which is exactly what NSEC3's own hashed owner names are designed to hide — a hash with no matching candidate among names the signer already expects cannot be resolved back to which real name should be removed. That's NSEC3's hiding property working as designed, not a bug, but it means a differential push can be made to work for additions and still be structurally unable to guarantee correctness for removals. Every record's own RRSIG and the transaction's overall SIG(0) already fully authenticate content regardless of how much of the zone one push carries, so replacing the whole zone is exactly as safe as replacing one record — and, unlike a differential push, needs the signer to hold no memory of prior state at all: its own zone definition simply *is* the push, every time.
>
> This trades bandwidth for correctness at scale — re-signing and transmitting an entire zone on every change costs real bandwidth and signing time for a large zone. Revisit only once a deployment's actual zone sizes make that cost the binding constraint, not speculatively; nothing about the rejection above weakens once zones get larger, so any future differential mechanism would need to solve the NSEC3 removal problem for real, not route around it.

> **NSEC vs. NSEC3 — a client/signer choice, not a protocol decision**
>
> SAZU's server side never generates a denial-of-existence chain itself — it only stores and serves whatever NSEC or NSEC3 records arrive already signed, exactly like any other RRset. The choice between them is entirely the client-side signer's to make:
>
> - **NSEC** (RFC 4034) — each record names the next existing owner name in canonical order. Simple, no hashing, no parameters to choose. The trade-off: the chain is trivially walkable, so anyone can enumerate every name in the zone by following successive NSEC records, even ones never otherwise queried.
> - **NSEC3** (RFC 5155) — each record names the next *hashed* owner name instead, so a walker only ever sees hashes, not the real names. This defeats casual zone enumeration (a targeted dictionary attack against guessable names is still possible, but blind walking isn't). The historical complexity — choosing a salt and iteration count — has a settled answer now: **RFC 9276** recommends **zero iterations and an empty salt**; extra iterations were found to mostly cost CPU on both signer and validator without materially raising the bar. At iterations=0, NSEC3 costs about the same to compute and serve as plain NSEC.
>
> Given RFC 9276's current guidance removes NSEC3's old cost penalty, **NSEC3 with zero iterations, no salt, opt-out disabled** is the reasonable default recommendation for a new deployment — it buys enumeration resistance for free. NSEC remains a perfectly fine choice where a client's signer tooling defaults to it, or enumeration resistance isn't a concern for that zone; SAZU supports either without caring which.

> **Operational note — NSEC chains**
>
> Inserting one name touches two NSEC(3) records regardless of which is used: the new name's own, and its predecessor's "next" pointer. A full-zone push sidesteps this entirely by recomputing the whole chain from scratch on every push, rather than patching it incrementally — a real source of chain-consistency bugs the decision above avoids by construction, not just for now.

## 6. Server-side acceptance algorithm

Identical across both carriers — only how the message arrives (§7) changes.

```
0. Is a key already pinned for this zone?

   NO  (first contact — see §10.2):
       - Require a DNSKEY RRset in this message.
       - Verify the transaction signature (SIG(0)) is
         self-consistent with what's in THIS message.
         → reject on failure.
       - If a DS exists at the parent: fetch it (+ live DNSKEY if
         migrating), validate the chain, require the delivered key's
         digest to match. → reject on mismatch.
       - If no DS exists yet: → reject (ERR_NO_DS_PUBLISHED). Publish
         a DS at the registrar first — no self-consistency-only
         fallback, to keep this endpoint from being a database-
         flooding vector for unverifiable zone names.
       - Record this request's arrival time and pin the delivered key
         via an atomic compare-and-set on the zone's registration row
         (INSERT ... ON CONFLICT / equivalent) keyed on "no key pinned
         yet" — never a read-then-write. If two self-consistent,
         validly-signed first-contact requests race for the same
         unclaimed zone, the CAS lets exactly one commit; the loser's
         request is retried by the normal "subsequent contact" path
         and rejected as REFUSED, since a key is now pinned. Where a
         tiebreak is somehow still needed (e.g. the CAS key is coarser
         than per-request), the earlier of the two recorded arrival
         timestamps wins, never an implicit "whoever the database
         happened to serialize last."
       - This message's own RRSIGs are now verifiable — continue to
         step 1 using it.

   YES (subsequent contact):
       - Verify the transaction signature against the PINNED key.
         → reject with REFUSED on mismatch.
       - A different key is only accepted via the §10.4 rollover
         flow — never by simply substituting one in a normal push.

1. Parse the UPDATE message into: prerequisites, deletes, adds.

2. Check prerequisite: current stored SOA serial == expected serial.
   → reject with NXRRSET/YXRRSET mismatch (RFC 2136 §2.4) if stale.

3. For each added RRSIG (Level 1+):
     - inception <= now <= expiration, with sane bounds
     - algorithm and any DS digest type meet the §10.7 floor
       (SHA-256+, no RFC 8624 "MUST NOT"/"NOT RECOMMENDED" algorithms)
     - key tag references a DNSKEY already on file (or bundled + itself
       validly signed by an already-pinned key, for rollover — see §10)
   → reject the whole transaction on any failure (all-or-nothing).

4. For each added RRSIG (Level 2 only):
     - cryptographically verify the signature covers exactly the
       RRset being published, using the referenced key
   → reject the WHOLE transaction if even ONE RRSIG fails —
     no partial application, ever, even if every other record in
     the same push is perfectly valid. Record exactly which
     name/type failed and why, for step 7's feedback.

5. If this message carries a real SOA (an ordinary content push, per
   §5's full-zone-push-only decision): replace the zone's entire
   served content with exactly what this message's adds contain —
   anything previously served that isn't re-asserted here is removed,
   without needing its own explicit delete op. Otherwise (a
   trust-establishing or key-management message, §10.9, which carries
   a DNSKEY RRset and nothing else): apply only the deletes and adds
   present, leaving all other served content untouched. Either way,
   apply atomically and store the new SOA serial when one was sent.

6. Trigger the existing live-reload path (e.g. Postgres NOTIFY) so
   the zone is served immediately, once step 4/5 have actually
   passed (see the note on synchronous vs. queued Level 2 below).

7. Respond: the DNS RCODE for basic interoperability (NOERROR /
   FORMERR / SERVFAIL / REFUSED / NXRRSET / YXRRSET), plus a SAZU
   status code in the Additional section (§12) — e.g. OK,
   ERR_STALE_SERIAL, ERR_UNKNOWN_SIGNER, ERR_SIG_INVALID,
   ERR_EXPIRED_SIGNATURE, ERR_WEAK_ALGORITHM, ERR_QUOTA_EXCEEDED,
   ERR_RATE_LIMITED, ERR_NO_DS_PUBLISHED — each carrying the
   specific name/type/reason that failed (e.g. "www.example.org.
   A: signature does not verify against key tag 51286"), plus a
   transaction UUID the client can use to query final status later
   (see below), not just the bare code.
```

> **Synchronous vs. queued Level 2**
>
> Resolved as a hybrid rather than picking one: steps 1–3 (parse, prerequisite, Level 0/1 checks) always run synchronously — they're cheap, and their result is in the step 7 response immediately. Level 2's full cryptographic verification (§4) *may* run synchronously too for a small push, or be queued and completed asynchronously for a larger one; either way, step 5's apply only happens once Level 2 has actually passed, never optimistically before it. The immediate response always carries a **transaction UUID**; if Level 2 was queued rather than completed inline, that UUID is how the client later asks "did it actually go live" rather than assuming a fast ack meant success. A queryable status endpoint for this is worth building; a GraphQL interface for it specifically is a reasonable direction if the rest of the client tooling ends up wanting one, but that's an implementation choice, not a protocol requirement.

## 7. Transport variants

SAZU has exactly one authentication mechanism — SIG(0), decided in §9.1 — and **two equally supported carriers** for it. Neither is a fallback for the other; pick whichever fits the network path between you and the hoster. TSIG was considered and is documented below for the record, but it isn't an adopted option.

### 7.2 SAZU over raw DNS UPDATE — carrier A
*RFC 2136 · RFC 2931*

The transaction is a standard RFC 2136 UPDATE message, authenticated with a public-key signature (SIG(0)) instead of a shared secret — `nsupdate -k` auto-detects a SIG(0) keypair by file format. This is the arrangement where **the same key that signs your zone data also authorizes the transaction that delivers it** — "accept the update because it carries a valid signature," never "accept the update because it carries a secret."

Setup cost: the hoster needs to record your public KEY once (§10), rather than paste in a shared secret. Adoption of SIG(0) in the wild is thin — it's real, it's standard, but plan to write your own thin client wrapper rather than relying on wide library support. Use this carrier when outbound 53/tcp+udp is available.

**Algorithm for SIG(0) specifically:** start with RSA where a client's SIG(0) library already supports it comfortably — library maturity there is still RSA-centric, and there's no reason to fight that for the transport-signature algorithm. Ed25519 is explicitly also accepted, even where that means writing the verification/signing glue by hand rather than leaning on existing SIG(0) tooling — worth the extra code for a smaller, faster, more modern default. Nothing here couples the SIG(0) transport algorithm to §10.7's DNSSEC content-signing algorithm; a zone can reasonably use one for its RRSIGs and a different one for its SIG(0) transaction signatures.

### 7.3 SAZU over HTTPS, JSON-encoded — carrier B
*RFC 2136 semantics · RFC 8427 encoding · RFC 2931 auth*

The exact same message as 7.2 — same sections, same SIG(0) record, same server-side acceptance logic (§6) — just serialized with RFC 8427's standard DNS-message-as-JSON format (media type `application/dns+json`) and delivered as a plain HTTPS POST instead of raw UDP/TCP port 53. Use this carrier when the hoster's ingestion point sits behind a normal HTTPS load balancer, or when your own network only allows outbound 443 — it is not a lesser option, only a different envelope around the identical, identically-authenticated content.

```
POST /update HTTP/1.1
Host: push.hoster.example.net
Content-Type: application/dns+json

{
  "ID": 41312, "QR": 0, "Opcode": 5,
  "Zone":         [{"name":"example.org.","type":"SOA","class":"IN"}],
  "Prerequisite": [{"name":"example.org.","type":"SOA","class":"IN",
                     "TTL":0,"rdata":"... last-serial ..."}],
  "Update": [
    {"name":"www.example.org.","type":"A","class":"IN","TTL":300,
     "rdata":"203.0.113.10"},
    {"name":"www.example.org.","type":"RRSIG","class":"IN","TTL":300,
     "rdata":"A 13 3 300 ... <base64 signature> ..."}
  ],
  "Additional": [ /* SIG(0) record, same as 7.2 */ ]
}
```

**Honest caveat:** no existing server accepts an RFC 8427-encoded UPDATE over HTTP today — you're writing both ends. What you get in exchange is a payload every HTTP client, proxy, and logging tool already understands, and a message shape that stays faithful to RFC 2136 instead of inventing a bespoke schema.

> **Considered, not adopted — TSIG (RFC 8945)**
>
> The obvious third option: the same RFC 2136 UPDATE, authenticated with a pre-shared HMAC secret (`tsig-keygen`) instead of SIG(0). It's the most widely supported mechanism in existing DNS tooling, which made it a real contender. §9.1 records why it wasn't adopted: a shared secret is a second thing to provision, transmit once, and rotate, separate from the DNSSEC key already doing the real authorization work — SIG(0) does the same job with nothing but the key that's already there. Kept here for the comparison, not as a supported carrier.

> **If standards-alignment doesn't matter to you**
>
> The simplest possible thing, full stop, is a signed zone file committed to a small git repo, pushed over SSH to a bare repo on the hoster with a `post-receive` hook that runs the §6 algorithm and reloads. Zero new client library, free version history, trivial rollback via `git revert`. It isn't a DNS protocol in any sense — it's SSH plus the decades-old RFC 1035 zone-file format — which is exactly why it's out of scope for the "aligned with public standard" ranking above, but worth knowing it's available.

## 8. Comparison

| Carrier | Wire standard | Auth | Client tooling | Firewall friendly | Debuggable with curl |
|---|---|---|---|---|---|
| 7.2 Raw DNS UPDATE | RFC 2136 | SIG(0), public key | `nsupdate`, thin wrapper | Needs 53/tcp+udp out | No |
| 7.3 JSON over HTTPS | RFC 8427 | SIG(0), same record as 7.2 | Any HTTP client | 443/tcp only | Yes |

## 9. Recommendation

- **7.2 (raw DNS UPDATE) and 7.3 (JSON over HTTPS) are equally valid** — same authentication, same server-side acceptance logic, same guarantees. Choose by network fit, not by preference ranking: 7.2 if outbound 53/tcp+udp is open and you're comfortable writing a small SIG(0) client wrapper; 7.3 if port 53 is blocked somewhere in your path, or the hoster's ingestion point is HTTP-ingress-only. A hoster can reasonably support both endpoints for the same underlying protocol at low incremental cost, since §6's acceptance algorithm doesn't change either way.
- **TSIG (§7's "considered, not adopted" note) is out of scope** — SAZU authenticates every message with SIG(0), full stop; see §9.1 for why.

### 9.1 Decision

> **Decision record**
>
> **Chosen: SIG(0) (RFC 2931) as SAZU's sole authentication mechanism, carried equally over 7.2 (raw RFC 2136 UPDATE) or 7.3 (RFC 8427 JSON over HTTPS). TSIG (RFC 8945) considered, not adopted.** — *Status: Accepted*
>
> **Primary driver (stated reason):** using the same key for transaction authorization and zone-content signing means there is nothing to register beyond the key itself — no shared secret to provision, no traditional account (login, password, session) to build or secure on the hoster's side. The "customer" of this feature is simply whoever holds a private key, exactly mirroring how an ACME account (§10.6) is nothing but a key pair, never a username/password identity. Onboarding collapses to "send a self-consistent first request" (§10.2), with no separate registration surface to design, secure, or support. This holds identically whether the message arrives via 7.2 or 7.3 — the decision is about the signature, not the wire it rides on.
>
> **Known, accepted limitation:** RFC 2931 cautions against using zone keys for SIG(0) (a SIG(0) signer should be a host/user identity, not a zone). A fuller resolution — treating "the key" as one entry in a per-zone set of independently-authorized signers — was explored and deliberately deferred (§10.2) rather than folded into this version: it's real added complexity for a first release, and it's cleanly buildable later as a layer on the customer's own side rather than a core-protocol change. The rationale above is accepted as sufficient for the default, single-signer case this version ships with.

**Additional security drivers, for the record:**

- **Asymmetric secrets only — nothing to leak from the hoster's side.** TSIG requires the hoster to store a symmetric secret whose disclosure directly enables forgery. SIG(0) requires the hoster to store only a public key, which is safe to leak, log, or display by definition — a breach of the hoster's own database exposes nothing an attacker can act on.
- **One kind of secret in the system, not two.** TSIG would mean managing an independent secret per zone alongside its DNSSEC signing keys — the shared secret and the KSK/ZSK pair (§10.9), each with its own generation, storage, and rotation lifecycle that can independently drift or leak. SIG(0) needs nothing beyond the DNSSEC keys the zone already has, authorized by the one rollover procedure (§10.4) those keys already need regardless.
- **No secret-provisioning channel to secure.** A TSIG secret needs at least one moment where it travels from you to the hoster — a support ticket, a web form, a copy-paste — and that moment is itself an attack surface. A public key has no equivalent requirement; it's safe on any channel, by construction.
- **Non-repudiation.** TSIG's symmetric MAC means the hoster holds everything needed to produce a transaction indistinguishable from a genuine one; SIG(0)'s asymmetric signature means only the private-key holder can produce a valid one. The accepted-transaction audit log (§12) becomes cryptographic proof of authorization, not just an administrative record.
- **One trust model, end to end.** First contact (§10.2), ordinary pushes (§6), and rollover (§10.4) are already all built around "prove possession of a specific private key." SIG(0) is the one variant where that's also true of the transport, so the whole protocol reduces to a single mental model rather than two different trust mechanisms (possession-based and secret-based) sitting side by side.

> **Accepted trade-off**
>
> SIG(0) has thin real-world library support compared to TSIG — a small client-side wrapper needs to be written rather than relying on `nsupdate` to do everything out of the box, for either carrier. Recorded here so it's a known, accepted cost rather than a surprise found mid-implementation.

## 10. Key bootstrap & rollover

Reworked per your follow-up: **nobody places a key anywhere, ever, as a separate step.** §5 already makes the DNSKEY RRset mandatory content of the bundle — delivering it is simply part of sending a well-formed request. Trust establishment falls out of that for free: the first request the hoster accepts for a zone *is* the act of establishing which key is trusted, because that key arrived as a required field of the request itself, not through a side channel.

### 10.1 The one thing that isn't a key-placement step

A request still has to say *which zone* it's for and arrive somewhere the hoster is listening for that zone — that requires a zone resource to exist at the hoster, bound to your customer account. This is unavoidable in any hosting relationship (you can't upload to a bucket that was never created) and it's not a DNSSEC concept: it's ordinary account/API-token provisioning, the same step every SaaS product needs before it'll accept anything from you. It carries no cryptographic trust weight on its own — it only answers "which zone slot is this for," never "is this content authentic." That question is still answered solely by §10.2.

### 10.2 First contact: self-consistency, hardened automatically where possible

When a request arrives for a zone with no pinned key yet, the hoster runs two checks — and, per a since-tightened policy, **both are required, not just the first:**

1. **Self-consistency (always):** the request's own transaction signature must verify against the DNSKEY carried in that same request. SIG(0) (§7.2/§7.3) makes this literal — sign the UPDATE with the same private key you're publishing, so the message authenticates itself with no external reference at all, regardless of which carrier delivered it.
2. **Chain-of-trust cross-check (mandatory):** the hoster fetches the DS record for the zone from the parent/TLD and, if this is a migration, the live DNSKEY from wherever the domain is currently served — a normal validating DNS resolution, exactly like any resolver performs on an ordinary query. If the delivered key's digest matches, trust is anchored all the way to the root, automatically, from data that was already public. If it doesn't match — or if there's **no DS at all yet** — reject.

**No self-consistency-only fallback:** a domain enabling DNSSEC for the very first time must publish its DS at the registrar *before* the hoster will accept a first-contact request for it — not after. This gives up the zero-touch case where the hoster would otherwise hand back a fresh DS for you to publish post-hoc, in exchange for closing an abuse path: without this requirement, the first-contact endpoint would accept a self-signed request for literally any zone name, with nothing external to check it against, which is a database-flooding vector for a public-facing registration endpoint. Publishing a DS first is a normal part of standing up DNSSEC on any domain regardless of this protocol — this just moves that step ahead of the hoster interaction instead of after it.

**Resolved — does `ERR_NO_DS_PUBLISHED` leak anything?** No: a DS record is unauthenticated, publicly queryable DNS data by design — DNSSEC's whole chain-of-trust model depends on anyone being able to fetch it directly from the parent/TLD with an ordinary, unauthenticated query. Returning a specific status code for "no DS yet" tells a prober nothing they couldn't already get with a two-second query against the TLD itself; a generic REFUSED wouldn't hide that fact, it would just make the client script's error handling worse for no security gain. What's still worth limiting is the endpoint itself: **cap failed first-contact attempts at 5 per source IP** (customizable), so the path can't be hammered with disposable self-signed junk to spam the audit log or waste verification cycles — an ordinary abuse control, unrelated to what any individual error code reveals.

> **Deferred: multi-signer authorization**
>
> RFC 2931 cautions that SIG(0) signatures "should not be generated by zone keys," since it models a SIG(0) signer as a host or user identity, not a zone — which raises a fair question for a CI pipeline, a second operator, or another automation host that would rather not share the zone's actual DNSSEC key just to be allowed to push. A fuller answer (tiered, individually-revocable signer identities, a new record type, its own authorization rules) was drafted and then deliberately removed here — it's real complexity for a first version, and it doesn't need to live inside SAZU's wire protocol to be useful. The cleaner place to build it, if and when it's needed, is entirely on the **customer's own side**: run a small client/server gatekeeper that holds the one SAZU-authorized key, and have it broker pushes on behalf of multiple internal actors under its own access control. SAZU itself only ever sees one signer per zone; "who's allowed to trigger a push within the customer's own organization" is solved a layer above the protocol, not inside it. Revisit folding this into the core spec only if that layered pattern proves insufficient in practice.
>
> **Is more than one legitimate signer per zone a real scenario, independent of the above?** Yes — **multi-signer DNSSEC (RFC 8901)** is deployed today: Cloudflare and Akamai both support it, for domains that run two independent DNS providers simultaneously (redundancy, multi-cloud), each with its own ZSK in the same DNSKEY RRset. A simpler rule was proposed for this case: trust any key the parent's chain of trust currently vouches for (i.e., anything in the zone's live, DS-validated DNSKEY RRset), reject anything that isn't. That's worth adopting as an additional check, not as the *only* one — flagging why: "part of the zone's DNSKEY RRset" answers *"is this a real, non-forged key for this zone,"* but not *"is this specific key one I want pushing updates to THIS hoster."* In a genuine multi-signer setup, the other provider's ZSK is legitimately in your DNSKEY RRset — accepting SAZU pushes from it too would hand that unrelated provider write access to a hoster relationship it has nothing to do with. The two questions need to stay separate: keep the local pinned-key check (§10.2/§6) as the actual authorization decision, and use live parent-chain validation as an additional, ongoing *sanity* check on it — the pinned key must always currently be part of the zone's real DNSKEY RRset (checked periodically via §11's existing watch loop; if it ever drops out, that's exactly the kind of divergence §11 already alerts on), rather than treating chain membership alone as sufficient grounds to accept a push.

> **The trade-off this buys you**
>
> Zero manual key ceremony *with the hoster*, ever — nothing to paste into a support portal, no account handshake beyond ordinary API/account provisioning (§10.1). What you still owe your registrar, independent of this protocol entirely, is publishing a DS before the hoster will look at a first-contact request at all (above) — that's DNSSEC hygiene every deployment needs regardless of SAZU, just sequenced before the hoster interaction rather than after. Because the chain-of-trust check is now mandatory rather than a self-consistency-only fallback, a first-contact race can only be won by a request whose key genuinely digests to the real DS — an attacker without the actual private key can't produce one, no matter how many requests they send. Once a key is pinned, it closes permanently: every later request either matches the pinned key or goes through §10.4's rollover, never a silent replacement.

> **Don't race it**
>
> "Automatic" means *no human configures anything*, not *accept optimistically while checking in the background*. Both checks in §10.2 are step 0 of the §6 algorithm — they gate acceptance, they don't run concurrently with it.

### 10.3 Sequencing for a migration

The instruction, stated plainly: **publish the new key at the parent first; only once the zone is confirmed established on the new hoster should the delegation itself be repointed. Never the other order.** Here's precisely why, and how to do the first half safely.

A validating resolver accepts an answer only when some entry in the currently-published **DS RRset** matches the digest of a DNSKEY that's actually signing what's currently served. The instant that stops being true — for example, because the DS was updated to name SAZU's new key while NS delegation still points at the old provider, still signing with the old key — every DNSSEC-validating resolver returns SERVFAIL for the **entire zone**, not just the records being migrated. The timing of that failure is staggered and unpredictable across the internet, bounded only by however long each resolver's already-cached DS answer has left to live. Publishing the new key's DS as a *replacement* ahead of cutover is exactly this failure waiting to happen — "publish the key first" must mean additive, never a swap.

The safe procedure is additive, mirroring the RFC 6781 pre-publish method already used for ordinary key rollover (§10.4), applied here across a change of provider instead of a change of key alone:

1. Publish a **second** DS record at the parent, alongside the existing one — the DS RRset becomes `{digest(old key), digest(new key)}`. Nothing being served changes yet; the old entry keeps validating the still-live old provider throughout, so there is no gap.
2. This is what makes §10.2's automatic hardening check meaningful *ahead of time*: the new key is now genuinely published at the parent, with zero risk, because the old entry — not the new one — is what's actually keeping resolution alive in the meantime.
3. Cut NS delegation over to the new hoster. It serves content signed by the new key; the new DS entry, already in place since step 1, validates it immediately. No gap, because that entry was sitting there before the cutover happened.
4. Once the new hoster is confirmed stable (allow time for any stale NS/delegation caches elsewhere to expire too), remove the old DS entry, leaving only the new one. Migration complete.

Step 2's bootstrap on the new hoster is, mechanically, exactly §10.4's "new registration" — so a migration that's validated but never gets its NS cutover finished ages out the same way: **90 days** of inactivity (customizable), same figure, same reasoning, one policy rather than two.

Whether this is available depends entirely on the **registrar**, not the registry — RFC 5910's EPP DNSSEC extension supports up to **8 simultaneous DS records** at the protocol level, everywhere. What varies is whether a given registrar's own tooling exposes that capability, or actively gets in the way:

| Registrar | 2nd DS supported? | How | Catch |
|---|---|---|---|
| Amazon Route 53 | Yes | Console "Add key," or API `AssociateDelegationSignerToDomain` — purely additive | None found — accepts the DS as data, no live-match check |
| Cloudflare Registrar | Yes | Documented explicitly — "add DS records, one for each provider" | Framed around multi-signer setups, mechanically identical to a migration dual-DS |
| Namecheap | Yes | Custom-nameserver DNSSEC panel | None found |
| OVHcloud | Yes | DS records tab → Edit → "+" | None beyond requiring fully external DNS |
| Gandi | Yes, indirectly | Submit DNSKEY data, not raw DS — Gandi computes and files the DS itself | Whether Gandi also live-validates before filing is unconfirmed — verify directly |
| IONOS | Yes, not self-service | External-nameserver DS changes go through emailing `transfer@ionos.com` | Not API-automatable — a human is in the loop for both adding and later removing the old entry |
| GoDaddy | Yes, risky | UI "Add" supports multiple | **Performs a live DNSKEY-match check** against the currently delegated nameservers on submission — may reject a DS for a key nothing is serving yet |
| Squarespace Domains (ex-Google Domains) | **No** | — | Their own docs state it plainly: "You can only add one DNSSEC record to your domain." Hard limitation, not a workflow inconvenience. |

> **Fallback when dual-DS isn't available**
>
> For GoDaddy (where the live-match check may block a pre-published, not-yet-served key) and Squarespace Domains (where a second DS slot doesn't exist at all): remove the DS record entirely before migrating. An unsigned delegation resolves fine for everyone — it just isn't authenticated for that window. Do the NS cutover and key setup with no DS in place, confirm the new hoster is correctly serving and signing, then publish a single fresh DS once stable. Strictly worse than dual-DS — there's a real window with no DNSSEC protection — but it avoids the SERVFAIL risk entirely, and it works on every registrar, since it never requires two DS entries to coexist.

> **CDS/CDNSKEY automation during a migration**
>
> No special-case logic needed here: which keys are allowed is entirely a function of what's published at the parent — §10.2 already trusts nothing else. If a registrar's CDS/CDNSKEY auto-sync is actively polling the old provider's zone during the migration, it may try to reconcile the parent's DS back toward whatever the old provider currently publishes, undoing the staged dual-DS entry from step 1. That's a registrar-configuration fact to know going in — pause CDS auto-sync for the duration of a migration if the registrar has it — not something the protocol needs to detect or work around. The parent zone remains the single source of truth throughout, exactly as designed; the operator just has to make sure nothing else is also writing to it at the same time.

### 10.4 Rollover: a new registration, not a new message

"Rollover" is actually two separate problems, and it's worth untangling them before answering "how do you announce a new key":

- **Content-validity rollover** — can resolvers out on the internet keep validating the zone throughout the transition? This is a solved problem, unaffected by anything in this document: RFC 6781 §4.1's **pre-publish** method (publish the new key unused for a TTL before signing with it — no double-signing) for ZSKs, and its **double-signature** method (both KSKs sign in parallel while the parent's DS catches up) for KSKs. Keep doing this exactly as any DNSSEC operator would; nothing here changes it.
- **Push-authorization rollover** — how does the *hoster's acceptance gate* (§6) move from trusting the old key to trusting the new one? Nothing in RFC 6781 answers this, because it's specific to having a hoster that pins a key at all. This is the piece this protocol has to define.

The earlier design answered this with a bespoke, dual-signed `RolloverAnnouncement` — a new object with its own fields that never got a real wire encoding (§13 tracked this as an open gap). The simpler mechanism proposed here doesn't need one, because it reuses machinery §10.2 and §5 already define instead of inventing a new one:

1. Publish the new key at the parent — the §10.3 dual-DS technique for a KSK-level change, or simply adding it to the zone's live DNSKEY RRset for an ordinary ZSK-only change that doesn't need a new DS at all.
2. Bootstrap a **second registration** for the same zone, under the same customer account (§10.1), through the ordinary first-contact flow (§10.2) — which, per §10.2's tightened policy, always goes through the mandatory chain-of-trust cross-check, since the zone already has a DS by definition here. Resolved: each registration owns its own **separate copy** of the zone content, not a shared row — two worlds the hoster genuinely maintains side by side, kept independently until one retires.
3. Switch the client's automation to sign with the new key. Nothing has to happen at the moment of the switch on the hoster's side — the old registration simply stops being used.
4. The old registration retires itself one of two ways: **inactivity** — no accepted push using it for 90 days, default and customizable per server — or an **explicit signed removal**, an ordinary push, signed by the old key, that deletes its own DNSKEY entry from the served RRset. That's not a new operation either: removing a retired key from the DNSKEY RRset is something RFC 6781 already has you do at the end of any rollover, so the "signal" is a record the client was going to delete anyway. A registration's expiry clock is purely inactivity-based — it keeps running (and the registration stays retained) regardless of whether the zone's live NS delegation currently points at this hoster or somewhere else; delegation status is §11's concern, not §10.4's.

> **Why this is the better mechanism, not just a simpler one**
>
> Beyond resolving the wire-encoding gap outright — nothing new to define, only RFC 2136's existing ADD/DELETE and §10.2's existing bootstrap — it fixes a real weakness the old design had: if the old key is *lost entirely* (destroyed, no automation left able to sign with it), the dual-signature announcement had no path forward, since it required the old key's cooperation by construction. Here, the new key can bootstrap on chain-of-trust validation alone (§10.2), with no cooperation from the old key required at all — provided the operator can still get the new key published at the parent through some other means (typically: they still control the registrar, even having lost the SAZU signing key). A design that survives losing the old key is meaningfully more robust than one that doesn't.

**How long can "both worlds" coexist?** No forced end — an inactivity-based auto-retirement is a soft nudge, not an eviction; forcing retirement on a fixed clock could itself be leveraged by an attacker who's already compromised the new key, by simply waiting out the old one. The recommended (not enforced) figure is the same **90 days** as the inactivity default above, customizable per server — past that point the hoster should warn the operator that a rollover looks stalled, not act on it unilaterally.

### 10.5 Parent-side DS record

Keeping the parent's DS in sync with your current key is out of scope for this document, but RFC 7344/8078 (CDS/CDNSKEY) exist precisely to automate the registrar/registry side of that — worth wiring up separately regardless of which push variant above you pick, and it's what keeps §10.2's cross-check working across rollovers without a manual registrar visit each time.

### 10.6 Registration record: key and contact travel together, as data

ACME (RFC 8555) already answers this exact question, one layer over in the CA world: an ACME account object bundles the account's public key *and* its `contact` field (typically a `mailto:` URL) into one resource, created by a single `newAccount` request and updated only by a request signed with that same account key — never a second registration channel alongside the certificate-issuance protocol. Key rollover (`keyChange`) is the one operation that gets special handling: it requires a dual signature, the new key signing "I am taking over this account from the old key" and the old key signing its consent, so a rollover is authorized by both endpoints of the transition at once.

Same shape here, applied to §10.2's first-contact message:

- Add one field — a contact address — to the same message that already carries the DNSKEY. Nothing new to bootstrap: it's authenticated by the same self-consistency/chain-of-trust check, pinned the same way, at the same moment.
- Store it as part of a small **zone registration record** (key + contact), kept separate from the RRset store — it's control-plane data that changes on the order of "almost never," not zone content that changes on every push.
- Changing *either* field later requires a request signed by the **currently pinned** key — exactly §10.4's rollover rule, now covering the contact address too. This closes the gap that motivated the question: an attacker who only controls the push endpoint's transport, without the actual signing key, cannot silently redirect where alerts go.

### 10.7 Algorithm policy

**Floor:** per RFC 8624, reject anything at "MUST NOT" or "NOT RECOMMENDED" — no RSAMD5, DSA, RSASHA1, or RSASHA1-NSEC3-SHA1 DNSKEY/RRSIG algorithms, and no SHA-1 (digest type 1) DS records; require SHA-256 (type 2) or SHA-384 (type 4) at minimum. This is a §6 step 3 check, applied identically to every algorithm field in the design, not a separate gate.

**Starting default:** **ECDSAP256SHA256** (algorithm 13) — RFC 8624 places it at "MUST" for both signing and validation, with meaningfully smaller keys and signatures than RSASHA256. ED25519 (15) is a reasonable smaller/faster alternative to adopt later; nothing about this design hardcodes an algorithm, so extending the accepted set is a policy change, not a protocol change.

### 10.8 Client-side key custody

Out of this protocol's wire format, but worth stating since it's the actual point of splitting signing from serving: the private key should live as an **offline copy**, ideally inside an **HSM**; at an absolute minimum, the on-disk key must be passphrase-protected. A perfectly designed acceptance protocol on the hoster's side is moot if the key it's built to protect sits in plaintext on the same box doing the pushing.

### 10.9 KSK and ZSK: generated together, used for different jobs

Everything above (§10.1–10.4) describes what a key does once it exists; this section defines which key does which job. A zone under this protocol has a **key-signing key (KSK)** and a **zone-signing key (ZSK)**, generated together as a pair at first contact — never the KSK alone.

The KSK keeps exactly the job §10.2/§10.4 already give a key: it is the one thing ever anchored to a parent DS record, and it signs the DNSKEY RRset (RFC 4034's own convention — the key-signing key signs the key set). Once first contact and any later rollover are done, the KSK is not touched again. The ZSK is what authenticates and signs every **routine** push from then on — ordinary content updates, on whatever schedule the operator's automation runs them. An automation host that only ever sends routine content pushes holds only the ZSK, and never needs the KSK for anything: its compromise costs an ordinary same-day key change (the ZSK-only path in §10.4, no registrar step), not a registrar round trip.

This needs no additional wire mechanism — it fits entirely inside §5's update bundle and §6's acceptance algorithm:

- **First contact** (§10.2) carries the KSK and its paired ZSK together, as two DNSKEY records in the same message — either alone, as a trust-establishing message with no zone content at all, or together with the zone's initial content in one message. The KSK signs the DNSKEY RRset; the ZSK's own private half is never needed for this message. Both keys become trusted the moment §10.2's two checks (self-consistency, chain-of-trust) pass against the KSK.
- **Routine pushes** are ZSK-authenticated and ZSK-signed, and carry no DNSKEY at all — trust in the ZSK was already established at first contact, so nothing about it needs restating on every push.
- **Rollover (§10.4)** applies exactly as written, per key: a KSK rollover is the "new registration, dual-DS" procedure; registering, replacing, or retiring a ZSK is the "ordinary... change that doesn't need a new DS at all" procedure already described there — no registrar step, no chain-of-trust re-check, authorized by any key already trusted for the zone.

**Distinct from §10.2's deferred multi-signer authorization.** That question is about several independent parties (a CI pipeline, a second operator) each wanting their own revocable identity. This is one signer splitting its own authority across two keys with different privilege levels — closer to a cold key and a warm key held by the same party than to multi-tenant authorization. A multi-signer scheme, if built, layers on top of this split (each independent signer getting its own ZSK-equivalent, all subordinate to one KSK-equivalent anchor) rather than replacing it.

## 11. Delegation-change monitoring & alerting

The registration record from §10.6 only earns its keep if something is actually watching. This is the concrete mechanism behind the scope note in §3.

- **Watch loop, concretely:** query the parent for the zone's current NS and DS every **5 minutes per zone** (default, customizable per server) and compare against the last-known-good set observed at §10.2 bootstrap / last rollover. Run this from the same validating-resolver code already built for §10.2's chain-of-trust cross-check — it's the identical query, just repeated.
- **Debounce:** a single mismatch doesn't fire the alarm — **two consecutive failed checks** (10 minutes apart, at the default cadence) raises it to the operator, absorbing a transient resolution hiccup without absorbing a real change.
- **On the very first confirmed change:** email the registered contact (§10.6) immediately — this is the one signal that something changed outside the channel this whole protocol controls, and it fires from the very first zone the account has, not after some accumulation period.
- **Fail closed, not just loud:** pair the alert with freezing further pushes for that zone pending manual confirmation. An unexpected parent-level change is exactly the moment to stop trusting automation and wait for a human — the alert should gate behavior, not merely inform.
- **Total silence:** if the parent gives no answer at all for a zone for a full day, assume the zone has been destroyed at the registry (not merely changed) — notify the registered contact and remove the zone's registration on the hoster's side rather than continuing to watch a delegation that no longer exists.
- **Precedent — Certificate Transparency:** the CA ecosystem hit the identical problem (domain-validated issuance can be tricked by anyone who currently controls the domain, including a hijacker) and answered it with CT (RFC 6962): every publicly trusted certificate is logged, and third-party monitors (crt.sh, Certspotter) alert domain owners when a certificate they didn't request appears. It's the same shape — detect an unexpected change to your identity binding, alert a registered contact — for a different binding. DNS has no equivalent public, ecosystem-wide transparency log for delegation/DS changes at comparable scale, which is exactly why this has to be self-operated rather than something you can subscribe to.

> **Architecture: keep the watch loop separable**
>
> The target deployment for SAZU is on-premise / single-tenant first, not a multi-tenant hoster running this for thousands of customer zones — but nothing here should introduce a limit that would block scaling later, either. Concretely: the watch loop and the notification/alerting logic must be a **strictly separate process** from the push-acceptance server (§6), communicating with it only through the shared database — never in-process, never sharing state any other way. That means it can run on the same box as a background task for a small deployment, or move to an entirely different machine with its own access to the same database once the number of zones being watched actually warrants it, with no redesign either way.

## 12. Operational concerns

- **Signature expiry monitoring:** if the client's cron job silently stops running, RRSIGs march toward expiration and the zone goes *Bogus* for validating resolvers with no server-side symptom to alert on. Monitor expiry-of-the-soonest-RRSIG as its own metric, independent of whether pushes are "succeeding."
- **Atomicity:** the RFC 2136 prerequisite check (§5, §6 step 2) gives all-or-nothing semantics for free — lean on it rather than adding your own transaction log.
- **Rate limiting / quota (starting numbers):** **5 content pushes/day and 50 key-management pushes/day per zone** (trust establishment, rollover, and ZSK registration/retirement — §10.9), both customizable per server, on a **24-hour rolling window** — not a fixed calendar-day reset, so the count is always "in the last 24 hours" rather than resettable by timing a burst around midnight. This is a per-tenant quota, not a global rate limit — the acceptance path must be tenant-aware so one zone's traffic can never exhaust another's allowance. Exceeding it doesn't silently drop the request: respond with `ERR_QUOTA_EXCEEDED` and a message plain enough for the client script to relay to a human ("daily update quota exceeded — contact support to raise it"), rather than an opaque REFUSED. Raising a zone's quota is an out-of-band support action, not something this protocol negotiates.
- **Audit trail and client feedback:** log every accepted *and rejected* transaction's serial, timestamp, source, transaction UUID (§6), and resulting status code — this is both the record that lets you prove what was published and when, and the mechanism a client script uses to report something specific to a human, rather than a bare pass/fail. Per §6 step 7: the DNS RCODE carries the coarse signal (works unmodified with any RFC 2136-aware tool), and a SAZU status code alongside it — `OK`, `ERR_STALE_SERIAL`, `ERR_UNKNOWN_SIGNER`, `ERR_SIG_INVALID`, `ERR_EXPIRED_SIGNATURE`, `ERR_WEAK_ALGORITHM`, `ERR_QUOTA_EXCEEDED`, `ERR_RATE_LIMITED`, `ERR_NO_DS_PUBLISHED` — carries the specific one, plus which name/type/reason triggered it where applicable (§6 step 7). On the raw-DNS carrier (7.2) this rides as a short diagnostic TXT record in the response's Additional section; on the JSON carrier (7.3) it's just a field in the response body. Same code list either way, so a client script's error-handling logic doesn't fork by carrier. The transaction UUID is also what a future status-query interface (§6) would key on.

## 13. Open questions

None outstanding as of this revision — every item raised through the previous rounds is now decided; see §§5, 6, 10.2, 10.4, 12 for where each landed, and §14 for what's deliberately deferred rather than unresolved (below). Kept as a section heading for whatever the next round of review surfaces, rather than removed for being momentarily empty.

## 14. Deferred to post-PoC

Deliberately not decided now — real usage from a first proof-of-concept phase is worth more here than a guess:

- **Registrar behavior:** §10.3's two unconfirmed cells — whether Gandi's DNSKEY-submission flow also does a live-match check like GoDaddy's, and whether IONOS's email-based process for external nameservers can be pinned to a predictable turnaround time. Confirm both empirically during the PoC.
- **Multi-signer placement:** whether the deferred multi-signer pattern (§10.2) should eventually move into the core protocol, or stay a customer-side, client/server concern indefinitely. Revisit once there's real demand rather than deciding it speculatively now.
- **Transaction-status interface:** §6 commits to a transaction UUID and a queryable final status; whether that query interface is worth building as GraphQL, a plain REST endpoint, or something else entirely depends on what the PoC's actual client tooling ends up wanting.

---

*SAZU — Self-Authenticated Zone Update · Design proposal v1.5*
