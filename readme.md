# SAZU

**Self-Authenticated Zone Update**: a zone owner signs their own zone with DNSSEC keys they keep to themselves, and pushes the signed zone to a DNS hoster. The hoster verifies it and serves it, but never holds a private key. The only credential involved is the DNSSEC key that already signs the zone.

*Protocol proposal · split-signing DNSSEC*

| | |
|---|---|
| Status | Draft proposal, v2.0 (supersedes v1.5, see §17) |
| Scope | Zone owner's signer → hoster's authoritative server |
| Wire format | RFC 2136 UPDATE, authenticated with RFC 2931 SIG(0) |
| Carriers | DNS over TCP/UDP, or the same bytes over HTTPS |
| Reference implementation | CoreDNS plugin, [`mrwiora/coredns@feat/sazu`](https://github.com/mrwiora/coredns/tree/feat/sazu/plugin/sazu) (§14) |

> **Abstract**
>
> Today a DNSSEC zone hosted by a third party is either signed by the hoster, which then holds your private key, or signed by you on a "hidden primary" that the hoster has to pull from with AXFR, which means you run a listening server. SAZU is a third option. The zone owner signs everything offline and pushes the complete signed zone as one standard RFC 2136 dynamic UPDATE, authenticated with SIG(0) using the zone's own DNSSEC key. The hoster checks every signature before it publishes anything. It learns which key to trust from the DS record already in the parent zone, so there is no account, no API token and no shared secret. The one deliberate deviation from existing practice is on the server side. RFC 3007 §4.3 assumes the server re-signs updated data with an online zone key. A SAZU server instead verifies signatures the client supplied and never signs anything itself. [`rfc-diff/`](rfc-diff/) shows that change as a proposed amendment to RFC 3007.

> **Why "SAZU"**
>
> Every SAZU message proves its own authorization with the key it carries or references. That covers onboarding (§7), routine pushes (§6) and key rollover (§8). There is no second credential. "Self-authenticated" describes the mechanism literally.

## Contents

1. [Motivation](#1-motivation)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [Overview](#3-overview)
4. [Conventions and terminology](#4-conventions-and-terminology)
5. [Message format](#5-message-format)
6. [Server processing](#6-server-processing)
7. [Onboarding (first contact)](#7-onboarding-first-contact)
8. [Key management](#8-key-management)
9. [Transports](#9-transports)
10. [Responses and status codes](#10-responses-and-status-codes)
11. [Operational requirements](#11-operational-requirements)
12. [Security considerations](#12-security-considerations)
13. [Design decisions and alternatives](#13-design-decisions-and-alternatives)
14. [Reference implementation status](#14-reference-implementation-status)
15. [Open issues](#15-open-issues)
16. [Registrar notes (informative)](#16-registrar-notes-informative)
17. [Changes since v1.5](#17-changes-since-v15)

---

## 1. Motivation

A DNSSEC zone served by someone else normally ends up in one of two setups:

- **The hoster signs.** This is convenient, but the hoster holds the private key. A breach or a rogue insider at the hoster can publish validly signed data for your domain.
- **You sign on a hidden primary and the hoster pulls it (AXFR/IXFR).** You keep the key, but you now run an always-on, reachable server with NOTIFY, ACLs and TSIG secrets, just so the hoster can fetch your data.

SAZU keeps the key with the zone owner and needs nothing on the owner's side to be reachable. A cron job or CI step builds and signs the zone, then pushes it. The hoster accepts a push only if every RRSIG in it verifies against keys that the parent's DS record anchors to the DNS root. So the hoster can publish exactly what you signed and nothing else. For validating resolvers, a compromised hoster database leads to validation failures, not silent forgeries (§12.4).

## 2. Goals and non-goals

**Goals**

- The zone owner holds the KSK and ZSK and computes every RRSIG. The hoster never receives, generates or stores private key material.
- The zone owner runs no listening service. Pushes are outbound only.
- The hoster verifies, stores and serves. It never signs.
- Authorization to publish rests on possession of the zone's DNSSEC keys, anchored at the parent's DS. There is no second credential with its own lifecycle.
- Only existing IETF wire formats and mechanisms are used: RFC 2136, RFC 2931, RFC 4034/4035, RFC 5155 and RFC 8484.

**Non-goals**

- Multi-signer DNSSEC (RFC 8901), where two independent operators sign one zone.
- Pull-based transfer (AXFR/IXFR). SAZU is the push-based alternative.
- Automating parent-side DS changes. CDS/CDNSKEY (RFC 7344, RFC 8078) is complementary: a zone owner may publish CDS/CDNSKEY as ordinary zone content, and a SAZU server serves it like anything else.
- Hoster-side signing, differential/incremental updates, and account or billing models.

## 3. Overview

```
  zone owner (offline or CI)                        hoster (SAZU server)
  ──────────────────────────                        ────────────────────
  KSK (cold), ZSK (warm)
  build zone, sign all RRsets,
  build NSEC/NSEC3 chain
          │
          │  RFC 2136 UPDATE + SIG(0)            ┌───────────────────────────────┐
          └────── TCP/53, UDP/53 or HTTPS ──────▶│ 1. verify SIG(0) against the  │
                                                 │    zone's pinned keys         │
     first contact / KSK rollover only:          │ 2. verify every RRSIG         │
     server checks parent DS  ◀──── DNSSEC ──────│ 3. replace served zone        │
     (validated from the root)                   │    atomically                 │
                                                 └───────────────────────────────┘
```

A zone's lifecycle, seen from the hoster:

1. **Onboarding (§7).** The first message for an unknown zone carries the zone's DNSKEY RRset and is SIG(0)-signed by the KSK. The server looks up the zone's DS record in the parent, validating the chain from the root trust anchor. If the KSK matches, the server *pins* the KSK and registers the ZSK(s). Nothing else is ever needed to onboard a zone.
2. **Content pushes (§5.3).** Every later content change is a *complete* signed zone, SIG(0)-signed by a ZSK. The server verifies every RRSIG and then atomically replaces what it serves.
3. **Key management (§8).** ZSKs are added and retired by KSK-signed messages. The KSK itself is replaced by a rollover that repeats the DS check for the new key.

## 4. Conventions and terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are to be read as described in BCP 14 (RFC 2119, RFC 8174) when they appear in bold capitals.

| Term | Meaning |
|---|---|
| Zone owner / client | The party that holds the zone's private keys and sends SAZU messages. |
| Server / hoster | The authoritative DNS server that receives SAZU messages and serves the zone. |
| KSK | The zone's key-signing key: a DNSKEY with the SEP flag set. It is the only key matched against the parent DS. It signs the DNSKEY RRset and authenticates key-management messages. |
| ZSK | A zone-signing key: a DNSKEY without the SEP flag. It signs zone content and authenticates content pushes. A zone **MAY** have several. |
| Pinned KSK | The KSK the server currently trusts for a zone, set at onboarding or by a KSK rollover. |
| Registered ZSK | A ZSK the server trusts for a zone because a message authenticated by the pinned KSK introduced it. |
| Zone keys | The pinned KSK plus all registered ZSKs. |
| Chain-of-trust check | DNSSEC validation from the root trust anchor down to the parent's DS RRset for the zone, followed by a digest match of a candidate KSK against that RRset (§7.2). |

## 5. Message format

### 5.1 Common rules

Every SAZU message is an RFC 2136 UPDATE message (opcode 5):

- **Zone section:** exactly one entry: the zone apex, class IN, type SOA.
- **Prerequisite section:** carries the zone-version prerequisite (§6.3), which every control change and a zone's first content push **MUST** include. It **MAY** carry further RFC 2136 §2.4 prerequisites, which the server evaluates as RFC 2136 specifies.
- **Update section:** the operations for one of the message kinds in §5.2.
- **Additional section:** the last record **MUST** be a SIG(0) record (RFC 2931 §3) covering the whole message.

SIG(0) specifics:

- The SIG(0) signer name **MUST** be the zone apex. The key is identified by key tag and algorithm, and **MUST** be one of the zone's DNSKEYs. At onboarding and KSK rollover it is the candidate KSK carried in the message itself. The server never fetches a KEY RR from the DNS. The SIG(0) key is the zone key. RFC 2931 advises against this (it models SIG(0) signers as hosts or users), so it is a deliberate relaxation, justified in §13.1 and written up as an amendment in [`rfc-diff/`](rfc-diff/).
- Because the SIG(0) key is a DNSKEY, the SIG(0) algorithm is always that DNSKEY's algorithm.
- The signature covers the exact wire bytes as sent (RFC 2931 §3.1). Servers **MUST** verify against the bytes as received, never against a re-encoding of the parsed message. This is why the HTTPS carrier transports the wire bytes verbatim (§9.2).
- `expiration − inception` **MUST NOT** exceed the server's maximum SIG(0) lifetime. It is **RECOMMENDED** to be 1 hour plus 5 minutes of clock skew. Servers **MUST** reject messages whose SIG(0) window is longer, or that are outside their window at receipt.

### 5.2 Message kinds

The server tells message kinds apart by content. A message **MUST** match exactly one row; anything else is rejected with FORMERR.

| Kind | Recognized by | SIG(0) by | Update section carries |
|---|---|---|---|
| Onboard (§7) | Zone has no pinned KSK | The one SEP-flagged DNSKEY in the message | The complete DNSKEY RRset (exactly one SEP key, zero or more ZSKs) and its RRSIG by that KSK. Optionally a contact directive. Nothing else. |
| Content push (§5.3) | Adds an apex SOA | A registered ZSK or the pinned KSK | The complete zone and its signatures. No DNSKEY, no deletes. |
| Key update (§8.1) | Changes the apex DNSKEY RRset, keeps the pinned KSK | Pinned KSK | The complete resulting DNSKEY RRset as adds, delete-RR ops (RFC 2136 §2.5.4) for each removed ZSK, and an RRSIG over the resulting RRset by the pinned KSK. |
| KSK rollover (§8.2) | Adds a new SEP DNSKEY whose key signs the SIG(0) | The new KSK | The complete resulting DNSKEY RRset as adds, a delete-RR op for the old KSK, and an RRSIG over the resulting RRset by the new KSK. |
| Contact update (§11.4) | TXT at `_sazu-contact.<zone>` | Pinned KSK | Add: the new contact addresses. Delete: clear the contact. **MAY** be combined with onboarding or a key update. |
| Decommission (§8.4) | TXT at `_sazu-decommission.<zone>` | Pinned KSK | Only the directive. It **MUST NOT** be combined with anything else. |

The two reserved owner names (`_sazu-contact.`, `_sazu-decommission.`) are control data. The server strips them out before content processing. They are never served and never DNSSEC-signed; the SIG(0) authenticates them.

### 5.3 Content pushes are always complete

A content push carries the zone's **entire** authoritative content:

- the apex SOA and every other RRset, *except* the apex DNSKEY RRset (which only §8 manages)
- a complete NSEC or NSEC3 chain (and NSEC3PARAM, if NSEC3 is used)
- an RRSIG for every one of those RRsets, made by a zone key

The server replaces everything it serves for the zone with the push's contents, except the DNSKEY RRset and its RRSIGs. Anything not re-asserted is removed. There are no partial content updates. A message that changes served content without adding an apex SOA **MUST** be rejected. §13.2 explains why.

The choice between NSEC and NSEC3 belongs to the signer. The server stores and serves whatever chain arrives. The **RECOMMENDED** default is NSEC3 with zero extra iterations, an empty salt and no opt-out (RFC 9276). That gives resistance to zone walking at roughly the cost of NSEC.

## 6. Server processing

### 6.1 Algorithm

The server processes each message as follows. Every step fails closed, and nothing is applied until every step has passed.

```
0.  Scope: is the zone name one this server accepts?     → REFUSED
1.  Rate limit: per-source-IP budget (§11.2).            → REFUSED  ERR_RATE_LIMITED
2.  Capture the exact wire bytes. Unavailable?            → SERVFAIL
3.  Take the per-zone update lock (all later steps are serialized per zone).
4.  Authenticate SIG(0):
      zone pinned:   try each zone key allowed to sign this message kind (§5.2);
                     if none verifies and the message carries a new SEP DNSKEY
                     that verifies it → treat as a KSK rollover candidate.
      zone unknown:  the candidate is the single SEP DNSKEY in the message
                     (no SEP key → REFUSED  ERR_FIRST_CONTACT_REQUIRES_KSK).
    The candidate algorithm is below the floor (§11.3)?  → REFUSED  ERR_WEAK_ALGORITHM
    Signature, window or lifetime is invalid?            → NOTAUTH
5.  Classify (§5.2). Is the signer allowed for the kind?  → REFUSED / FORMERR
6.  Version check (§6.3):
      control change or first content push without one   → REFUSED  ERR_VERSION_REQUIRED
      version not the zone's current one                  → NXRRSET  ERR_STALE_VERSION
7.  Per-zone quota (§11.2).                               → REFUSED  ERR_QUOTA_EXCEEDED
8.  Onboarding or KSK rollover only:
      arrived over UDP?                                   → REFUSED  ERR_TRANSPORT_NOT_ALLOWED
      chain-of-trust check for the candidate KSK (§7.2):
        no DS at the parent                               → REFUSED  ERR_NO_DS_PUBLISHED
        DS present, no match                              → REFUSED  ERR_UNKNOWN_SIGNER
        validation failure                                → REFUSED
9.  Evaluate RFC 2136 prerequisites.                     → NXRRSET/YXRRSET/…  (ERR_STALE_SERIAL for SOA)
10. Content push only: new SOA serial > current serial
    (RFC 1982 arithmetic).                               → REFUSED  ERR_STALE_SERIAL
11. Verify signatures (§6.2).                             → NOTAUTH  ERR_SIG_INVALID / ERR_EXPIRED_SIGNATURE
12. Persist, then apply atomically. Queries see either the old zone or the new
    one, never a mix.
13. Update key state (pin KSK / add or retire ZSK) and contact; for a control
    change, increment the zone version (persisted with the change).
14. Respond NOERROR. Write an audit record for every outcome except those
    rejected at step 0, step 1 or for transport (§11.5).
```

### 6.2 Signature verification (mandatory)

Signature verification is not optional and there is no mode that turns it off. SIG(0) proves who sent a message. Only RRSIG verification proves that what the server is about to serve will actually validate.

- Every RRset the message adds **MUST** be covered by at least one RRSIG in the same message that verifies (RFC 4035 §5.3) against a permitted key and is inside its validity window at receipt.
- Verification **MUST** be done against the RRset **as it will be served after the update is applied**, not only against the records in the message. For a content push these are the same thing, because the whole zone is replaced. For DNSKEY changes it means that the RRSIG must cover the complete resulting DNSKEY RRset.
- Permitted keys: for the apex DNSKEY RRset, **only** the KSK being pinned (the pinned KSK, or at onboarding and rollover the candidate KSK). A validating resolver only accepts a DNSKEY RRset signed by a key the parent DS matches (RFC 4035 §5.2), so an RRSIG(DNSKEY) from a ZSK would give a server-accepted but bogus zone. For every other RRset, any zone key.
- A single failure rejects the whole message. The response identifies the failing name and type where possible.

### 6.3 Replay and rollback protection

A captured message stays cryptographically valid until its SIG(0) expires. Its RRSIGs stay valid for much longer. Without further checks, a replay could roll the zone back to older content, or undo a key change (for example, re-add a retired ZSK). SAZU prevents this with two per-zone counters that are part of the zone's own state. Neither depends on anyone's clock, and neither needs per-message history on the server.

1. **Content: the SOA serial.** A content push's SOA serial **MUST** be greater than the one currently served (RFC 1982 arithmetic; §6.1 step 10). An older push, replayed or held back and delivered late, can never be applied over a newer one.
2. **Control: the zone version.** Every zone has a version, a non-negative integer that is 0 for a zone the server has never seen. A *control change* is onboarding, a key update, a KSK rollover, a contact update or a decommission. Every control change **MUST** carry the zone's current version as an RFC 2136 §2.4.2 "RRset exists (value dependent)" prerequisite: a TXT record at `_sazu-version.<zone>`, class IN, TTL 0, whose single string is the version in decimal. A zone's first content push has no serial to be ordered by yet, so it **MUST** carry the version too. Any other message **MAY** carry it; if it does, it must match. The server:
   - rejects a required but missing version with REFUSED and `ERR_VERSION_REQUIRED`, and a version that isn't current with NXRRSET and `ERR_STALE_VERSION`;
   - increments the version when it applies a control change, in the same atomic step as the change itself;
   - keeps the version after a decommission (which increments it), so an old onboarding message cannot re-create the zone;
   - publishes the version, unsigned, as a TXT record at `_sazu-version.<zone>`, so a client can read it before signing;
   - refuses any update that writes to `_sazu-version.<zone>` itself.

A control message therefore names exactly one version. It applies at most once, and of two control changes signed for the same version only one can apply; the other must be re-read and re-signed. Content pushes do not change the version, so a control change prepared on an offline KSK host, against the published version, stays valid across any number of routine content pushes until it is sent.

Because both counters are zone state, a server that shares zones with other instances replicates them together with the zone's content and keys (§15).

## 7. Onboarding (first contact)

### 7.1 What the client sends

An onboarding message carries the zone's complete initial DNSKEY RRset: one KSK and, typically, one ZSK. It is RRSIG-signed and SIG(0)-signed by the KSK, and it **MAY** carry a contact directive (§11.4). It carries no zone content. The first content push follows as a separate message, signed by the ZSK. Until then the zone is "trusted but empty" and answers only from its DNSKEY RRset.

There is no account-creation step. Which zone names a server accepts at all (every name, or only names below some suffix) is local server policy, set in configuration.

### 7.2 The chain-of-trust check

The server **MUST** establish, with its own DNSSEC validation, that the candidate KSK matches the parent's DS RRset:

1. Validate from a configured root trust anchor down through each ancestor zone (DNSKEY → DS → DNSKEY …) to the parent's signed DS RRset for the target zone. Any break, bad signature or network failure fails the check. The check never degrades to "insecure".
2. The candidate KSK **MUST** match one DS in that RRset (key tag, algorithm, and a recomputed digest). The DS digest type **MUST** be SHA-256 (2) or SHA-384 (4). SHA-1 (1) DS records do not count as a match.
3. If the parent answers authoritatively with no DS at all, the result is `ERR_NO_DS_PUBLISHED`. The zone owner has to publish the DS at the registrar *before* onboarding. There is no self-signed-only fallback: without one, the endpoint would accept any key for any name, which makes it a database-flooding vector.

The check only asks whether the parent vouches for this key. It does not care where the zone is currently delegated. A zone can therefore be onboarded and fully tested on a new hoster before any NS change (§8.3).

`ERR_NO_DS_PUBLISHED` and `ERR_UNKNOWN_SIGNER` leak nothing: DS records are public, unauthenticated-to-read data, so anyone can learn the same thing with a single query to the parent.

### 7.3 Concurrency

Onboarding messages for the same zone **MUST** be serialized. The first one to commit pins the KSK. A later one is then treated as a message for a pinned zone and fails SIG(0) authentication unless it is signed by a zone key. Because the chain-of-trust check is mandatory, only a holder of the private key behind the published DS can win the race at all.

## 8. Key management

### 8.1 Adding and retiring ZSKs

A key-update message (§5.2) replaces the DNSKEY RRset with a new complete set that still contains the pinned KSK. It is authenticated and RRSIG-signed by the pinned KSK. No registrar step and no chain-of-trust check are involved, because a ZSK is trusted only through the KSK that introduced it. Zone owners **SHOULD** follow the RFC 6781 §4.1.1 pre-publish method: add the new ZSK, wait at least the DNSKEY TTL, switch content signing, wait until old signatures have expired from caches, then retire the old ZSK.

Because ZSKs can be added and retired without the registrar, a compromised ZSK is cheap to recover from. The KSK holder retires it in a single message.

### 8.2 KSK rollover

A KSK rollover is a *double-DS* rollover (RFC 6781 §4.1.2, RFC 7583):

1. Publish the new KSK's DS at the registrar **alongside** the existing one. Wait until it is visible, then wait at least the parent's DS TTL more, so that resolvers with the old DS RRset cached have refreshed it.
2. Send the rollover message: the new DNSKEY RRset (new KSK plus the existing ZSKs, old KSK removed), RRSIG-signed and SIG(0)-signed by the new KSK. The server runs the §7.2 check for the new KSK and, if it passes, re-pins. Registered ZSKs are not affected.
3. Once the old DNSKEY RRset has expired from caches (its TTL), remove the old DS at the registrar. **Do this promptly.** While the old DS is still published, anyone holding the old KSK can use this same procedure to roll the zone back to that key (§12.3).

The old KSK's cooperation is not required. That is deliberate: it means a zone owner who has *lost* their KSK can recover, as long as they still control the registrar. Since control of the parent's DS already is the root of authority for the zone, this adds no new trust assumption. It does mean that a registrar compromise leads directly to a hoster takeover (§12.2, §15).

### 8.3 Migrating from another provider

Onboarding only needs a matching DS, not a delegation. So a migration is:

1. Add the SAZU KSK's DS at the parent *alongside* the current provider's DS. Never replace the existing DS: a DS RRset that matches no key actually signing the served zone makes the whole zone SERVFAIL for validating resolvers.
2. Onboard and push content to the new hoster. Verify it by querying the new hoster directly.
3. Switch the NS delegation at the parent.
4. After the old NS and DNSKEY data has expired from caches, remove the old provider's DS.

If the registrar cannot hold two DS records (§16), the fallback is to remove DNSSEC before migrating and republish the DS afterwards. That leaves an unsigned window but no outage. Pause any CDS/CDNSKEY automation at the registrar for the duration of a migration, so that it does not "correct" the staged DS RRset.

### 8.4 Decommissioning

A KSK-authenticated decommission message removes everything the server holds for the zone: keys, content, contact and quota state. It increments rather than removes the zone's version (§6.3). Removing the DS at the parent is the zone owner's own step. After decommissioning, the zone can be onboarded again from scratch.

## 9. Transports

The two carriers transport byte-identical messages and share the processing in §6. Choose by network path.

### 9.1 DNS (TCP and UDP port 53)

Clients **SHOULD** use TCP. Signed pushes routinely exceed one unfragmented UDP datagram. Servers **MUST NOT** accept onboarding or KSK-rollover messages over UDP. Both trigger outbound chain-of-trust queries, and over UDP the source address is spoofable, which would defeat per-IP rate limiting. Other message kinds **MAY** be accepted over UDP.

### 9.2 HTTPS

The client sends the exact wire-format message as an HTTP POST body with `Content-Type: application/dns-message`, using the RFC 8484 conventions (for example `POST https://push.hoster.example/dns-query`). The response is the wire-format DNS response. HTTPS carries no additional authentication, since SIG(0) inside the body is the only credential.

A server **MAY** also accept a JSON envelope `{"wire": "<base64 of the same bytes>"}` for clients and tooling that prefer JSON. This is a wrapper around the identical bytes, not a structural encoding.

> **Why not RFC 8427 JSON**
>
> v1.5 proposed a structural JSON encoding of the message (RFC 8427). That cannot work with SIG(0). The signature covers the literal wire bytes, including name compression, label case and record order, and a structural JSON form has no lossless way back to those bytes, so the server would have nothing it could verify.

## 10. Responses and status codes

The RCODE gives the coarse result, so any RFC 2136-aware tool understands it. A SAZU status code, where one applies, gives the specific reason. It is carried as a TXT record in the response's Additional section: owner = zone apex, class IN, TTL 0, one string holding the code. Moving this to RFC 8914 Extended DNS Errors is an open issue (§15).

| RCODE | Status code | Meaning |
|---|---|---|
| NOERROR | — | Accepted and applied. |
| FORMERR | — | Malformed message, or it does not match exactly one kind in §5.2. |
| NOTAUTH | — | SIG(0) missing, invalid, outside its window, or signed by a key not allowed for this kind. |
| NOTAUTH | `ERR_SIG_INVALID` | An added RRset has no RRSIG that verifies (§6.2). |
| NOTAUTH | `ERR_EXPIRED_SIGNATURE` | A covering RRSIG verifies but is outside its validity window. The fix is to re-sign and push again. |
| REFUSED | `ERR_NO_DS_PUBLISHED` | Onboarding or rollover: the parent publishes no DS for the zone. |
| REFUSED | `ERR_UNKNOWN_SIGNER` | Onboarding or rollover: a DS exists, but none matches the candidate KSK. This is often the current provider's DS. The fix is to add a DS for this key alongside it. |
| REFUSED | `ERR_WEAK_ALGORITHM` | A DNSKEY algorithm is below the floor (§11.3). |
| REFUSED | `ERR_FIRST_CONTACT_REQUIRES_KSK` | Onboarding message without a SEP-flagged DNSKEY. |
| REFUSED | `ERR_DECOMMISSION_REQUIRES_KSK` | Decommission authenticated by a key other than the pinned KSK. |
| REFUSED | `ERR_TRANSPORT_NOT_ALLOWED` | Onboarding or rollover over UDP (§9.1). |
| REFUSED | `ERR_QUOTA_EXCEEDED` | Per-zone 24-hour quota used up (§11.2). |
| REFUSED | `ERR_RATE_LIMITED` | Per-source-IP rate exceeded (§11.2). |
| NOTAUTH | `ERR_SIG0_LIFETIME_TOO_LONG` | The SIG(0) validity window exceeds the server's maximum (§5.1). |
| REFUSED | `ERR_KEY_MANAGEMENT_REQUIRES_KSK` | A key update or contact update was authenticated by a ZSK (§5.2). |
| REFUSED | `ERR_DNSKEY_RRSET_MISMATCH` | An update touching the DNSKEY RRset doesn't carry it complete, or would leave it different from the pinned KSK plus the registered ZSKs (§6.2). |
| REFUSED | `ERR_FULL_ZONE_REQUIRED` | Served content would change without an apex SOA, i.e. not as a complete replacement (§5.3). |
| REFUSED | `ERR_VERSION_REQUIRED` | A control change, or a zone's first content push, carries no version prerequisite (§6.3). |
| NXRRSET | `ERR_STALE_VERSION` | The version prerequisite isn't the zone's current version: a replay, or another control change was applied first. Re-read and re-sign (§6.3). |
| NXRRSET / YXRRSET / … | `ERR_STALE_SERIAL` (SOA only) | A prerequisite failed (RFC 2136 §2.4), or the SOA serial did not increase. |
| SERVFAIL | — | Internal error. Nothing was applied. |

A server **MAY** include a transaction identifier in the response for correlation with its audit log (§11.5). Verification is always synchronous: a NOERROR means the new data is already being served.

## 11. Operational requirements

### 11.1 Signature freshness

The server never re-signs anything. If the client's automation stops, the RRSIGs eventually expire and the zone turns bogus for validating resolvers. The server has no fault of its own to detect. Clients **MUST** re-push more often than their RRSIG validity (the reference client uses 30 days). Servers **SHOULD** monitor the earliest RRSIG expiration per zone and alert the zone's contact well before it passes.

### 11.2 Quotas and rate limits

Defaults (servers **SHOULD** make them configurable):

- **Per zone, rolling 24 hours:** 5 content pushes and 50 key-management messages (onboarding, key update, rollover, contact, decommission). These are counted separately because they cost very different amounts. The limit is tenant-scoped, so one zone can never use up another zone's allowance.
- **Per source IP, rolling 1 minute:** 30 UPDATE attempts, checked before any cryptography. This bounds scanning across many candidate zone names, which per-zone quotas cannot.

Raising a quota is an out-of-band matter between the zone owner and the hoster. The protocol does not negotiate it.

### 11.3 Algorithm policy

DNSKEY algorithms follow RFC 8624 and its updates. Servers **MUST** refuse RSAMD5 (1), DSA (3, 6), RSASHA1 (5, 7), RSASHA512 (10) and ECC-GOST (12). They **MUST** accept ECDSAP256SHA256 (13) and ED25519 (15), and **MAY** accept RSASHA256 (8), ECDSAP384SHA384 (14) and ED448 (16). The policy is an allowlist, so an unknown algorithm is refused. ECDSAP256SHA256 or ED25519 is **RECOMMENDED**; the reference client uses ED25519. The same allowlist applies to SIG(0), since a SIG(0) key is always a zone DNSKEY.

### 11.4 Contact registration and monitoring

A zone **MAY** register one or more contact addresses (`mailto:` or `https:` webhook) as a TXT RRset at `_sazu-contact.<zone>`, carried in a KSK-authenticated message. The model is ACME's account `contact` (RFC 8555 §7.3): the contact is control-plane data, bound to the key and changeable only by the key.

Servers **SHOULD** run a monitor as a process separate from the one that accepts pushes, sharing only the database. At a default interval of 5 minutes per zone, it:

- re-runs the §7.2 chain-of-trust check for the pinned KSK. A pinned KSK that no longer matches any DS means that either the registrar changed or the zone no longer validates.
- confirms that each registered ZSK is present in the served DNSKEY RRset (a canary for server bugs).

It alerts the contact on a *transition* (failing to passing, or passing to failing), and only after two consecutive identical observations, so that transient resolution failures do not page anyone. A failure to reach the parent at all is reported as inconclusive, never as a change.

### 11.5 Audit trail

The server logs every accepted and rejected transaction with the zone, time, source address, RCODE, status code, and the key tag and role of the key that authenticated it (recorded only after verification has succeeded). The exception is rejections for rate or transport (§6.1 steps 1 and 8), which are not logged because they could be used to flood the log from spoofed or rotating addresses. Because SIG(0) is asymmetric, the log of accepted transactions together with the retained messages is non-repudiable proof of who authorized each change.

### 11.6 Client key custody

The KSK is needed only for onboarding, key management and rollover. It **SHOULD** be kept offline or in an HSM. The ZSK is what routine automation holds. On disk it **SHOULD** be encrypted at rest or kept in a key-management service.

## 12. Security considerations

### 12.1 Trust model

| Party | Trusted for | Not trusted for |
|---|---|---|
| Zone owner | Holding the keys; deciding the zone contents | — |
| Hoster | Availability; answering queries from what it accepted | Originating or altering content |
| Parent / registry / registrar | The DS RRset, which is the root of authority for the zone | — (see §12.2) |
| Network | — | Anything. Messages are authenticated end to end by SIG(0). |

### 12.2 Parent compromise is out of scope

Anyone who can change the zone's DS at the parent can onboard or roll over the zone at any SAZU server, and can equally redirect NS and serve whatever they like elsewhere. No push protocol can prevent that. The mitigations belong one layer up: Registry Lock, hardened registrar accounts, and the §11.4 monitor, which turns a silent change into an alert. A hold-down on DS-only rollovers would make such a takeover slower and louder; it is listed in §15.

### 12.3 Key compromise

- **ZSK compromised.** The attacker can push content until the KSK holder retires that ZSK (§8.1). No registrar interaction is needed. A ZSK cannot change the DNSKEY RRset, the contact or the zone's existence.
- **KSK compromised.** Equivalent to losing control of the zone at this hoster: the attacker can register their own ZSKs. Recovery is a KSK rollover to a new key (§8.2) plus removal of the compromised key's DS at the parent. Until that DS is gone, the compromised KSK can roll the zone back to itself.

### 12.4 Hoster compromise

Someone with write access to the hoster's database, or an insider, can serve arbitrary data. For DNSSEC-validating resolvers this produces a bogus answer (SERVFAIL), not a successful forgery, because the attacker cannot produce RRSIGs chained to the DS. For non-validating clients there is no protection. That is the general state of DNSSEC deployment, not a SAZU property. The hoster stores only public keys, so a database leak discloses nothing that could be used to sign.

### 12.5 Denial of service

The costly operation is the outbound chain-of-trust walk. It is triggered only by onboarding and rollover messages, only after a valid SIG(0) by the candidate key, only over a handshake-validated transport (§9.1), and only within both rate limits. Per-zone lock striping keeps one slow walk from blocking other zones. Audit rows are not written for rate or transport rejections (§11.5).

### 12.6 Root trust anchor

The chain-of-trust check depends on a correct root trust anchor. Servers **MUST** have a way to update it: RFC 5011 tracking, or shipping updates of the IANA anchor. With a stale anchor, onboarding and rollover would fail for every zone at once after the next root KSK roll.

## 13. Design decisions and alternatives

### 13.1 SIG(0) with the zone key, not TSIG

TSIG (RFC 8945) is the widely supported way to authenticate RFC 2136 updates. It was considered and rejected:

- **Nothing to register.** Onboarding is one self-consistent message plus a DS the zone owner needed for DNSSEC anyway. There is no secret to provision and no account to secure, much like an ACME account is only a key pair.
- **Nothing worth stealing at the hoster.** The hoster stores only public keys. A leaked TSIG secret, by contrast, lets anyone forge updates.
- **One key lifecycle, not two.** No shared secret needs rotating alongside the DNSSEC keys.
- **Non-repudiation.** Only the private key holder can produce a valid SIG(0). A TSIG MAC could have come from either side.

The cost: SIG(0) client support is thin (`nsupdate -k` handles it, but most libraries do not), and using a zone key for SIG(0) goes against RFC 2931's "SHOULD NOT". The amendment in [`rfc-diff/`](rfc-diff/) argues that under an externally-signed policy the update principal *is* the zone signer, so the separation RFC 2931 protects does not exist to begin with. The KSK/ZSK split restores some separation of privilege: the warm key can only push content.

### 13.2 Full-zone pushes, not differential updates

Every content push replaces the whole zone. Differential pushes were built and tested three separate ways in the reference implementation (client-side chain cache, live reconciliation, server-side diffing) and all three were removed. They save bandwidth that typical zones do not need to save. They also bring a recurring correctness risk: incremental NSEC/NSEC3 chain maintenance, plus the fact that under NSEC3 a stateless signer cannot tell which hashed names correspond to a removal. A full push needs no signer-side state at all: the zone file *is* the push. The cost is transfer size and signing time proportional to the zone. That matters for zones with millions of records, which SAZU does not target.

### 13.3 Mandatory verification

A server could store whatever an authenticated principal sends ("trust the pipe"), or check only signature metadata. Both were rejected. SAZU's single guarantee is that what the server serves validates. A server that skips verification makes the same claim without backing it, and to anyone who has not audited it, it looks identical to one that does verify.

### 13.4 Not a DNS protocol at all

If standards alignment is not a concern, a signed zone file in a git repository, pushed over SSH to a hook that runs §6.2's verification, gives the same end-to-end property with version history for free. SAZU prefers RFC 2136 so that the message format, prerequisites and tooling are standard and so that a DNS server can implement it natively.

## 14. Reference implementation status

The CoreDNS plugin in [`mrwiora/coredns@feat/sazu`](https://github.com/mrwiora/coredns/tree/feat/sazu/plugin/sazu) (plugin `sazu`, client `sazuctl`, monitor `sazu-watchd`) is a proof of concept. As of this revision it implements: onboarding with full root-to-parent DNSSEC validation; KSK/ZSK split; ZSK add and retire; double-DS KSK rollover; full-zone pushes with NSEC or NSEC3; mandatory RRSIG verification; DNS over TCP and UDP and the HTTPS carrier (raw bytes and the `{"wire"}` envelope); the UDP restriction for onboarding and rollover; per-zone quotas and per-IP rate limits; SQLite persistence; the audit trail with key attribution; contact registration; decommission; and the §11.4 monitor with email and webhook alerts.

The review of this revision found a number of divergences and security bugs in the implementation. Fixes for all of them, including the per-zone version counter of §6.3, are on the [`fix/sazu-spec-v2-conformance`](https://github.com/mrwiora/coredns/tree/fix/sazu-spec-v2-conformance/plugin/sazu) branch, pending merge into `feat/sazu`; its threat model lists them. Remaining divergences on that branch:

| Spec | Implementation | Impact |
|---|---|---|
| §5.2: a content push carries no DNSKEY | A KSK-authenticated full push may also carry the (complete, KSK-signed) DNSKEY RRset. It then counts as a control change and needs the version. | None known; the message is simply two kinds in one. |
| §10: status carrier | TXT in Additional, as specified. EDE not used. | See §15. |
| §12.6: trust anchor updates | Configurable anchor file (e.g. `unbound-anchor`'s `root.key`); no built-in RFC 5011 tracking. | The built-in anchors are only as current as the build. |

The implementation's own `plugin/sazu/docs/SAZU-THREAT-MODEL.md` is a STRIDE analysis of the code. `SAZU-CLUSTER.md` sketches a design for running several instances.

## 15. Open issues

- **Rollover hold-down.** A KSK rollover authenticated only by the new key and the DS check (§8.2) lets a registrar compromise take over the hoster immediately. Proposal: accept such a rollover only after the new DS has been observed continuously for a hold-down period (e.g. 72 hours, in the spirit of RFC 5011) and the contact has been notified. A rollover that the old KSK also signs (for example an additional RRSIG(DNSKEY) by the old key) would take effect immediately. This keeps lost-key recovery possible while making takeovers slow and loud.
- **Status codes via Extended DNS Errors.** RFC 8914 EDE is the standard channel for this. Mapping candidates: 1 Unsupported DNSKEY Algorithm, 6 DNSSEC Bogus, 7 Signature Expired, 18 Prohibited, with the SAZU code in EXTRA-TEXT. Keeping the TXT record during a transition would preserve compatibility.
- **Per-key scoping beyond KSK/ZSK.** Several independent signers (CI, a second operator) currently each get a ZSK with full content rights. Finer scopes, such as a name subtree, would need signer metadata that the DNSKEY wire format cannot express.
- **Multi-instance consistency.** Key state, the zone version and SOA serial (§6.3), and quotas have to be shared or replicated between instances serving the same zone. The version and serial are ordinary zone state, so they travel with the zone.
- **Registrar behavior.** The §16 entries marked unconfirmed need to be verified empirically.

## 16. Registrar notes (informative)

EPP (RFC 5910) allows up to 8 DS records per domain, but whether a registrar's UI or API lets you use more than one varies. The table below reflects the authors' observations and published documentation at the time of writing. Check it before relying on it.

| Registrar | Second DS possible? | Notes |
|---|---|---|
| Amazon Route 53 | Yes | `AssociateDelegationSignerToDomain`. Purely additive, no live-match check. |
| Cloudflare Registrar | Yes | Documented for multi-signer. The mechanics are the same as for a migration. |
| Namecheap | Yes | DNSSEC panel for custom nameservers. |
| OVHcloud | Yes | DS records tab. Requires fully external DNS. |
| Gandi | Yes, indirectly | You submit DNSKEY data and Gandi computes the DS. Whether it live-checks the key is **unconfirmed**. |
| IONOS | Yes, not self-service | DS changes for external nameservers go through support email. |
| GoDaddy | Yes, risky | Reportedly checks the DS against the currently served DNSKEYs, and may reject a pre-published key. |
| Squarespace Domains | No | Only one DS record per domain. Use the §8.3 fallback. |

## 17. Changes since v1.5

- **HTTPS carrier:** now the exact wire bytes (RFC 8484 media type, optional `{"wire"}` envelope) instead of RFC 8427 structural JSON, which cannot preserve the bytes SIG(0) signs (§9.2).
- **Message kinds and authorization** are defined explicitly (§5.2). Key management, contact changes and decommission require the KSK. The apex DNSKEY RRset must be signed by the KSK (§6.2).
- **Onboarding** carries keys only. Content follows in a separate push (§7.1).
- **KSK rollover** is a double-DS rollover that re-pins in place. The v1.5 "second registration with its own copy of the zone, retiring after 90 days of inactivity" model is dropped (§8.2).
- **Replay protection** is now normative: a per-zone version counter that every control change must name as a prerequisite, SOA serial monotonicity for content, and a cap on SIG(0) lifetime (§5.1, §6.3). v1.5 relied on an optional prerequisite.
- **Algorithm section corrected:** SIG(0) and zone signing necessarily share an algorithm, because the SIG(0) key *is* the zone key. The v1.5 advice to use RSA for SIG(0) independently of the zone algorithm is removed.
- **Transport rule added:** no onboarding or rollover over UDP (§9.1). New status codes: `ERR_TRANSPORT_NOT_ALLOWED`, `ERR_FIRST_CONTACT_REQUIRES_KSK`, `ERR_DECOMMISSION_REQUIRES_KSK`.
- **Decommission** is added (§8.4).
- **Removed:** the per-customer account prerequisite (replaced by server scope policy), asynchronous verification with a status endpoint (verification is synchronous), deleting a zone after a day of parent silence (unsafe: an outage or an attacker blocking resolution would delete zones), and freezing pushes on any delegation change (replaced by the rollover hold-down proposal in §15).
- **Fixed** the RFC 3007 reference (§4.3), dropped the "Level 0/1/2" framing (only full verification exists), and moved the registrar table to an informative appendix.
- The document's own reference implementation is now linked, together with a list of its known divergences (§14).

---

*SAZU — Self-Authenticated Zone Update · Draft proposal v2.0*
