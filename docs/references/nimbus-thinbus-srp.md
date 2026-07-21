# Nimbus / Thinbus SRP-6a — byte-exact spec for sfs interop (D5-3)

**Why:** sfs's ZK SaaS auth MUST speak the same SRP-6a as the Java/**Nimbus** world, because the Zero family's
Java backends use Nimbus (BouncyCastle was tried and could not be made to work — Nimbus is effectively the only
viable Java SRP). Ifyna's production uses the **Thinbus** JS client against a **Nimbus** Java server, so
*whatever Thinbus computes, Nimbus accepts*. Therefore **Thinbus is the ground-truth spec**: matching Thinbus =
speaking Nimbus.

**Conformance fixture:** `crates/sfs-saas/tests/fixtures/thinbus_nimbus_srp_vectors.json` — a full real Thinbus
client↔server handshake transcript (`client_step3_ok: true`, both sides agree on `K`/`SS`). Regenerate with
`crates/sfs-saas/tests/fixtures/gen_srp_vectors.mjs` (run via node in a dir where `thinbus-srp` is installed,
e.g. Ifyna's `admin-frontend`). The sfs Rust SRP implementation MUST reproduce these values byte-for-byte.

## Parameters (RFC 5054, 2048-bit)
- `N` = the RFC5054 2048-bit safe prime (decimal in the fixture `params.N_base10`).
- `g` = 2.
- `k` = constant `5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300` (hex). This is `H(N | PAD(g))`
  under Nimbus, but Thinbus is *given* it as a literal constant — sfs uses the **same literal constant**.
- Hash `H` = **SHA-256**.

## The interop-critical conventions (THIS is what breaks naive impls)
Everything is hashed over **ASCII hex strings**, not raw big-endian bytes:
- `H(x)` = lowercase-hex of `SHA256(utf8_bytes_of(x))`. (x is a string; the SHA input is its ASCII bytes.)
- `toHex(n)` = `BigInteger.toString(16)` = **minimal** lowercase hex, **no zero-padding**, leading zeros
  trimmed. (NOT fixed-width / NOT PAD-to-len(N).)
- `strip0(s)` = remove leading `'0'` characters from the hex string `s` (Java BigInteger trims leading zeros,
  so the JS side mirrors it). Applied to several hash outputs — see below.

> ⚠️ The RustCrypto `srp` crate does NOT match this (it hashes raw bytes and uses a different M1). Do not use it.

## Formulas (reproduce exactly)
```
x:   hash1 = strip0( H(identity + ":" + password) )
     x     = strip0( H( UPPERCASE(saltHex + hash1) ) )   parsed as BigInteger (base 16)
            // NOTE the .toUpperCase() on (saltHex + hash1) before the second hash.
v:   v = g^x mod N                       (verifier = toHex(v))
A:   A = g^a mod N                       (a = client private, random in [1,N))
B:   B = (k*v + g^b) mod N               (b = server private, random in [1,N))
u:   u = H( toHex(A) + toHex(B) )  parsed as BigInteger(base16)   (no strip0; used as number)
S:   client: S = (B - k * g^x)^(a + u*x) mod N
     server: S = (A * v^u)^b mod N        (both equal — the shared secret)
K:   K = H( toHex(S) )                    (the session key)
M1:  M1 = strip0( H( toHex(A) + toHex(B) + toHex(S) ) )    // Tom-Wu form, NOT RFC5054's H(N)^H(g) form
M2:  M2 = strip0( H( toHex(A) + M1 + toHex(S) ) )          // note: uses S, not K
```
Salt: random 32-byte hex (server stores it). Verifier `v` and salt are what the server persists (NEVER the
password). `client.step3(M2)` verifies the server proof → mutual auth.

## What the sfs T6 tests must assert against the fixture
1. `k` literal == fixture `params.k_base16`, and equals `H(N|PAD(g))` recomputed (sanity).
2. From `(salt, username, password)` → recompute `verifier` == fixture `verifier`. (validates x + toUpper + strip0.)
3. From `(toHex A, toHex B, toHex S=client_internals.SS)` → recompute `K` == fixture `sessionKey_*`,
   `M1` == fixture `M1`, `M2` == fixture `M2`. (validates u-not-needed-here, K, M1, M2, strip0.)
4. (Optional, opt-in/ignored) a LIVE cross-handshake Rust↔Thinbus via node closes the raw-modexp gap; not in
   default CI (no node dep at test time).

## sfs server storage (ZK)
Server (`sfs-saas`) stores per account ONLY: `salt`, `verifier`, and the opaque **wrapped root key** blob.
Never the password, never `x`, never the root key. Root-key-wrap KEK = Argon2id(password) (sfs-internal,
independent of the Nimbus interop).
