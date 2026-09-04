# Transition Envelope interoperability fixtures

These are approved static protocol vectors for the development profile, not
executable tests and not a replacement for runtime conformance tests.

- `canonicalization.json` contains RFC 8785 JCS-based value vectors and explicit
  rejection cases.
- `effect-identity.json` contains the proposed `identity-v1` preimage, domain
  separation, expected SHA-256 identities, and identity-exclusion cases.

## How to use

An implementation should:

1. Parse the fixture without duplicate-key tolerance.
2. Canonicalize each valid JSON value according to the declared version.
3. Compare canonical JSON text and exact UTF-8 bytes with the fixture.
4. For identity vectors, prepend the declared UTF-8 domain separator and calculate
   the declared digest.
5. Compare the complete `mycelium:effect:v1:<digest>` string.
6. Confirm that rejection cases fail before any ledger claim.

The expected hashes are **approved identity-v1 vectors**. The identity preimage,
canonicalization profile, and hashing construction are versioned by the RFC. Current
Python `canonical_json()` and
`derive_effect_id_for_call()` are not expected to match every vector because they
use a Python serializer and currently include optional dispatch identity.
