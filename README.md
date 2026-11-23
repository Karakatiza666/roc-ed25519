# roc-ed25519

SHA-512 and Ed25519 signature verification for Roc, in pure Roc. No platform call, so it works on each platform and target.

| Function | Type | Result |
| --- | --- | --- |
| `Sha512.hash` | `List(U8) -> List(U8)` | The 64-byte SHA-512 digest of the bytes (FIPS 180-4). |
| `Ed25519.is_valid_public_key` | `List(U8) -> Bool` | `Bool.True` when the bytes are 32 bytes that decode to a point of the curve, by the same decode that `verify` uses (check 2 below): a y of p or more is taken mod p, a small-order point and x = 0 with the sign bit set are accepted, a y with no x is rejected. Any other length gives `Bool.False`. A caller can check a key once, before it uses it. |
| `Ed25519.verify` | `{ public_key : List(U8), message : List(U8), signature : List(U8) } -> Bool` | `Bool.True` when `signature` is a valid Ed25519 signature of `message` by `public_key` (RFC 8032, PureEdDSA: no context, no prehash), by the checks below. |

The package verifies only. It does not make keys and does not sign: a signer needs a secret key and constant-time code, and this package is not that.

## Checks of `Ed25519.verify`

The checks are those of Go `crypto/ed25519` (`Verify`, Go 1.17 and later), so a signature that Go accepts is accepted here, and a signature that Go rejects is rejected here:

| # | Check | Fails with |
| --- | --- | --- |
| 1 | The public key has 32 bytes and the signature has 64 bytes | `Bool.False` (Go panics for a key of another length) |
| 2 | The public key decodes to a point of the curve: the same decode as `Ed25519.is_valid_public_key` | `Bool.False` |
| 3 | S, the last 32 bytes of the signature as a little-endian number, is below the group order L | `Bool.False` |
| 4 | The encoding of [S]B - [k]A is equal to R (the first 32 bytes), byte for byte, with k = SHA-512(R ‖ A ‖ message) mod L | `Bool.False`. R is not decoded, so an R that is not a canonical point encoding never matches. |

The check is cofactorless, as in Go. Two results follow, and the tests record them on purpose (`tests/ed25519.roc`, the `GO` expects):

| Input | Result, as Go |
| --- | --- |
| A small-order public key (for example 32 zero bytes, a point of order 4) | Not rejected. With R and S chosen for it, some messages verify: the zero key, a zero signature and the message `[9]` give `Bool.True`; the message `[0]` gives `Bool.False`. |
| A non-canonical public key (y >= p, for example `ee ff ... ff 7f`, which is y = 1) | Decoded as y mod p, not rejected |

A caller that must refuse such keys checks the key itself. A caller that verifies with a fixed, trusted key (for example a transparency log key) is not affected.

## Usage

Add the release to the header of your app, package or platform (the URL is known after the first release):

```roc
ed: "https://github.com/Karakatiza666/roc-ed25519/releases/download/0.1.0/<hash>.tar.zst",
```

Then:

```roc
import ed.Sha512
import ed.Ed25519

expect Sha512.hash("abc".to_utf8()).len() == 64
expect !Ed25519.verify({ public_key: [], message: [], signature: [] })
```

## Tests

| Layer | Files | Tool |
| --- | --- | --- |
| L0 | `tests/sha512.roc` (FIPS 180-4 examples and lengths at the padding edges), `tests/rfc8032.roc` (all test vectors of RFC 8032 section 7.1), `tests/ed25519.roc` (the rejections of the checks above), `tests/key.roc` (`is_valid_public_key`: points, y values with no x, the keys that Go accepts, lengths) | `roc test` |
| L1 | `fuzz/*.roc` (properties: verify never crashes and rejects random signatures for a key that is not small-order, one changed bit rejects a valid vector, SHA-512 gives 64 bytes and is deterministic) | [roc-fuzz](https://github.com/lukewilliamboswell/roc-fuzz) 0.7.0 |

`scripts/test.sh [ROC [FUZZ_ROC]]` runs `roc check`, `roc fmt --check`, the L0 tests and the L1 targets. Use the nightly in `.roc-version` (`nightly-2026-11-13-03dce41`; the fuzz targets of roc-fuzz 0.7.0 crash at start with the older nightlies 10-14 and 11-06). `RUNS=<n>` sets the fuzz run count (default 100000), and `FUZZ_TIME=<s>` the time limit of one fuzz target (default 120 s; a run that reaches it ends and passes). CI (`.github/workflows/ci.yml`) runs the same checks on that nightly, with the same time limit.

`node scripts/vectors.mjs` makes the test vectors again with `node:crypto` and BigInt, and checks each one against node. `scripts/rfc8032-7.1.txt` is section 7.1 of RFC 8032 (https://www.rfc-editor.org/rfc/rfc8032.txt).

## Release

`.github/workflows/release.yml` makes a release with [roc-lang/release-package](https://github.com/roc-lang/release-package): `gh workflow run release.yml --ref main -f release_version=X.Y.Z`. The tag is `X.Y.Z` with no prefix, and the one package asset is `<hash>.tar.zst` from `roc bundle`.

## License

UPL-1.0, see `LICENSE`.
