app [main!] { pkg: "../package/main.roc" }

import pkg.Ed25519

main! = |_args| Ok({})

# L0 tests of Ed25519.verify: the rejections. The rules are those of Go crypto/ed25519 (Verify, Go 1.17 and later, filippo.io/edwards25519):
# - LEN: a signature that does not have 64 bytes, or a public key that does not have 32 bytes, is false (Go: false for the signature,
#   a panic for the key; this package gives false).
# - S: S >= L is false (Go: SetCanonicalBytes), also when S < 2^253, so that the 3 high bits of the last byte are 0. A high bit set is false.
# - A: a public key that does not decode to a point is false (Go: SetBytes).
# - R: R is not decoded. Go compares the encoding of [S]B - [k]A with R, so an R that is not a point, or a changed R, is false.
# - SIG: a changed message, a changed signature or another key is false.
# - GO: Go accepts a small-order public key and a non-canonical one (y >= p): no small-order check, cofactorless, and SetBytes takes
#   y mod p. This package does the same, and the GO expects record it on purpose (dispute D1 of Talon slice 261, the user's decision
#   2026-11-23). The expected values come from a BigInt reference of the Go rules (and the probe of the code agent for the first two).
# The vectors come from scripts/vectors.mjs: BigInt for S + L and for the y with no x; node:crypto checks that each one is rejected.

# --- Test helpers (not under test) ---

nibble : U8 -> U8
nibble = |c| if (c >= 97) c - 87 else c - 48

from_hex : Str -> List(U8)
from_hex = |text| text.to_utf8().chunks_of(2).map(
	|p| match p {
		[a, b] => nibble(a) * 16 + nibble(b)
		_ => 0
	},
)

# RFC 8032 7.1 TEST 1, TEST 2 and TEST 3 (all valid; tests/rfc8032.roc checks them).
pk1 : List(U8)
pk1 = from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

sig1 : List(U8)
sig1 = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

pk2 : List(U8)
pk2 = from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")

msg2 : List(U8)
msg2 = from_hex("72")

sig2 : List(U8)
sig2 = from_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

pk3 : List(U8)
pk3 = from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")

msg3 : List(U8)
msg3 = from_hex("af82")

sig3 : List(U8)
sig3 = from_hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")

# The encoding of y = 2: (y^2 - 1) / (d y^2 + 1) is not a square mod p, so no point has it.
bad_point : List(U8)
bad_point = from_hex("0200000000000000000000000000000000000000000000000000000000000000")

# sig1 with S + L (still below 2^253), with S = L, and with the high bit of the last byte set.
sig_s_plus_l : List(U8)
sig_s_plus_l = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901554c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b")

sig_s_eq_l : List(U8)
sig_s_eq_l = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

sig_s_high : List(U8)
sig_s_high = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a108b")

v : List(U8), List(U8), List(U8) -> Bool
v = |public_key, message, signature| Ed25519.verify({ public_key, message, signature })

# The bytes with bit `bit` of byte `i` changed.
flip_bit : List(U8), U64, U64 -> List(U8)
flip_bit = |bytes, i, bit| bytes.map_with_index(|b, j| if (j == i) b.bitwise_xor([1, 2, 4, 8, 16, 32, 64, 128].get(bit) ?? 0) else b)

# A guard of the test data: the unchanged vectors are valid
expect v(pk1, [], sig1) and v(pk2, msg2, sig2) and v(pk3, msg3, sig3)

# S: S + L is not canonical (S >= L), and its 3 high bits are 0
expect !v(pk1, [], sig_s_plus_l)

# S: S = L
expect !v(pk1, [], sig_s_eq_l)

# S: the high bit of the last byte is set
expect !v(pk1, [], sig_s_high)

# S: a changed byte of S
expect !v(pk1, [], flip_bit(sig1, 32, 0))

# R: a changed byte of R
expect !v(pk1, [], flip_bit(sig1, 0, 0))

# R: the last byte of R changed: bit 7 (the sign of x) and bit 0
expect !v(pk1, [], flip_bit(sig1, 31, 7)) and !v(pk1, [], flip_bit(sig1, 31, 0))

# R: all 32 bytes of R count. The zero key (order 4), S = 0, R = 31 zero bytes and then 0x80, the message [0]: k mod 4 = 3, so
# [S]B - [k]A is A, whose encoding is 32 zero bytes. It equals R in the first 31 bytes only, so Go rejects it
# (mutation check of slice 261a: a compare of only 31 bytes of R accepts it; values from a BigInt reference of the Go rules)
expect !v(List.repeat(0, 32), [0], List.repeat(0, 31).append(0x80).concat(List.repeat(0, 32)))

# R: an R that is not a point (the encoding of y = 2), with the S of sig1
expect !v(pk1, [], bad_point.concat(sig1.drop_first(32)))

# A: a public key that is not a point
expect !v(bad_point, [], sig1)

# A: a changed byte of the public key
expect !v(flip_bit(pk1, 0, 0), [], sig1)

# SIG: another key (the key of TEST 2 with the signature of TEST 1)
expect !v(pk2, [], sig1)

# SIG: a changed message (TEST 2, bit 0 of its byte)
expect !v(pk2, flip_bit(msg2, 0, 0), sig2)

# SIG: one more byte at the end of the message (TEST 3)
expect !v(pk3, msg3.append(0), sig3)

# SIG: the signature of another message (the key and signature of TEST 2 on the message of TEST 3)
expect !v(pk2, msg3, sig2)

# SIG: each of the 16 bits of the message of TEST 3 changed, one at a time
expect U64.until(0, 16).fold(Bool.True, |ok, i| ok and !v(pk3, flip_bit(msg3, i // 8, i % 8), sig3))

# LEN: a signature of 63 bytes
expect !v(pk1, [], sig1.drop_last(1))

# LEN: a signature of 65 bytes (one more byte at the end)
expect !v(pk1, [], sig1.append(0))

# LEN: a public key of 31 bytes and of 33 bytes
expect !v(pk1.drop_last(1), [], sig1) and !v(pk1.append(0), [], sig1)

# LEN: all empty
expect !v([], [], [])

# GO: the key of 32 zero bytes (y = 0, a point of order 4), R of 32 zero bytes and S = 0. The check is: the encoding of -[k]A is R.
# For the message [9], k mod 4 = 3, so -[k]A = A, and its encoding is R: Go accepts.
expect v(List.repeat(0, 32), [9], List.repeat(0, 64))

# GO: the same key and signature for the message [0]: k mod 4 is not 3, so Go rejects
expect !v(List.repeat(0, 32), [0], List.repeat(0, 64))

# GO: a non-canonical public key: the encoding of y = p + 1 (bytes ee ff ... ff 7f), which is y = 1, the identity point. With R the
# canonical identity (01 00 ... 00) and S = 0, [S]B - [k]A is the identity for each message, so Go accepts it for "abc" and for the empty message
expect v([0xee].concat(List.repeat(0xff, 30)).append(0x7f), "abc".to_utf8(), [1].concat(List.repeat(0, 63))) and v([0xee].concat(List.repeat(0xff, 30)).append(0x7f), [], [1].concat(List.repeat(0, 63)))
