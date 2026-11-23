app [main!] { pkg: "../package/main.roc" }

import pkg.Ed25519

main! = |_args| Ok({})

# L0 tests of Ed25519.is_valid_public_key: 32 bytes that decode to a point by the decode of verify (the rules of Go crypto/ed25519,
# filippo.io/edwards25519 SetBytes):
# - RFC: the 5 public keys of RFC 8032 7.1 decode.
# - NOX: a y with no x does not decode: (y^2 - 1) / (d y^2 + 1) is not a square mod p. The values y = 2, 7, 8, 11, 12, 13 (the 6 smallest)
#   and y = p - 2 (the largest below p), with and without the sign bit, and y = p + 2 (a non-canonical form of 2).
# - GO: Go accepts each small-order point (the 7 encodings of y, as in fuzz/verify-total.roc), a non-canonical y (p, p + 1: taken mod p),
#   and x = 0 with the sign bit set (y = 1).
# - LEN: only 32 bytes.
# The values come from a BigInt reference of the Go rules (Talon research/slice-261a-revert/ref.mjs and keys.mjs). The mutation check of
# Talon slice 261a needs these tests: a decode that takes a y with no x (the mutant non-point-a-valid) gives Bool.True for the NOX keys.

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

# The 32 little-endian bytes of a small y.
small_y : U8 -> List(U8)
small_y = |y| [y].concat(List.repeat(0, 31))

# The bytes with the sign bit (bit 7 of byte 31) set.
with_sign : List(U8) -> List(U8)
with_sign = |bytes| bytes.map_with_index(|b, i| if (i == 31) b.bitwise_or(0x80) else b)

valid : List(U8) -> Bool
valid = |bytes| Ed25519.is_valid_public_key(bytes)

rfc_keys : List(Str)
rfc_keys = [
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
	"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
	"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
	"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
	"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
]

# y = p - 2: no x.
y_p_minus_2 : List(U8)
y_p_minus_2 = from_hex("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

# y = p + 2 (non-canonical; mod p it is 2): no x.
y_p_plus_2 : List(U8)
y_p_plus_2 = from_hex("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

small_order : List(Str)
small_order = [
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]

# RFC: the 5 public keys of RFC 8032 7.1
expect rfc_keys.all(|k| valid(from_hex(k)))

# NOX: y = 2, 7, 8, 11, 12 and 13 have no x
expect [2, 7, 8, 11, 12, 13].all(|y| !valid(small_y(y)))

# NOX: the same y values with the sign bit set
expect [2, 7, 8, 11, 12, 13].all(|y| !valid(with_sign(small_y(y))))

# NOX: y = p - 2 (the largest y below p with no x), with and without the sign bit
expect !valid(y_p_minus_2) and !valid(with_sign(y_p_minus_2))

# NOX: y = p + 2, a non-canonical form of y = 2
expect !valid(y_p_plus_2)

# GO: each small-order point, in canonical and non-canonical form (y = 1, p - 1, 0, the 2 values of order 8, p, p + 1)
expect small_order.all(|k| valid(from_hex(k)))

# GO: x = 0 with the sign bit set (y = 1, bytes 01 00 ... 00 80)
expect valid(with_sign(small_y(1)))

# GO: an RFC key with the sign bit changed is still a point (the other x)
expect valid(with_sign(from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")))

# LEN: 31, 33 and 0 bytes
expect !valid(from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f70751")) and !valid(small_y(1).append(0)) and !valid([])
