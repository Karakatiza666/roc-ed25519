app [target] {
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.7.0/HBigHQhVZWEF2EkLxpYK35u8P6UNsAmPYxpNFTxXK1Br.tar.zst",
	pkg: "../package/main.roc",
}

import fuzz.Fuzz
import pkg.Ed25519

# The input: random bytes for the key, the message and the signature. The key length is 32 for about half of the inputs and
# the signature length is 64 for about half (the other inputs keep their random length), so both the length checks and the curve code run.
Input := { key : List(U8), key_full : U8, message : List(U8), sig : List(U8), sig_full : U8 }.{
	parser_for : _
	encoder_for : _

	generator_for : Fuzz.FuzzEncoding -> Fuzz.Generator(Input)
	generator_for = |_| { key: Fuzz.bytes, key_full: Fuzz.u8_in(0, 1), message: Fuzz.bytes, sig: Fuzz.bytes, sig_full: Fuzz.u8_in(0, 1) }.Fuzz
}

# The bytes cut or padded to n bytes. The pad byte is 0x55, not 0: a key of 32 zero bytes is a small-order point (test D1, slice 261).
sized : List(U8), U64 -> List(U8)
sized = |bytes, n| bytes.take_first(n).concat(List.repeat(0x55, n - bytes.take_first(n).len()))

# The 7 encodings, with the sign bit (bit 7 of byte 31) cleared, of the y of each point of order 1, 2, 4 or 8 (the 5 canonical values
# 1, p - 1, 0 and the 2 values of order 8, and the non-canonical p and p + 1). Go accepts such a key (cofactorless, no small-order check),
# and with it a signature with R and S chosen by the attacker can verify for about 1 message in 8 or more, so a random signature is not
# rejected for it. The property skips such keys. Values from libsodium (`blocklist` of `crypto_core_ed25519_is_valid_point`), each checked
# with BigInt (8 P = identity).
small_order : List(List(U8))
small_order = [
	[1].concat(List.repeat(0, 31)),
	[0xec].concat(List.repeat(0xff, 30)).append(0x7f),
	List.repeat(0, 32),
	[0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
	[0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
	[0xed].concat(List.repeat(0xff, 30)).append(0x7f),
	[0xee].concat(List.repeat(0xff, 30)).append(0x7f),
]

# True when the key is a small-order point in any encoding (the sign bit is ignored).
is_small_order : List(U8) -> Bool
is_small_order = |key| small_order.contains(key.map_with_index(|b, i| if (i == 31) b.bitwise_and(0x7f) else b))

## TESTING.md 4 ("never crashes"): verify never crashes, for any lengths and bytes. For a key that is not a small-order point,
## a random signature is valid with a probability of about 2^-128, so the result is always Bool.False. A small-order key is skipped
## after the call (Go accepts some signatures for it, test D1 of slice 261; tests/ed25519.roc records that on purpose). A key that is
## not 32 bytes or a signature that is not 64 bytes gives Bool.False by the length rule (README, Go crypto/ed25519).
test : Input -> Fuzz.Outcome
test = |input| {
	public_key = if (input.key_full == 1) sized(input.key, 32) else input.key
	signature = if (input.sig_full == 1) sized(input.sig, 64) else input.sig
	valid = Ed25519.verify({ public_key, message: input.message, signature })
	if (valid and !is_small_order(public_key)) crash "a random signature verified" else Fuzz.keep
}

target = Fuzz.target_with({
	name: "verify-total",
	examples: [
		Fuzz.example({ name: "all-empty", revision: "1", make: || { key: [], key_full: 0, message: [], sig: [], sig_full: 0 } }),
		Fuzz.example({ name: "padded-short", revision: "1", make: || { key: [1, 2, 3], key_full: 1, message: [9], sig: [4], sig_full: 1 } }),
	],
	generator: Input.generator_for(Default),
	test,
	show: |input| Str.inspect(input),
})
