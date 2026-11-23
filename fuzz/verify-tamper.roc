app [target] {
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.7.0/HBigHQhVZWEF2EkLxpYK35u8P6UNsAmPYxpNFTxXK1Br.tar.zst",
	pkg: "../package/main.roc",
}

import fuzz.Fuzz
import pkg.Ed25519

nibble : U8 -> U8
nibble = |c| if (c >= 97) c - 87 else c - 48

from_hex : Str -> List(U8)
from_hex = |text| text.to_utf8().chunks_of(2).map(
	|p| match p {
		[a, b] => nibble(a) * 16 + nibble(b)
		_ => 0
	},
)

# RFC 8032 7.1 TEST 3.
pk3 : List(U8)
pk3 = from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")

msg3 : List(U8)
msg3 = from_hex("af82")

sig3 : List(U8)
sig3 = from_hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")

# The input: which part to change (0 key, 1 message, 2 signature), the byte (mod the length of the part) and the bit.
Input := { part : U8, pos : U64, bit : U8 }.{
	parser_for : _
	encoder_for : _

	generator_for : Fuzz.FuzzEncoding -> Fuzz.Generator(Input)
	generator_for = |_| { part: Fuzz.u8_in(0, 2), pos: Fuzz.u64_in(0, 63), bit: Fuzz.u8_in(0, 7) }.Fuzz
}

flip_bit : List(U8), U64, U8 -> List(U8)
flip_bit = |bytes, i, bit| bytes.map_with_index(|b, j| if (j == i % bytes.len()) b.bitwise_xor([1, 2, 4, 8, 16, 32, 64, 128].get(bit.to_u64()) ?? 0) else b)

## RFC 8032 5.1.7, Go crypto/ed25519: one changed bit in the key, the message or the signature of a valid vector gives Bool.False.
test : Input -> Fuzz.Outcome
test = |input| {
	args = match input.part {
		0 => { public_key: flip_bit(pk3, input.pos, input.bit), message: msg3, signature: sig3 }
		1 => { public_key: pk3, message: flip_bit(msg3, input.pos, input.bit), signature: sig3 }
		_ => { public_key: pk3, message: msg3, signature: flip_bit(sig3, input.pos, input.bit) }
	}
	if (Ed25519.verify(args)) crash "a changed vector verified" else Fuzz.keep
}

target = Fuzz.target_with({
	name: "verify-tamper",
	examples: [Fuzz.example({ name: "first-key-bit", revision: "1", make: || { part: 0, pos: 0, bit: 0 } })],
	generator: Input.generator_for(Default),
	test,
	show: |input| Str.inspect(input),
})
