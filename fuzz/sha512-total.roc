app [target] {
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.7.0/HBigHQhVZWEF2EkLxpYK35u8P6UNsAmPYxpNFTxXK1Br.tar.zst",
	pkg: "../package/main.roc",
}

import fuzz.Fuzz
import pkg.Sha512

## TESTING.md 4 ("never crashes"), FIPS 180-4: hash never crashes, gives 64 bytes for any input, gives the same digest twice,
## and gives another digest when one zero byte is added (a collision of SHA-512 is not expected).
test : List(U8) -> Fuzz.Outcome
test = |bytes| {
	d = Sha512.hash(bytes)
	if d.len() != 64 {
		crash "the digest does not have 64 bytes"
	} else if Sha512.hash(bytes) != d {
		crash "two digests of one input differ"
	} else if Sha512.hash(bytes.append(0)) == d {
		crash "one more byte gave the same digest"
	} else {
		Fuzz.keep
	}
}

target = Fuzz.target_with({
	name: "sha512-total",
	examples: [Fuzz.example({ name: "empty", revision: "1", make: || [] })],
	generator: Fuzz.bytes,
	test,
	show: |bytes| Str.inspect(bytes),
})
