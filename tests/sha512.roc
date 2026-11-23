app [main!] { pkg: "../package/main.roc" }

import pkg.Sha512

main! = |_args| Ok({})

# L0 tests of Sha512.hash (FIPS 180-4). The expected digests come from scripts/vectors.mjs (node:crypto), not from the code under test.
# - FIPS: the examples of FIPS 180-4 (NIST CSRC, "SHA512.pdf"): the empty message, "abc" (one block) and the 896-bit message (two blocks).
#   scripts/vectors.mjs checks them against node:crypto.
# - LEN: pattern(n), byte i is (i * 31 + 7) mod 256, at the padding edges (111, 112, 113: the 16-byte length field fits or does not fit
#   in the last block; 127, 128, 129; 239, 240; 255, 256) and longer inputs (1000 and 8192 bytes: 8 and 65 blocks).
#   The NIST example of 1,000,000 times "a" is not here: its time in `roc test` is not known yet.

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

# The bytes of pattern(n).
pattern : U64 -> List(U8)
pattern = |n| U64.until(0, n).fold([], |acc, i| acc.append(((i * 31 + 7) % 256).to_u8_wrap()))

# FIPS: the empty message
expect Sha512.hash([]) == from_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

# FIPS: "abc", one block
expect Sha512.hash("abc".to_utf8()) == from_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

# FIPS: the 896-bit message, two blocks
expect Sha512.hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_utf8()) == from_hex("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")

# The digest has 64 bytes for each length
expect [0, 1, 111, 112, 128, 1000].all(|n| Sha512.hash(pattern(n)).len() == 64)

# LEN: pattern(1)
expect Sha512.hash(pattern(1)) == from_hex("365d11a1dfe610b60efa996136d37ab8afd2715b8c6bc2850dc5e6005b702bb9f59b0f306ecb2c43ee44c429967d45843524eb2f7c16aab9bde142ee268b51c6")

# LEN: pattern(111)
expect Sha512.hash(pattern(111)) == from_hex("da780d8338a8a920ceb6892cb4ecbb0cc0c66956269aadd5dd0f48790a00857bd975890f3b2955a317738cc7a770820c29f922ffbc22020f1909d594cc987d1b")

# LEN: pattern(112)
expect Sha512.hash(pattern(112)) == from_hex("053182f7fa4e59f8636e415a77ed4fdc650f0a43834c9d35adf899599c3ab9c4153f02ff50bd01888060cd36a6fa12d9db242fc35164c80135613514186d5843")

# LEN: pattern(113)
expect Sha512.hash(pattern(113)) == from_hex("766fea2f90094ecec1166ea4d6e9ddc6ae6fbe4a060e049300ecbe631a7d6547409b6ac39865409e6dd5dada112955fddf32698feb98806c1910f446ac5af7e3")

# LEN: pattern(127)
expect Sha512.hash(pattern(127)) == from_hex("a7a75593826fd37d4e60f6101eabb9f8ab1cf4d5319ebc805266d5da8deb5097de1a235fc5d9d3d73c50ac100ffc75089fb454674ab61232091bd19cbdc67396")

# LEN: pattern(128)
expect Sha512.hash(pattern(128)) == from_hex("df007a08f3aaae47e0c92ef840ecd43645ae6098c819f2a4a66174ef1cd49e5c6dfccf0616895e570b7564af641de5863dff9f89c752913d30cf0ecf678e1635")

# LEN: pattern(129)
expect Sha512.hash(pattern(129)) == from_hex("a10ea769b79831bca33e9efb29fc501ded6e9c88885d079acb76eecaa8ac58d68bdc7e00103053e1519352c0d064c87accc3d553a6039decc2c4f1e7667eef79")

# LEN: pattern(239)
expect Sha512.hash(pattern(239)) == from_hex("38980139aa28f1ccec548e21fd73d927488c4aa749a4b304fe0c5f7797fb80a03bc0557584ef42f47e0d3ff4eee0011084ac8421cf08dd2cea6a132bcd075c90")

# LEN: pattern(240)
expect Sha512.hash(pattern(240)) == from_hex("eb5690f4b1753298de6626f031576ca2b93cec042d597a7a1f9e47534af610f409acb608d88fdaeade8b36fd09a6cd81f2ff8ec10962e79cd791eebc26d569f5")

# LEN: pattern(255)
expect Sha512.hash(pattern(255)) == from_hex("ac1ecd53106f3dfba66b7b3fcac37652aad2aad2a291c354eaca03928e74853d53c0e8c7f2fa05025efdb262fd4b51103747d3dafd53e1feefc590bf2617b30a")

# LEN: pattern(256)
expect Sha512.hash(pattern(256)) == from_hex("7629794792236644c8c5792257d9a64320b887aae34806f9bc3713c494ea7f17602e0a9a9009b1e69b31d189d89a4f599dd30891fa04a1668ff31e30d0719df4")

# LEN: pattern(1000)
expect Sha512.hash(pattern(1000)) == from_hex("b41d42e106eca6bf57123566b7ed1550c37d33af23afbfa8e302dfd44c988b3003a26b4140ef42f535e66ea424e7c4a31616307269e6d520a6508f726da23d0a")

# LEN: pattern(8192)
expect Sha512.hash(pattern(8192)) == from_hex("e7dc889a30c42e05542ca312b441bc602b939564b1cc7a913780ae9fed52b38cf28a9e01fc877e110efd7b9e3b737527122dd2e7ba25dd8f8b60f260627ef5e1")
