## SHA-512 of FIPS 180-4, in pure Roc.
Sha512 :: [].{

	## The 64-byte SHA-512 digest of the bytes. The empty list is a valid input.
	hash : List(U8) -> List(U8)
	hash = |bytes| {
		msg = pad(bytes)
		var $st = {
			a: 0x6A09E667F3BCC908.U64,
			b: 0xBB67AE8584CAA73B.U64,
			c: 0x3C6EF372FE94F82B.U64,
			d: 0xA54FF53A5F1D36F1.U64,
			e: 0x510E527FADE682D1.U64,
			f: 0x9B05688C2B3E6C1F.U64,
			g: 0x1F83D9ABFB41BD6B.U64,
			h: 0x5BE0CD19137E2179.U64,
		}
		var $off = 0.U64
		while $off < msg.len() {
			$st = compress($st, msg, $off)
			$off = $off + 128
		}
		[$st.a, $st.b, $st.c, $st.d, $st.e, $st.f, $st.g, $st.h].fold(List.with_capacity(64), |acc, w| append_be64(acc, w))
	}
}

# The state: the 8 words of the hash.
State : { a : U64, b : U64, c : U64, d : U64, e : U64, f : U64, g : U64, h : U64 }

# The round constants of FIPS 180-4 4.2.3.
k : List(U64)
k = [
	0x428A2F98D728AE22,
	0x7137449123EF65CD,
	0xB5C0FBCFEC4D3B2F,
	0xE9B5DBA58189DBBC,
	0x3956C25BF348B538,
	0x59F111F1B605D019,
	0x923F82A4AF194F9B,
	0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242,
	0x12835B0145706FBE,
	0x243185BE4EE4B28C,
	0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F,
	0x80DEB1FE3B1696B1,
	0x9BDC06A725C71235,
	0xC19BF174CF692694,
	0xE49B69C19EF14AD2,
	0xEFBE4786384F25E3,
	0x0FC19DC68B8CD5B5,
	0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275,
	0x4A7484AA6EA6E483,
	0x5CB0A9DCBD41FBD4,
	0x76F988DA831153B5,
	0x983E5152EE66DFAB,
	0xA831C66D2DB43210,
	0xB00327C898FB213F,
	0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2,
	0xD5A79147930AA725,
	0x06CA6351E003826F,
	0x142929670A0E6E70,
	0x27B70A8546D22FFC,
	0x2E1B21385C26C926,
	0x4D2C6DFC5AC42AED,
	0x53380D139D95B3DF,
	0x650A73548BAF63DE,
	0x766A0ABB3C77B2A8,
	0x81C2C92E47EDAEE6,
	0x92722C851482353B,
	0xA2BFE8A14CF10364,
	0xA81A664BBC423001,
	0xC24B8B70D0F89791,
	0xC76C51A30654BE30,
	0xD192E819D6EF5218,
	0xD69906245565A910,
	0xF40E35855771202A,
	0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8,
	0x1E376C085141AB53,
	0x2748774CDF8EEB99,
	0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63,
	0x4ED8AA4AE3418ACB,
	0x5B9CCA4F7763E373,
	0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC,
	0x78A5636F43172F60,
	0x84C87814A1F0AB72,
	0x8CC702081A6439EC,
	0x90BEFFFA23631E28,
	0xA4506CEBDE82BDE9,
	0xBEF9A3F7B2C67915,
	0xC67178F2E372532B,
	0xCA273ECEEA26619C,
	0xD186B8C721C0C207,
	0xEADA7DD6CDE0EB1E,
	0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA,
	0x0A637DC5A2C898A6,
	0x113F9804BEF90DAE,
	0x1B710B35131C471B,
	0x28DB77F523047D84,
	0x32CAAB7B40C72493,
	0x3C9EBE0A15C9BEBC,
	0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6,
	0x597F299CFC657E2A,
	0x5FCB6FAB3AD6FAEC,
	0x6C44198C4A475817,
]

# The message with the padding of FIPS 180-4 5.1.2: 0x80, zeros, and the bit length as 16 big-endian bytes.
pad : List(U8) -> List(U8)
pad = |bytes| {
	n = bytes.len()
	zeros = (239 - (n % 128)) % 128
	hi = n.shr_zf_wrap(61)
	lo = n.shl_wrap(3)
	append_be64(append_be64(bytes.append(0x80).concat(List.repeat(0, zeros)), hi), lo)
}

# The bytes with the 8 big-endian bytes of the word at the end.
append_be64 : List(U8), U64 -> List(U8)
append_be64 = |bytes, w| [56.U8, 48, 40, 32, 24, 16, 8, 0].fold(bytes, |acc, s| acc.append(w.shr_zf_wrap(s).to_u8_wrap()))

# The big-endian word at index i of the bytes.
be64 : List(U8), U64 -> U64
be64 = |bytes, i| {
	var $w = 0.U64
	for j in U64.until(i, i + 8) {
		$w = $w.shl_wrap(8).bitwise_or((bytes.get(j) ?? 0).to_u64())
	}
	$w
}

# Rotate right by n bits.
rotr : U64, U8 -> U64
rotr = |x, n| x.shr_zf_wrap(n).bitwise_or(x.shl_wrap(64 - n))

# One block (128 bytes at index off) into the state (FIPS 180-4 6.4.2).
compress : State, List(U8), U64 -> State
compress = |st, msg, off| {
	var $w = List.with_capacity(80)
	for t in U64.until(0, 16) {
		$w = $w.append(be64(msg, off + t * 8))
	}
	for t in U64.until(16, 80) {
		w2 = $w.get(t - 2) ?? 0
		w15 = $w.get(t - 15) ?? 0
		s0 = rotr(w15, 1).bitwise_xor(rotr(w15, 8)).bitwise_xor(w15.shr_zf_wrap(7))
		s1 = rotr(w2, 19).bitwise_xor(rotr(w2, 61)).bitwise_xor(w2.shr_zf_wrap(6))
		x = s1.plus_wrap($w.get(t - 7) ?? 0).plus_wrap(s0).plus_wrap($w.get(t - 16) ?? 0)
		$w = $w.append(x)
	}
	var $a = st.a
	var $b = st.b
	var $c = st.c
	var $d = st.d
	var $e = st.e
	var $f = st.f
	var $g = st.g
	var $h = st.h
	for t in U64.until(0, 80) {
		e = $e
		a = $a
		s1 = rotr(e, 14).bitwise_xor(rotr(e, 18)).bitwise_xor(rotr(e, 41))
		ch = e.bitwise_and($f).bitwise_xor(e.bitwise_not().bitwise_and($g))
		t1 = $h.plus_wrap(s1).plus_wrap(ch).plus_wrap(k.get(t) ?? 0).plus_wrap($w.get(t) ?? 0)
		s0 = rotr(a, 28).bitwise_xor(rotr(a, 34)).bitwise_xor(rotr(a, 39))
		maj = a.bitwise_and($b).bitwise_xor(a.bitwise_and($c)).bitwise_xor($b.bitwise_and($c))
		t2 = s0.plus_wrap(maj)
		$h = $g
		$g = $f
		$f = e
		$e = $d.plus_wrap(t1)
		$d = $c
		$c = $b
		$b = a
		$a = t1.plus_wrap(t2)
	}
	{
		a: st.a.plus_wrap($a),
		b: st.b.plus_wrap($b),
		c: st.c.plus_wrap($c),
		d: st.d.plus_wrap($d),
		e: st.e.plus_wrap($e),
		f: st.f.plus_wrap($f),
		g: st.g.plus_wrap($g),
		h: st.h.plus_wrap($h),
	}
}
