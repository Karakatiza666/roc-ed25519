## Ed25519 signature verification of RFC 8032 (PureEdDSA, no context, no prehash), in pure Roc.
##
## The checks are those of Go `crypto/ed25519` (`Verify`, Go 1.17 and later):
##
## - The public key has 32 bytes and the signature has 64 bytes. Else `Bool.False`.
## - The public key decodes to a curve point. Else `Bool.False`.
## - S (the last 32 bytes of the signature, little-endian) is below the group order L. Else `Bool.False`.
## - R (the first 32 bytes) is not decoded: the encoding of [S]B - [k]A must be equal to R, byte for byte, where k is
##   SHA-512(R || A || message) mod L. So an R that is not a canonical point encoding is never accepted.
## - The check is cofactorless, and a small-order public key or R is not rejected (as in Go).
Ed25519 :: [].{

	## `Bool.True` when the bytes are a public key that `verify` can use: 32 bytes that decode to a point of the curve, by the decode
	## of `verify` (the rules of Go `crypto/ed25519`: y of p or more is taken mod p, a small-order point is accepted, x = 0 with the
	## sign bit set is accepted, a y with no x is rejected). Any other length gives `Bool.False`.
	is_valid_public_key : List(U8) -> Bool
	is_valid_public_key = |bytes| bytes.len() == 32 and decode_point(bytes).is_ok()

	## `Bool.True` when `signature` is a valid Ed25519 signature of `message` by `public_key`, by the checks above.
	verify : { public_key : List(U8), message : List(U8), signature : List(U8) } -> Bool
	verify = |args| {
		pk = args.public_key
		sig = args.signature
		if pk.len() != 32 or sig.len() != 64 {
			return Bool.False
		}
		s = sc_from_bytes(sig, 32)
		if !sc_below_l(s) {
			return Bool.False
		}
		match decode_point(pk) {
			Err(_) => Bool.False
			Ok(a) => {
				r = sig.take_first(32)
				k = sc_reduce_512(Sha512.hash(r.concat(pk).concat(args.message)))
				encode_point(double_scalar_mul(s, k, point_neg(a))) == r
			}
		}
	}
}

import Sha512

# --- Field arithmetic mod p = 2^255 - 19 ---
# A field element is 5 limbs of 51 bits: l0 + l1 2^51 + l2 2^102 + l3 2^153 + l4 2^204.
# After each operation, each limb is below about 2^52, and the value is not always fully reduced.

Fe : { l0 : U64, l1 : U64, l2 : U64, l3 : U64, l4 : U64 }

mask51 : U64
mask51 = 0x7FFFFFFFFFFFF

mask51_128 : U128
mask51_128 = 0x7FFFFFFFFFFFF

fe_zero : Fe
fe_zero = { l0: 0, l1: 0, l2: 0, l3: 0, l4: 0 }

fe_one : Fe
fe_one = { l0: 1, l1: 0, l2: 0, l3: 0, l4: 0 }

# d = -121665 / 121666.
fe_d : Fe
fe_d = { l0: 0x34DCA135978A3, l1: 0x1A8283B156EBD, l2: 0x5E7A26001C029, l3: 0x739C663A03CBB, l4: 0x52036CEE2B6FF }

# 2 d.
fe_d2 : Fe
fe_d2 = { l0: 0x69B9426B2F159, l1: 0x35050762ADD7A, l2: 0x3CF44C0038052, l3: 0x6738CC7407977, l4: 0x2406D9DC56DFF }

# A square root of -1: 2^((p - 1) / 4).
fe_sqrtm1 : Fe
fe_sqrtm1 = { l0: 0x61B274A0EA0B0, l1: 0xD5A5FC8F189D, l2: 0x7EF5E9CBD0C60, l3: 0x78595A6804C9E, l4: 0x2B8324804FC1D }

# Move the high bits of each limb into the next limb. The top carry goes to l0 times 19, because 2^255 = 19 mod p.
fe_carry : Fe -> Fe
fe_carry = |a| {
	l1 = a.l1 + a.l0.shr_zf_wrap(51)
	l2 = a.l2 + l1.shr_zf_wrap(51)
	l3 = a.l3 + l2.shr_zf_wrap(51)
	l4 = a.l4 + l3.shr_zf_wrap(51)
	l0 = a.l0.bitwise_and(mask51) + l4.shr_zf_wrap(51) * 19
	{ l0, l1: l1.bitwise_and(mask51), l2: l2.bitwise_and(mask51), l3: l3.bitwise_and(mask51), l4: l4.bitwise_and(mask51) }
}

fe_add : Fe, Fe -> Fe
fe_add = |a, b| fe_carry({ l0: a.l0 + b.l0, l1: a.l1 + b.l1, l2: a.l2 + b.l2, l3: a.l3 + b.l3, l4: a.l4 + b.l4 })

# a - b, as a + 4p - b, so that no limb goes below zero.
fe_sub : Fe, Fe -> Fe
fe_sub = |a, b| fe_carry({
	l0: a.l0 + 0x1FFFFFFFFFFFB4 - b.l0,
	l1: a.l1 + 0x1FFFFFFFFFFFFC - b.l1,
	l2: a.l2 + 0x1FFFFFFFFFFFFC - b.l2,
	l3: a.l3 + 0x1FFFFFFFFFFFFC - b.l3,
	l4: a.l4 + 0x1FFFFFFFFFFFFC - b.l4,
})

fe_neg : Fe -> Fe
fe_neg = |a| fe_sub(fe_zero, a)

fe_mul : Fe, Fe -> Fe
fe_mul = |a, b| {
	a0 = a.l0.to_u128()
	a1 = a.l1.to_u128()
	a2 = a.l2.to_u128()
	a3 = a.l3.to_u128()
	a4 = a.l4.to_u128()
	b0 = b.l0.to_u128()
	b1 = b.l1.to_u128()
	b2 = b.l2.to_u128()
	b3 = b.l3.to_u128()
	b4 = b.l4.to_u128()
	b1_19 = b1 * 19
	b2_19 = b2 * 19
	b3_19 = b3 * 19
	b4_19 = b4 * 19
	r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19
	r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19
	r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19
	r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19
	r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
	c1 = r1 + r0.shr_zf_wrap(51)
	c2 = r2 + c1.shr_zf_wrap(51)
	c3 = r3 + c2.shr_zf_wrap(51)
	c4 = r4 + c3.shr_zf_wrap(51)
	c0 = r0.bitwise_and(mask51_128) + c4.shr_zf_wrap(51) * 19
	d1 = c1.bitwise_and(mask51_128) + c0.shr_zf_wrap(51)
	{
		l0: c0.bitwise_and(mask51_128).to_u64_wrap(),
		l1: d1.to_u64_wrap(),
		l2: c2.bitwise_and(mask51_128).to_u64_wrap(),
		l3: c3.bitwise_and(mask51_128).to_u64_wrap(),
		l4: c4.bitwise_and(mask51_128).to_u64_wrap(),
	}
}

fe_sq : Fe -> Fe
fe_sq = |a| fe_mul(a, a)

# a^(2^n): n squarings.
fe_sq_n : Fe, U64 -> Fe
fe_sq_n = |a, n| {
	var $x = a
	for _i in U64.until(0, n) {
		$x = fe_sq($x)
	}
	$x
}

# a^(2^250 - 1), and a^11 for the callers (the chain of ref10).
fe_pow_2_250_1 : Fe -> { t250 : Fe, t11 : Fe }
fe_pow_2_250_1 = |z| {
	t2 = fe_sq(z)
	t9 = fe_mul(fe_sq_n(t2, 2), z)
	t11 = fe_mul(t9, t2)
	t5 = fe_mul(fe_sq(t11), t9)
	t10 = fe_mul(fe_sq_n(t5, 5), t5)
	t20 = fe_mul(fe_sq_n(t10, 10), t10)
	t40 = fe_mul(fe_sq_n(t20, 20), t20)
	t50 = fe_mul(fe_sq_n(t40, 10), t10)
	t100 = fe_mul(fe_sq_n(t50, 50), t50)
	t200 = fe_mul(fe_sq_n(t100, 100), t100)
	t250 = fe_mul(fe_sq_n(t200, 50), t50)
	{ t250, t11 }
}

# 1 / z, as z^(p - 2) = z^(2^255 - 21).
fe_invert : Fe -> Fe
fe_invert = |z| {
	t = fe_pow_2_250_1(z)
	fe_mul(fe_sq_n(t.t250, 5), t.t11)
}

# z^((p - 5) / 8) = z^(2^252 - 3).
fe_pow_p58 : Fe -> Fe
fe_pow_p58 = |z| fe_mul(fe_sq_n(fe_pow_2_250_1(z).t250, 2), z)

# The little-endian word at index i of the bytes.
le64 : List(U8), U64 -> U64
le64 = |bytes, i| {
	var $w = 0.U64
	for j in U64.until(0, 8) {
		$w = $w.bitwise_or((bytes.get(i + j) ?? 0).to_u64().shl_wrap((j * 8).to_u8_wrap()))
	}
	$w
}

# The field element of 32 little-endian bytes. The top bit is not used. A value of p or more is accepted (as in Go).
fe_from_bytes : List(U8) -> Fe
fe_from_bytes = |bytes| {
	w0 = le64(bytes, 0)
	w1 = le64(bytes, 8)
	w2 = le64(bytes, 16)
	w3 = le64(bytes, 24)
	{
		l0: w0.bitwise_and(mask51),
		l1: w0.shr_zf_wrap(51).bitwise_or(w1.shl_wrap(13)).bitwise_and(mask51),
		l2: w1.shr_zf_wrap(38).bitwise_or(w2.shl_wrap(26)).bitwise_and(mask51),
		l3: w2.shr_zf_wrap(25).bitwise_or(w3.shl_wrap(39)).bitwise_and(mask51),
		l4: w3.shr_zf_wrap(12).bitwise_and(mask51),
	}
}

# The 32 little-endian bytes of the fully reduced value (below p).
fe_to_bytes : Fe -> List(U8)
fe_to_bytes = |a| {
	h = fe_carry(a)
	# q is 1 when h >= p, else 0 (h is below 2p here).
	q0 = (h.l0 + 19).shr_zf_wrap(51)
	q1 = (h.l1 + q0).shr_zf_wrap(51)
	q2 = (h.l2 + q1).shr_zf_wrap(51)
	q3 = (h.l3 + q2).shr_zf_wrap(51)
	q = (h.l4 + q3).shr_zf_wrap(51)
	# h - q p = h + 19 q - q 2^255: add 19 q, carry, and drop bit 255.
	c0 = h.l0 + 19 * q
	c1 = h.l1 + c0.shr_zf_wrap(51)
	c2 = h.l2 + c1.shr_zf_wrap(51)
	c3 = h.l3 + c2.shr_zf_wrap(51)
	c4 = h.l4 + c3.shr_zf_wrap(51)
	l0 = c0.bitwise_and(mask51)
	l1 = c1.bitwise_and(mask51)
	l2 = c2.bitwise_and(mask51)
	l3 = c3.bitwise_and(mask51)
	l4 = c4.bitwise_and(mask51)
	words = [
		l0.bitwise_or(l1.shl_wrap(51)),
		l1.shr_zf_wrap(13).bitwise_or(l2.shl_wrap(38)),
		l2.shr_zf_wrap(26).bitwise_or(l3.shl_wrap(25)),
		l3.shr_zf_wrap(39).bitwise_or(l4.shl_wrap(12)),
	]
	words.fold(
		List.with_capacity(32),
		|acc, w| U64.until(0, 8).fold(acc, |acc2, j| acc2.append(w.shr_zf_wrap((j * 8).to_u8_wrap()).to_u8_wrap())),
	)
}

fe_eq : Fe, Fe -> Bool
fe_eq = |a, b| fe_to_bytes(a) == fe_to_bytes(b)

# True when the reduced value is odd (the "negative" x of RFC 8032).
fe_is_odd : Fe -> Bool
fe_is_odd = |a| (fe_to_bytes(a).first() ?? 0).bitwise_and(1) == 1

# --- Points: extended twisted Edwards coordinates (X : Y : Z : T), x = X / Z, y = Y / Z, x y = T / Z ---

Point : { x : Fe, y : Fe, z : Fe, t : Fe }

point_identity : Point
point_identity = { x: fe_zero, y: fe_one, z: fe_one, t: fe_zero }

# The base point B of RFC 8032 (y = 4/5, x even).
point_base : Point
point_base = {
	x: { l0: 0x62D608F25D51A, l1: 0x412A4B4F6592A, l2: 0x75B7171A4B31D, l3: 0x1FF60527118FE, l4: 0x216936D3CD6E5 },
	y: { l0: 0x6666666666658, l1: 0x4CCCCCCCCCCCC, l2: 0x1999999999999, l3: 0x3333333333333, l4: 0x6666666666666 },
	z: fe_one,
	t: { l0: 0x68AB3A5B7DDA3, l1: 0xEEA2A5EADBB, l2: 0x2AF8DF483C27E, l3: 0x332B375274732, l4: 0x67875F0FD78B7 },
}

point_neg : Point -> Point
point_neg = |p| { x: fe_neg(p.x), y: p.y, z: p.z, t: fe_neg(p.t) }

# P + Q (add-2008-hwcd-3, a = -1). The formula is complete: it also works for P = Q and for the identity.
point_add : Point, Point -> Point
point_add = |p, q| {
	a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x))
	b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x))
	c = fe_mul(fe_mul(p.t, fe_d2), q.t)
	zz = fe_mul(p.z, q.z)
	d = fe_add(zz, zz)
	e = fe_sub(b, a)
	f = fe_sub(d, c)
	g = fe_add(d, c)
	h = fe_add(b, a)
	{ x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) }
}

# 2 P (dbl-2008-hwcd, a = -1).
point_double : Point -> Point
point_double = |p| {
	a = fe_sq(p.x)
	b = fe_sq(p.y)
	zz = fe_sq(p.z)
	c = fe_add(zz, zz)
	h = fe_add(a, b)
	e = fe_sub(h, fe_sq(fe_add(p.x, p.y)))
	g = fe_sub(a, b)
	f = fe_add(c, g)
	{ x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) }
}

# The point of a 32-byte encoding (RFC 8032 5.1.3, with the rules of Go filippo.io/edwards25519 SetBytes):
# y of p or more is accepted, and x = 0 with the sign bit set is accepted (x stays 0).
decode_point : List(U8) -> Try(Point, [NotAPoint])
decode_point = |bytes| {
	y = fe_from_bytes(bytes)
	sign = (bytes.get(31) ?? 0).shr_zf_wrap(7) == 1
	yy = fe_sq(y)
	u = fe_sub(yy, fe_one)
	v = fe_add(fe_mul(yy, fe_d), fe_one)
	v3 = fe_mul(fe_sq(v), v)
	v7 = fe_mul(fe_sq(v3), v)
	# x = u v^3 (u v^7)^((p - 5) / 8) is a root of u / v when v x^2 = u, or of -u / v when v x^2 = -u.
	x0 = fe_mul(fe_mul(u, v3), fe_pow_p58(fe_mul(u, v7)))
	vxx = fe_mul(v, fe_sq(x0))
	root =
		if fe_eq(vxx, u) {
			Ok(x0)
		} else if fe_eq(vxx, fe_neg(u)) {
			Ok(fe_mul(x0, fe_sqrtm1))
		} else {
			Err(NotAPoint)
		}
	match root {
		Err(e) => Err(e)
		Ok(x1) => {
			x = if (fe_is_odd(x1) != sign) fe_neg(x1) else x1
			Ok({ x, y, z: fe_one, t: fe_mul(x, y) })
		}
	}
}

# The 32-byte encoding of a point: y, with the low bit of x in the top bit.
encode_point : Point -> List(U8)
encode_point = |p| {
	zi = fe_invert(p.z)
	x = fe_mul(p.x, zi)
	y = fe_mul(p.y, zi)
	bytes = fe_to_bytes(y)
	if fe_is_odd(x) {
		bytes.update(31, |b| b.bitwise_or(0x80)) ?? bytes
	} else {
		bytes
	}
}

# --- Scalars: numbers below 2^256, as two 128-bit halves ---

Sc : { lo : U128, hi : U128 }

# The group order L = 2^252 + 27742317777372353535851937790883648493.
l_lo : U128
l_lo = 0x14DEF9DEA2F79CD65812631A5CF5D3ED

l_hi : U128
l_hi = 0x10000000000000000000000000000000

# The little-endian 128-bit number at index i of the bytes.
le128 : List(U8), U64 -> U128
le128 = |bytes, i| le64(bytes, i).to_u128().bitwise_or(le64(bytes, i + 8).to_u128().shl_wrap(64))

# The scalar of 32 little-endian bytes at index i.
sc_from_bytes : List(U8), U64 -> Sc
sc_from_bytes = |bytes, i| { lo: le128(bytes, i), hi: le128(bytes, i + 16) }

sc_below_l : Sc -> Bool
sc_below_l = |s| s.hi < l_hi or (s.hi == l_hi and s.lo < l_lo)

# The 64 little-endian bytes as a number, mod L. One bit at a time: r = 2 r + bit, minus L when r >= L.
sc_reduce_512 : List(U8) -> Sc
sc_reduce_512 = |bytes| {
	var $r = { lo: 0.U128, hi: 0.U128 }
	for j in U64.until(0, 512) {
		i = 511 - j
		bit = (bytes.get(i // 8) ?? 0).shr_zf_wrap((i % 8).to_u8_wrap()).bitwise_and(1).to_u128()
		r2 = { lo: $r.lo.shl_wrap(1).bitwise_or(bit), hi: $r.hi.shl_wrap(1).bitwise_or($r.lo.shr_zf_wrap(127)) }
		$r =
			if sc_below_l(r2) {
				r2
			} else {
				borrow = if (r2.lo < l_lo) 1.U128 else 0
				{ lo: r2.lo.minus_wrap(l_lo), hi: r2.hi - l_hi - borrow }
			}
	}
	$r
}

# Bit i (0 to 255) of the scalar.
sc_bit : Sc, U64 -> Bool
sc_bit = |s, i| {
	w = if (i < 128) s.lo else s.hi
	w.shr_zf_wrap((i % 128).to_u8_wrap()).bitwise_and(1) == 1
}

# [s]B + [k]P, both scalars below 2^253, with one shared chain of doublings (Straus).
# The time depends on the scalars; that is fine for verification, where no value is secret.
double_scalar_mul : Sc, Sc, Point -> Point
double_scalar_mul = |s, k, p| {
	bp = point_add(point_base, p)
	var $acc = point_identity
	for j in U64.until(0, 253) {
		i = 252 - j
		d = point_double($acc)
		sb = sc_bit(s, i)
		kb = sc_bit(k, i)
		$acc =
			if sb and kb {
				point_add(d, bp)
			} else if sb {
				point_add(d, point_base)
			} else if kb {
				point_add(d, p)
			} else {
				d
			}
	}
	$acc
}
