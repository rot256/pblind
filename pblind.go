package pblind

import (
	"crypto/elliptic"
	"math/big"
)

type PublicKey struct {
	curve elliptic.Curve
	x, y  *big.Int
}

type SecretKey struct {
	curve  elliptic.Curve
	scalar *big.Int
}

type Signature struct {
	p *big.Int
	w *big.Int
	o *big.Int
	g *big.Int
}

func SecretKeyFromBytes(curve elliptic.Curve, val []byte) SecretKey {
	var sk SecretKey
	sk.scalar = big.NewInt(0)
	sk.scalar.SetBytes(val)
	sk.curve = curve
	return sk
}

func (sk SecretKey) Bytes() []byte {
	return sk.scalar.Bytes()
}

func (sk SecretKey) GetPublicKey() PublicKey {
	var pk PublicKey
	pk.x, pk.y = sk.curve.ScalarBaseMult(sk.Bytes())
	pk.curve = sk.curve
	return pk
}
