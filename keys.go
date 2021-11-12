package pblind

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	curve elliptic.Curve
	X, Y  *big.Int
}

type SecretKey struct {
	curve  elliptic.Curve
	Scalar *big.Int
}

func (pk PublicKey) String() string {
	return fmt.Sprintf("%s-pk: (x = %s, y = %s)", pk.curve.Params().Name, pk.X, pk.Y)
}

func (sk SecretKey) String() string {
	return fmt.Sprintf("%s-sk: (s = %s)", sk.curve.Params().Name, sk.Scalar)
}

func NewSecretKey(curve elliptic.Curve) (SecretKey, error) {
	var err error
	var sk SecretKey
	sk.curve = curve
	sk.Scalar, err = rand.Int(rand.Reader, curve.Params().N)
	return sk, err
}

func SecretKeyFromBytes(curve elliptic.Curve, val []byte) SecretKey {
	var sk SecretKey
	sk.Scalar = big.NewInt(0)
	sk.Scalar.SetBytes(val)
	sk.curve = curve
	return sk
}

func (sk SecretKey) Bytes() []byte {
	return sk.Scalar.Bytes()
}

func (sk SecretKey) GetPublicKey() PublicKey {
	var pk PublicKey
	pk.X, pk.Y = sk.curve.ScalarBaseMult(sk.Bytes())
	pk.curve = sk.curve
	return pk
}
