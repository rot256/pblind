package pblind

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"math/big"
)

type Info struct {
	x *big.Int
	y *big.Int
}

func (info Info) String() string {
	return fmt.Sprintf("(%s %s)", info.x, info.y)
}

// TODO: find a more standized way to do this
func CompressInfo(curve elliptic.Curve, info []byte) (c Info, err error) {

	params := curve.Params()

	kdf := hkdf.New(
		sha512.New,
		info,
		[]byte(params.Name),
		[]byte("INFO-HASHING"),
	)

	// TODO: make constant time
	// e.g. use https://eprint.iacr.org/2009/226.pdf
	// not critical, since the function operates on public info

	for c.y = big.NewInt(0); ; {
		if c.x, err = rand.Int(kdf, params.N); err != nil {
			return
		}

		// x^3 + B

		c.y.Mul(c.x, c.x)
		c.y.Mod(c.y, params.P)
		c.y.Mul(c.y, c.x)
		c.y.Add(c.y, params.B)
		c.y.Mod(c.y, params.P)

		// check if square

		if c.y.ModSqrt(c.y, params.P) != nil {
			return
		}
	}
}

func hashToScalar(curve elliptic.Curve, value []byte) (scalar *big.Int) {
	par := curve.Params()
	kdf := hkdf.New(
		sha512.New,
		value,
		[]byte(par.Name),
		[]byte("SCALAR-HASHING"),
	)
	scalar, _ = rand.Int(kdf, par.N)
	return
}
