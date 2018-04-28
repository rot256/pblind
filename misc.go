package pblind

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/hkdf"
	"math/big"
)

func hashToPoint(curve elliptic.Curve, value []byte) (*big.Int, *big.Int, error) {
	params := curve.Params()

	kdf := hkdf.New(
		sha512.New,
		value,
		[]byte(params.Name),
		[]byte("POINT-HASHING"),
	)

	// TODO: make constant time
	// e.g. use https://eprint.iacr.org/2009/226.pdf
	// not critical, since the function operates on public info

	y := big.NewInt(0)

	for {
		x, err := rand.Int(kdf, params.P)
		if err != nil {
			return nil, nil, err
		}

		// y^2 = x^3 - 3x + B

		y.Mul(x, x)
		y.Mod(y, params.P)
		y.Mul(y, x)
		y.Mod(y, params.P)

		y.Add(y, params.B)
		y.Sub(y, x)
		y.Sub(y, x)
		y.Sub(y, x)
		y.Mod(y, params.P)

		// check if square

		if y.ModSqrt(y, params.P) == nil {
			continue
		}

		// final sanity check

		if !curve.IsOnCurve(x, y) {
			panic(errors.New("point not on curve, implementation error"))
		}

		return x, y, nil
	}

}

func hashToScalar(curve elliptic.Curve, value []byte) *big.Int {
	par := curve.Params()
	kdf := hkdf.New(
		sha512.New,
		value,
		[]byte(par.Name),
		[]byte("SCALAR-HASHING"),
	)
	scalar, _ := rand.Int(kdf, par.N)
	return scalar
}
