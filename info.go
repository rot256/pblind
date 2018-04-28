package pblind

import (
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"math/big"
)

type Info struct {
	curve elliptic.Curve
	x     *big.Int
	y     *big.Int
}

func (info Info) String() string {
	return fmt.Sprintf("(%s %s)", info.x, info.y)
}

func (info1 Info) Equals(info2 Info) bool {
	cmp1 := subtle.ConstantTimeCompare(info1.x.Bytes(), info2.x.Bytes())
	cmp2 := subtle.ConstantTimeCompare(info1.y.Bytes(), info2.y.Bytes())
	return subtle.ConstantTimeEq(int32(cmp1), int32(cmp2)) == 1
}

func CompressInfo(curve elliptic.Curve, info []byte) (c Info, err error) {
	c.x, c.y, err = hashToPoint(curve, info)
	return c, err
}
