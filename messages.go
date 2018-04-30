package pblind

import (
	"math/big"
)

type Signature struct {
	P *big.Int
	W *big.Int
	O *big.Int
	G *big.Int
}

type Message1 struct {
	Ax, Ay *big.Int
	Bx, By *big.Int
}

type Message2 struct {
	E *big.Int
}

type Message3 struct {
	R *big.Int
	C *big.Int
	S *big.Int
}
