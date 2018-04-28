package pblind

import (
	"math/big"
)

type Signature struct {
	p *big.Int
	w *big.Int
	o *big.Int
	g *big.Int
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
