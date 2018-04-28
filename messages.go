package pblind

import (
	"math/big"
)

type Message1 struct {
	ax, ay *big.Int
	bx, by *big.Int
}

type Message2 struct {
	e *big.Int
}

type Message3 struct {
	r *big.Int
	c *big.Int
	s *big.Int
}
