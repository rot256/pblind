package pblind

import (
	"math/big"
)

type MessageSignerRequester1 struct {
	ax, ay *big.Int
	bx, by *big.Int
}

type MessageRequesterSigner2 struct {
	e *big.Int
}

type MessageSignerRequester3 struct {
	r *big.Int
	c *big.Int
	s *big.Int
}
