package pblind

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type PublicKey struct {
	x, y *big.Int
}

type PrivateKey []byte

type Signature struct {
	p *big.Int
	w *big.Int
	o *big.Int
	g *big.Int
}

func main() {
	fmt.Println(elliptic.P256())
	fmt.Println("vim-go")
}
