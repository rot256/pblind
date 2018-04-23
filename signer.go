package pblind

// https://link.springer.com/content/pdf/10.1007/3-540-44598-6_17.pdf

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	stateSignerFresh       = iota
	stateSignerMsg1Created = iota
)

type StateSigner struct {
	state int
	info  Info           // shared info for exchange
	curve elliptic.Curve // domain
	x     *big.Int       // private key (scalar)
	u     *big.Int       // scalar
	s     *big.Int       // scalar
	d     *big.Int       // scalar
	e     *big.Int       // scalar
}

func CreateSigner(
	curve elliptic.Curve,
	sk PrivateKey,
	info Info,
) (*StateSigner, error) {

	order := curve.Params().N
	state := StateSigner{
		state: stateSignerFresh,
		curve: curve,
	}

	var err error

	if state.u, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if state.s, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if state.d, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	return &state, nil
}

func (st *StateSigner) CreateMessage1() MessageSignerRequester1 {

	/* a = u * g
	 * b = s * g + d * z
	 */

	var msg MessageSignerRequester1

	t1x, t1y := st.curve.ScalarMult(st.info.x, st.info.y, st.d.Bytes())
	t2x, t2y := st.curve.ScalarBaseMult(st.s.Bytes())

	msg.ax, msg.ay = st.curve.ScalarBaseMult(st.u.Bytes())
	msg.bx, msg.by = st.curve.Add(t1x, t1y, t2x, t2y)

	st.state = stateSignerMsg1Created

	return msg
}

func (st *StateSigner) ProcessMessage2(msg MessageRequesterSigner2) error {
	st.e = msg.e
	return nil
}

func (st *StateSigner) CreateMessage3() MessageSignerRequester3 {
	params := st.curve.Params()

	c := big.NewInt(0)
	c.Sub(st.e, st.d)
	c.Mod(c, params.N)

	r := big.NewInt(0)
	r.Mul(c, st.x)
	r.Sub(st.u, r)
	r.Mod(r, params.N)

	return MessageSignerRequester3{
		r: r,
		c: c,
		s: st.s,
	}
}
