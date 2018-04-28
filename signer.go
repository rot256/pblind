package pblind

// https://link.springer.com/content/pdf/10.1007/3-540-44598-6_17.pdf

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	stateSignerFresh = iota
	stateSignerMsg1Created
	stateSignerMsg2Processed
	stateSignerMsg3Created
)

type StateSigner struct {
	state int
	info  Info           // shared info for exchange
	curve elliptic.Curve // domain
	sk    SecretKey      // secret key
	u     *big.Int       // scalar
	s     *big.Int       // scalar
	d     *big.Int       // scalar
	e     *big.Int       // scalar
}

func CreateSigner(sk SecretKey, info Info) (*StateSigner, error) {

	st := StateSigner{
		state: stateSignerFresh,
		sk:    sk,
		curve: sk.curve,
		info:  info,
	}

	order := st.curve.Params().N

	var err error

	if st.u, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.s, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.d, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	return &st, nil
}

func (st *StateSigner) CreateMessage1() (Message1, error) {

	var msg Message1

	if st.state != stateSignerFresh {
		return msg, ErrorInvalidSignerState
	}

	/* a = u * g
	 * b = s * g + d * z
	 */

	t1x, t1y := st.curve.ScalarMult(st.info.x, st.info.y, st.d.Bytes())
	t2x, t2y := st.curve.ScalarBaseMult(st.s.Bytes())

	msg.Ax, msg.Ay = st.curve.ScalarBaseMult(st.u.Bytes())
	msg.Bx, msg.By = st.curve.Add(t1x, t1y, t2x, t2y)

	st.state = stateSignerMsg1Created

	return msg, nil
}

func (st *StateSigner) ProcessMessage2(msg Message2) error {
	if st.state != stateSignerMsg1Created {
		return ErrorInvalidSignerState
	}

	st.e = msg.E
	st.state = stateSignerMsg2Processed
	return nil
}

func (st *StateSigner) CreateMessage3() (Message3, error) {

	if st.state != stateSignerMsg2Processed {
		return Message3{}, ErrorInvalidSignerState
	}

	params := st.curve.Params()

	c := big.NewInt(0)
	c.Sub(st.e, st.d)
	c.Mod(c, params.N)

	r := big.NewInt(0)
	r.Mul(c, st.sk.scalar)
	r.Sub(st.u, r)
	r.Mod(r, params.N)

	st.state = stateSignerMsg3Created

	return Message3{R: r, C: c, S: st.s}, nil
}
