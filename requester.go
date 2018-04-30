package pblind

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	stateRequesterFresh = iota
	stateRequesterMsg1Processed
	stateRequesterMsg2Created
	stateRequesterMsg3Processed
)

type StateRequester struct {
	state   int
	info    Info           // shared info for exchange
	message []byte         // message to sign
	curve   elliptic.Curve // domain
	pk      PublicKey
	t1      *big.Int  // scalar
	t2      *big.Int  // scalar
	t3      *big.Int  // scalar
	t4      *big.Int  // scalar
	e       *big.Int  // scalar
	sig     Signature // final signature
}

func CreateRequester(pk PublicKey, info Info, message []byte) (*StateRequester, error) {

	st := StateRequester{
		state:   stateRequesterFresh,
		info:    info,
		pk:      pk,
		curve:   pk.curve,
		message: message,
	}

	order := st.curve.Params().N

	var err error

	if st.t1, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.t2, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.t3, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	if st.t4, err = rand.Int(rand.Reader, order); err != nil {
		return nil, err
	}

	return &st, nil
}

func (st *StateRequester) ProcessMessage1(msg Message1) error {

	if st.state != stateRequesterFresh {
		return ErrorInvalidRequesterState
	}

	if !st.curve.IsOnCurve(msg.Ax, msg.Ay) {
		return ErrorPointNotOnCurve
	}

	if !st.curve.IsOnCurve(msg.Bx, msg.By) {
		return ErrorPointNotOnCurve
	}

	st.e = func() *big.Int {

		// alpha = a + t1 * g + t2 * y

		alphax, alphay := func() (*big.Int, *big.Int) {
			t1x, t1y := st.curve.ScalarBaseMult(st.t1.Bytes())
			t2x, t2y := st.curve.ScalarMult(st.pk.x, st.pk.y, st.t2.Bytes())
			alx, aly := st.curve.Add(msg.Ax, msg.Ay, t1x, t1y)
			return st.curve.Add(alx, aly, t2x, t2y)
		}()

		// beta = b + t3 * g + t4 * z

		betax, betay := func() (*big.Int, *big.Int) {
			t3x, t3y := st.curve.ScalarBaseMult(st.t3.Bytes())
			t4x, t4y := st.curve.ScalarMult(st.info.x, st.info.y, st.t4.Bytes())
			bex, bey := st.curve.Add(msg.Bx, msg.By, t3x, t3y)
			return st.curve.Add(bex, bey, t4x, t4y)
		}()

		// hash to scalar

		var buff []byte

		buff = elliptic.Marshal(st.curve, alphax, alphay)
		buff = append(buff, elliptic.Marshal(st.curve, betax, betay)...)
		buff = append(buff, elliptic.Marshal(st.curve, st.info.x, st.info.y)...)
		buff = append(buff, st.message...)

		return hashToScalar(st.curve, buff)
	}()

	st.e.Sub(st.e, st.t2)
	st.e.Sub(st.e, st.t4)
	st.e.Mod(st.e, st.curve.Params().N)

	st.state = stateRequesterMsg1Processed

	return nil
}

func (st *StateRequester) CreateMessage2() (Message2, error) {
	if st.state != stateRequesterMsg1Processed {
		return Message2{}, ErrorInvalidRequesterState
	}
	st.state = stateRequesterMsg2Created
	return Message2{E: st.e}, nil
}

func (st *StateRequester) ProcessMessage3(msg Message3) error {

	if st.state != stateRequesterMsg2Created {
		return ErrorInvalidRequesterState
	}

	params := st.curve.Params()

	// infer d

	d := big.NewInt(0)
	d.Sub(st.e, msg.C)
	d.Mod(d, params.N)

	// calculate signature

	p := big.NewInt(0)
	p.Add(msg.R, st.t1)
	p.Mod(p, params.N)

	w := big.NewInt(0)
	w.Add(msg.C, st.t2)
	w.Mod(w, params.N)

	o := big.NewInt(0)
	o.Add(msg.S, st.t3)
	o.Mod(o, params.N)

	g := big.NewInt(0)
	g.Add(d, st.t4)
	g.Mod(g, params.N)

	st.sig = Signature{
		P: p, W: w,
		O: o, G: g,
	}

	// validate signature

	if !st.pk.Check(st.sig, st.info, st.message) {
		return ErrorInvalidSignature
	}

	st.state = stateRequesterMsg3Processed

	return nil
}

func (st *StateRequester) Signature() (Signature, error) {

	if st.state != stateRequesterMsg3Processed {
		return Signature{}, ErrorInvalidRequesterState
	}

	return st.sig, nil
}
