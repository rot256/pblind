package pblind

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	stateRequesterFresh       = iota
	stateRequesterMsg1Created = iota
)

type StateRequester struct {
	state   int
	info    Info           // shared info for exchange
	message []byte         // message to sign
	curve   elliptic.Curve // domain
	Yx, Yy  *big.Int       // public key
	t1      *big.Int       // scalar
	t2      *big.Int       // scalar
	t3      *big.Int       // scalar
	t4      *big.Int       // scalar
	e       *big.Int       // scalar
}

func CreateRequester(
	curve elliptic.Curve,
	key *PublicKey,
	info Info,
	message []byte,
) (*StateRequester, error) {

	st := StateRequester{
		state:   stateRequesterFresh,
		info:    info,
		curve:   curve,
		message: message,
	}

	order := curve.Params().N

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

func (st *StateRequester) ProcessMessage1(msg MessageSignerRequester1) error {

	if !st.curve.IsOnCurve(msg.ax, msg.ay) {
		return ErrorPointNotOnCurve
	}

	if !st.curve.IsOnCurve(msg.bx, msg.by) {
		return ErrorPointNotOnCurve
	}

	st.e = func() *big.Int {

		// alpha = a + t1 * g + t2 * y

		alphax, alphay := func() (*big.Int, *big.Int) {
			t1x, t1y := st.curve.ScalarBaseMult(st.t1.Bytes())
			t2x, t2y := st.curve.ScalarMult(st.Yx, st.Yy, st.t2.Bytes())
			alx, aly := st.curve.Add(msg.ax, msg.ay, t1x, t1y)
			return st.curve.Add(alx, aly, t2x, t2y)
		}()

		// beta = b + t3 * g + t4 * z

		betax := msg.bx
		betay := msg.by

		func() {
			t3x, t3y := st.curve.ScalarBaseMult(st.t3.Bytes())
			t4x, t4y := st.curve.ScalarMult(st.info.x, st.info.y, st.t2.Bytes())
			betax, betay = st.curve.Add(betax, betay, t3x, t3y)
			betax, betay = st.curve.Add(betax, betay, t4x, t4y)
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
	st.e.Mod(st.e, st.curve.Params().P)

	return nil
}

func (st *StateRequester) CreateMessage2() MessageRequesterSigner2 {
	return MessageRequesterSigner2{e: st.e}
}

func (st *StateRequester) ProcessMessage3(msg MessageSignerRequester3) Signature {

	params := st.curve.Params()

	// infer d

	d := big.NewInt(0)
	d.Sub(st.e, msg.c)
	d.Mod(d, params.N)

	// calculate signature

	p := big.NewInt(0)
	p.Add(msg.r, st.t1)
	p.Mod(p, params.N)

	w := big.NewInt(0)
	w.Add(msg.c, st.t2)
	w.Mod(w, params.N)

	o := big.NewInt(0)
	o.Add(msg.s, st.t3)
	o.Mod(o, params.N)

	g := big.NewInt(0)
	g.Add(d, st.t4)
	g.Mod(g, params.N)

	return Signature{
		p: p, w: w,
		o: o, g: g,
	}
}
