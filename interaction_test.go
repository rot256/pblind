package pblind

import (
	"crypto/elliptic"
	"testing"
)

func TestInteraction(t *testing.T) {

	messages := [][]byte{
		[]byte{},
		[]byte("sign me"),
		[]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
	}

	information := [][]byte{
		[]byte{},
		[]byte("context for signature"),
		[]byte{0xff, 0xfe, 0xfd, 0xfc},
	}

	curves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {

		for _, message := range messages {

			for _, infoStr := range information {

				// generate new key-pair

				sk, err := NewSecretKey(curve)
				if err != nil {
					t.Error("failed to generate secret key:", sk)
				}
				pk := sk.GetPublicKey()

				t.Log("testing interaction with:", sk, pk, message, infoStr)

				// compute shared point based on public info

				info, err := CompressInfo(curve, infoStr)
				if err != nil {
					t.Error("failed to compress info:", err)
				}

				// complete interaction / signature derivation

				requester, err := CreateRequester(pk, info, message)
				if err != nil {
					t.Error("failed to create requester:", err)
				}

				signer, err := CreateSigner(sk, info)
				if err != nil {
					t.Error("failed to create signer:", err)
				}

				msg1, err := signer.CreateMessage1()
				if err != nil {
					t.Error("failed to create msg1:", err)
				}

				err = requester.ProcessMessage1(msg1)
				if err != nil {
					t.Error("failed to process msg1:", err)
				}

				msg2, err := requester.CreateMessage2()
				if err != nil {
					t.Error("failed to create msg2:", err)
				}

				err = signer.ProcessMessage2(msg2)
				if err != nil {
					t.Error("failed to process msg2:", err)
				}

				msg3, err := signer.CreateMessage3()
				if err != nil {
					t.Error("failed to create msg3:", err)
				}

				err = requester.ProcessMessage3(msg3)
				if err != nil {
					t.Error("failed to process msg3:", err)
				}

				// check final signature

				sig, err := requester.Signature()
				if err != nil {
					t.Error("failed to obtain signature:", err)
				}

				if !pk.Check(sig, info, message) {
					t.Error("failed to validate signature")
				}
			}
		}
	}
}

func BenchmarkInteraction(b *testing.B) {

	infoStr := []byte("info")
	message := []byte("message")
	curve := elliptic.P256()

	// generate key-pair

	sk, err := NewSecretKey(curve)
	if err != nil {
		b.Error("failed to generate secret key:", sk)
	}
	pk := sk.GetPublicKey()

	// compute shared point based on public info

	info, err := CompressInfo(curve, infoStr)
	if err != nil {
		b.Error("failed to compress info:", err)
	}

	for i := 0; i < b.N; i++ {

		// complete interaction / signature derivation

		requester, err := CreateRequester(pk, info, message)
		if err != nil {
			b.Error("failed to create requester:", err)
		}

		signer, err := CreateSigner(sk, info)
		if err != nil {
			b.Error("failed to create signer:", err)
		}

		msg1, err := signer.CreateMessage1()
		if err != nil {
			b.Error("failed to create msg1:", err)
		}

		err = requester.ProcessMessage1(msg1)
		if err != nil {
			b.Error("failed to process msg1:", err)
		}

		msg2, err := requester.CreateMessage2()
		if err != nil {
			b.Error("failed to create msg2:", err)
		}

		err = signer.ProcessMessage2(msg2)
		if err != nil {
			b.Error("failed to process msg2:", err)
		}

		msg3, err := signer.CreateMessage3()
		if err != nil {
			b.Error("failed to create msg3:", err)
		}

		err = requester.ProcessMessage3(msg3)
		if err != nil {
			b.Error("failed to process msg3:", err)
		}
	}
}
