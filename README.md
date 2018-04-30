# Pblind

Pblind is a small library implementing the Masayuki Abe and Tatsuaki Okamoto
[scheme for partially blind signatures](https://www.iacr.org/archive/crypto2000/18800272/18800272.pdf)
based on Schnorr signatures.
As the underlaying group pblind allows the use
of all the NIST curves from the `crypto/elliptic`` package.

## Partially blind signatures

## How do I serialize the messages?

All messages can be serialized using any marshalling which supports `*big.Int`.
Here an example using asn1 (without the required error handling):

```golang
func main() {
    curve := elliptic.P256()

    sk := pblind.SecretKeyFromBytes(curve, []byte{0x13, 0x37})
    pk := sk.GetPublicKey()

    info, err := pblind.CompressInfo(curve, []byte{0x1, 0x5})
    if err != nil {
        panic(err)
    }

    msg := []byte("sign me")

    requester, err := pblind.CreateRequester(pk, info, msg)
    if err != nil {
        panic(err)
    }

    signer, err := pblind.CreateSigner(sk, info)
    if err != nil {
        panic(err)
    }

    // signer

    msg1S, _ := signer.CreateMessage1()
    ser1S, _ := asn1.Marshal(msg1S)
    fmt.Println("signer -> requester :", len(ser1S), "bytes")

    // requester

    var msg1R pblind.Message1
    asn1.Unmarshal(ser1S, &msg1R)
    requester.ProcessMessage1(msg1R)
    msg2R, _ := requester.CreateMessage2()
    ser2R, _ := asn1.Marshal(msg2R)
    fmt.Println("requester -> signer :", len(ser2R), "bytes")

    // signer

    var msg2S pblind.Message2
    asn1.Unmarshal(ser2R, &msg2S)
    signer.ProcessMessage2(msg2S)
    msg3S, _ := signer.CreateMessage3()
    ser3S, _ := asn1.Marshal(msg3S)
    fmt.Println("signer -> requester :", len(ser3S), "bytes")

    // requester

    var msg3R pblind.Message3
    asn1.Unmarshal(ser3S, &msg3R)
    requester.ProcessMessage3(msg3R)
    signature, _ := requester.Signature()
    sig, _ := asn1.Marshal(signature)
    fmt.Println("encoded signature   :", len(sig), "bytes")
}
```

Of course json, xml, bson, gob or another format could also be used.
