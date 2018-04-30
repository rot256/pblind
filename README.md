# Pblind

Pblind is a small library implementing the Masayuki Abe and Tatsuaki Okamoto [scheme for partially blind signatures](https://www.iacr.org/archive/crypto2000/18800272/18800272.pdf) based on Schnorr signatures. As the underlying group pblind allows the use of all the (NIST) curves from the `crypto/elliptic`` package.

**Note:** pblind is not stable, message and signature formats subject to change.

## Partially blind signatures

Partially blind signatures allows a signer and a requester to construct a blind signature on a document
with additional common information ("info") visible to both signer and requester.
This allows the signer some level of control over the contents of the document being signed,
while also providing a level of privacy / untraceability for the requester, at the two extremes:

- If the entire document is used as "info", you get an ordinary signature scheme.
- If "info" is a constant, the scheme becomes a traditional blind-signature scheme.

The interesting applications lie somewhere between the two. One such example might be a shop system allowing the buyers to sign anonymous reviews of the products they have purchased:

Using traditional blind signatures it is not possible for the service to know what product the
buyer is reviewing and therefore not possible to check if they have purchased the item at all.
This problem of "controlling the domain" of the blind signatures is usually solved by having district keys for the different message types, but clearly becomes infeasible when the number of types becomes large.
However using partially blind signatures an item identifier can be used as common info
and reviews of any item in the shop can be verified using the same key.

## Example usage

Below a simplied example of how to use pblind (without the required error handling).
All messages in pblind can be serialized using any marshaling which supports `*big.Int`.
Here an example using asn1:

```golang
func main() {

	// generate a key-pair

	curve := elliptic.P256()

	sk, _ := pblind.NewSecretKey(curve)
	pk := sk.GetPublicKey()

	msgStr := []byte("blinded message")
	infoStr := []byte("plaintext info")

	// create signer/requester with shared public info

	info, _ := pblind.CompressInfo(curve, infoStr)
	requester, _ := pblind.CreateRequester(pk, info, msgStr)
	signer, _ := pblind.CreateSigner(sk, info)

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

	// check signature

	fmt.Println("ok:", pk.Check(signature, info, msgStr))
}
```

Of course json, xml, bson, gob or another format could also be used.
