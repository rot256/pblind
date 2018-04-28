# Pblind

Pblind is a small library implementing the Masayuki Abe and Tatsuaki Okamoto
[scheme for partially blind signatures](https://www.iacr.org/archive/crypto2000/18800272/18800272.pdf)
based on Schnorr signatures.

## Partially blind signatures

## How do I serialize the messages?

All messages can be serialized using any marshalling which supports `*big.Int`.
