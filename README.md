## ElGamal Cryptosystem (Encryption & Signature Schemes)
This package is implemented according to the pseudo-code and mathematical notations of the following algorithms of the ElGamal cryptosystem:
 - Key Generation
 - Encryption Scheme
   - Encryption
   - Decryption
 - Signature Scheme
   - Signature Generation
   - Signature Verification

ElGamal has [multiplicative homomorphic encryption property](https://dl.acm.org/doi/pdf/10.1145/3214303) and is an example of Partially Homomorphic Encryption (PHE). Therefore, the multiplication of ciphers results in the product of original numbers.

Moreover, it also supports the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers


### Installation
```sh
go get -u github.com/Mirzazhar/elgamal
```
### Warning
This package is intendedly designed for education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
### Usage & Examples
### Acknowledge
I’m extremely grateful to [Drogunov Igor](https://github.com/ldinc) for her contribution in choosing large prime p along with a cyclic group generator Zp. Based on this, I was able to complete the implementation of the keys generation algorithm.
### LICENSE
MIT License
### References
1. https://en.wikipedia.org/wiki/ElGamal_encryption
2. https://en.wikipedia.org/wiki/ElGamal_signature_scheme
3. https://dl.acm.org/doi/pdf/10.1145/3214303
4. https://pkg.go.dev/golang.org/x/crypto/openpgp/elgamal
5. https://github.com/ldinc/pqg
