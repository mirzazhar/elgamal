package elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	mathrand "math/rand"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

var ErrMessageLarge = errors.New("elgamal: message is larger than public key size")
var ErrCipherLarge = errors.New("elgamal: cipher is larger than public key size")

// PublicKey represents a Elgamal public key.
type PublicKey struct {
	G, P, Y *big.Int
}

// PrivateKey represents Elgamal private key.
type PrivateKey struct {
	PublicKey
	X *big.Int
}

// GenerateKey generates elgamal private key according
// to given bit size and probability. Moreover, the given probability
// value is used in choosing prime number P for performing n Miller-Rabin
// tests with 1 - 1/(4^n) probability false rate.
func GenerateKey(bitsize, probability int) (*PrivateKey, error) {
	// p is prime number
	// q is prime group order
	// g is cyclic group generator Zp
	p, q, g, err := GeneratePQZp(bitsize, probability)
	if err != nil {
		return nil, err
	}

	randSource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	// choose random integer x from {1...(q-1)}
	priv := new(big.Int).Rand(randSource, new(big.Int).Sub(q, one))
	// y = g^p mod p
	y := new(big.Int).Exp(g, priv, p)

	return &PrivateKey{
		PublicKey: PublicKey{
			G: g, // cyclic group generator Zp
			P: p, // prime number
			Y: y, // y = g^p mod p
		},
		X: priv, // secret key x
	}, nil
}

func GeneratePQZp(bitsize, probability int) (p, q, g *big.Int, err error) {
	return Gen(bitsize, probability)
}

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if plain text value is larger than modulus P of Public key.
func (pub *PublicKey) Encrypt(message []byte) ([]byte, []byte, error) {
	// choose random integer k from {1...p}
	k, err := rand.Int(rand.Reader, pub.P)
	if err != nil {
		return nil, nil, err
	}

	m := new(big.Int).SetBytes(message)
	if m.Cmp(pub.P) == 1 { //  m < P
		return nil, nil, ErrMessageLarge
	}

	// c1 = g^k mod p
	c1 := new(big.Int).Exp(pub.G, k, pub.P)
	// s = y^k mod p
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	// c2 = m*s mod p
	c2 := new(big.Int).Mod(
		new(big.Int).Mul(m, s),
		pub.P,
	)
	return c1.Bytes(), c2.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns an
// error if cipher text value is larger than modulus P of Public key.
func (priv *PrivateKey) Decrypt(cipher1, cipher2 []byte) ([]byte, error) {
	c1 := new(big.Int).SetBytes(cipher1)
	c2 := new(big.Int).SetBytes(cipher2)
	if c1.Cmp(priv.P) == 1 && c2.Cmp(priv.P) == 1 { //  (c1, c2) < P
		return nil, ErrCipherLarge
	}

	// s = c^x mod p
	s := new(big.Int).Exp(c1, priv.X, priv.P)
	// s = s(inv) = s^(-1) mod p
	if s.ModInverse(s, priv.P) == nil {
		return nil, errors.New("elgamal: invalid private key")
	}

	// m = s(inv) * c2 mod p
	m := new(big.Int).Mod(
		new(big.Int).Mul(s, c2),
		priv.P,
	)
	return m.Bytes(), nil
}

// Note : this section of code is taken from (https://github.com/ldinc/pqg).
// Author of this code is "Drogunov Igor".
// Gen emit <p,q,g>.
// p = 2q + 1, p,q - safe primes
// g - cyclic group generator Zp
// performs n Miller-Rabin tests with 1 - 1/(4^n) probability false rate.
// Gain n - bit width for integer & probability rang for MR.
// It returns p, q, g and write error message.
func Gen(n, probability int) (*big.Int, *big.Int, *big.Int, error) {
	for {
		q, err := rand.Prime(rand.Reader, n-1)
		if err != nil {
			return nil, nil, nil, err
		}
		t := new(big.Int).Mul(q, two)
		p := new(big.Int).Add(t, one)
		if p.ProbablyPrime(probability) {
			for {
				g, err := rand.Int(rand.Reader, p)
				if err != nil {
					return nil, nil, nil, err
				}
				b := new(big.Int).Exp(g, two, p)
				if b.Cmp(one) == 0 {
					continue
				}
				b = new(big.Int).Exp(g, q, p)
				if b.Cmp(one) == 0 {
					return p, q, g, nil
				}
			}
		}
	}
	return nil, nil, nil, errors.New("can't emit <p,q,g>")
}
