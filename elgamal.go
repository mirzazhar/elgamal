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
