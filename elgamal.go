package elgamal

import (
	"errors"
	"math/big"
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
