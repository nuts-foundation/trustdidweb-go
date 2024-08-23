package trustdidweb

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	b58 "github.com/mr-tron/base58/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// Specification can be found here:
// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters

// LogParams represents the parameters of a log entry
type LogParams struct {
	Method        string        `json:"method,omitzero"`
	Scid          string        `json:"scid,omitzero"`
	UpdateKeys    []string      `json:"updateKeys,omitzero"`
	Portable      bool          `json:"portable,omitzero"`
	Cryptosuite   string        `json:"cryptosuite,omitempty"`
	Prerotation   bool          `json:"prerotation,omitzero"`
	NextKeyHashes []NextKeyHash `json:"nextKeyHashes,omitzero"`
	// Witness       Witness
	Deactivated bool `json:"deactivated,omitzero"`
	TTL         int  `json:"ttl,omitzero"`
}

type NextKeyHash string

func (keyHash NextKeyHash) VerifyUpdateKey(updateKey string) error {
	if len(keyHash) == 0 {
		return fmt.Errorf("next key hash is required")
	}

	newKeyHash, err := nextKeyHashFromUpdateKey(updateKey)
	if err != nil {
		return fmt.Errorf("failed to generate next key hash: %w", err)
	}

	if newKeyHash != keyHash {
		return fmt.Errorf("updateKey does not correspond with nextKeyHash")
	}
	return nil
}

// VerifyPublicKey takes a public key and verifies if it matches with the nextKeyHash
func (keyHash NextKeyHash) VerifyPublicKey(pubKey crypto.PublicKey) error {
	if len(keyHash) == 0 {
		return fmt.Errorf("next key hash is required")
	}

	keyHashBytes, err := b58.DecodeAlphabet(string(keyHash), b58.BTCAlphabet)
	if err != nil {
		return fmt.Errorf("failed to decode next key hash: %w", err)
	}

	code, n := binary.Uvarint([]byte(keyHashBytes))
	if n <= 0 {
		return fmt.Errorf("invalid multibase key type header")
	}

	var hashfn hash.Hash
	// var hashfn hash.Hash
	switch codec := multicodec.Code(code); codec {
	case multicodec.Sha2_256:
		hashfn = sha256.New()
	default:
		return fmt.Errorf("unsupported hash function: %s", codec.String())
	}

	// read the length of the digest
	length, m := binary.Uvarint([]byte(keyHashBytes[n:]))
	if n <= 0 {
		return fmt.Errorf("invalid multibase key type header")
	}
	fmt.Printf("length: %d\n", length)

	multikey, err := NewUpdateKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	hashfn.Write([]byte(multikey))
	digest := hashfn.Sum(nil)

	if len(digest) != int(length) {
		return fmt.Errorf("digest length does not match")
	}

	if !bytes.Equal(digest, keyHashBytes[n+m:]) {
		return fmt.Errorf("digest does not match, expected: %x, got: %x", digest, keyHashBytes[n:])
	}

	return nil
}

// NewUpdateKey encodes a public key to a multiKey formatted updateKey
func NewUpdateKey(pubKey crypto.PublicKey) (string, error) {
	var pubkeyBytes []byte
	var keyCodec multicodec.Code
	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		pubkeyBytes = elliptic.MarshalCompressed(pubKey.Curve, pubKey.X, pubKey.Y)
		switch pubKey.Curve {
		case elliptic.P256():
			keyCodec = multicodec.P256Pub
		case elliptic.P384():
			keyCodec = multicodec.P384Pub
		default:
			return "", fmt.Errorf("unsupported curve: %s", pubKey.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		pubkeyBytes = pubKey
		keyCodec = multicodec.Ed25519Pub
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, uint64(keyCodec))
	b := buf[:n]

	multiCodecKey := append(b, pubkeyBytes...)

	return multibase.Encode(multibase.Base58BTC, multiCodecKey)
}

// NewNextKeyHash takes a public key and generates the coresponding nextKeyHash
func NewNextKeyHash(pubKey crypto.PublicKey) (NextKeyHash, error) {
	multiKey, err := NewUpdateKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode public key: %w", err)
	}

	return nextKeyHashFromUpdateKey(multiKey)
}

func nextKeyHashFromUpdateKey(updateKey string) (NextKeyHash, error) {
	digest := sha256.Sum256([]byte(updateKey))

	// put the header for the hash type
	hashType := uint64(multicodec.Sha2_256)
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, hashType)
	b := buf[:n]

	// calculate and encode the length of the digest
	buf = make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(buf, uint64(len(digest)))
	b = append(b, buf[:n]...)
	b = append(b, digest[:]...)

	hash := b58.EncodeAlphabet(b, b58.BTCAlphabet)

	return NextKeyHash(hash), nil
}

// NewInitialParams returns the parameters for the first log entry
// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters
func NewInitialParams(pubKeys []crypto.PublicKey, nextKeyHashes []NextKeyHash) (LogParams, error) {
	if len(pubKeys) == 0 {
		return LogParams{}, fmt.Errorf("at least one public key is required")
	}

	updateKeys := make([]string, len(pubKeys))
	var err error
	cryptoSuite := ""
	for i, pubKey := range pubKeys {
		var suite string
		switch pubKey.(type) {
		case ecdsa.PublicKey:
			suite = CRYPTO_SUITE_ECDSA_JCS_2019
		case *ecdsa.PublicKey:
			suite = CRYPTO_SUITE_ECDSA_JCS_2019
		case ed25519.PublicKey:
			suite = CRYPTO_SUITE_EDDSA_JCS_2022
		case *ed25519.PublicKey:
			suite = CRYPTO_SUITE_EDDSA_JCS_2022
		default:
			return LogParams{}, fmt.Errorf("unsupported public key type: %T", pubKey)
		}

		if cryptoSuite != "" && cryptoSuite != suite {
			return LogParams{}, fmt.Errorf("multiple public key types not supported")
		}
		cryptoSuite = suite

		if updateKeys[i], err = NewUpdateKey(pubKey); err != nil {
			return LogParams{}, fmt.Errorf("failed to encode public key: %w", err)
		}
	}
	var prerotation bool
	if len(nextKeyHashes) > 0 {
		prerotation = true
	}

	if cryptoSuite == CRYPTO_SUITE_EDDSA_JCS_2022 {
		// for the eddsa-jcs-2022, crypto suite is not set, since it is the default
		cryptoSuite = ""
	}

	return LogParams{
		Method:        TDWMethodv03,
		Scid:          "{SCID}",
		Prerotation:   prerotation,
		UpdateKeys:    updateKeys,
		NextKeyHashes: nextKeyHashes,
		Cryptosuite:   cryptoSuite}, nil
}
