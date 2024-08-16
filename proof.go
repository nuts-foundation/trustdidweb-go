package trustdidweb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

type Proof struct {
	Type               string             `json:"type"`
	Cryptosuite        string             `json:"cryptosuite"`
	VerificationMethod verificationMethod `json:"verificationMethod"`
	Created            string             `json:"created"`
	ProofPurpose       string             `json:"proofPurpose"`
	Challenge          string             `json:"challenge"`
	ProofValue         string             `json:"proofValue,omitempty"`
}

// verificationMethod represents a did:key verification method
type verificationMethod string

func (verificationMethod verificationMethod) PublicKey() (uint64, crypto.PublicKey, error) {
	if !strings.HasPrefix(string(verificationMethod), "did:key:") {
		return 0, nil, fmt.Errorf("verificationmethod must be a did:key method")
	}
	encodedPubKey := strings.Split(string(verificationMethod), "#")[1]
	_, multibaseKey, err := multibase.Decode(encodedPubKey)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode verificationMethod: %w", err)
	}

	keyType, n := binary.Uvarint(multibaseKey)
	if n <= 0 {
		return 0, nil, fmt.Errorf("invalid multibase key type header")
	}
	keyBytes := multibaseKey[n:]

	var pubKey crypto.PublicKey

	switch multicodec.Code(keyType) {
	case multicodec.P256Pub:
		pubKey, err = extractEcdsaPubKey(keyBytes, elliptic.P256())
	case multicodec.P384Pub:
		pubKey, err = extractEcdsaPubKey(keyBytes, elliptic.P384())
	case multicodec.Ed25519Pub:
		pubKey = ed25519.PublicKey(keyBytes)
	default:
		return 0, nil, fmt.Errorf("unsupported key type: %x", keyType)
	}

	if err != nil {
		return 0, nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return keyType, pubKey, nil
}

func (verificationMethod verificationMethod) toUpdateKey() string {
	return strings.Split(string(verificationMethod), "#")[1]
}

func verificationMethodFromSigner(signer crypto.Signer) (verificationMethod, error) {
	pubKey := signer.Public()
	encodedKey, err := encodePubKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode public key: %w", err)
	}
	return verificationMethod(fmt.Sprintf("did:key:%s#%s", encodedKey, encodedKey)), nil
}

func (proof Proof) Verify(challenge string, updateKeys []string, doc map[string]interface{}) error {
	if proof.Type != "DataIntegrityProof" {
		return fmt.Errorf("unsupported proof type: %s", proof.Type)
	}
	if proof.ProofPurpose != "authentication" {
		return fmt.Errorf("unsupported proof purpose: %s", proof.ProofPurpose)
	}
	if proof.Challenge != challenge {
		fmt.Printf("proof.challenge: %s, expected: %s\n", proof.Challenge, challenge)
		return fmt.Errorf("challenge mismatch")
	}

	updateKey := proof.VerificationMethod.toUpdateKey()
	if !slices.Contains(updateKeys, updateKey) {
		return fmt.Errorf("proof must be signed with an active update key")
	}

	var hashfn hash.Hash
	keyType, pubKey, err := proof.VerificationMethod.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to extract public key from verification method: %w", err)
	}

	// set hash function based on cryptosuite and key type
	switch proof.Cryptosuite {
	case CRYPTO_SUITE_ECDSA_JCS_2019:
		switch multicodec.Code(keyType) {
		case multicodec.P256Pub:
			hashfn = sha256.New()
		case multicodec.P384Pub:
			hashfn = sha512.New384()
		default:
			return fmt.Errorf("incompatible key type '%s' for cryptosuite '%s'", multicodec.Code(keyType), proof.Cryptosuite)
		}
	case CRYPTO_SUITE_EDDSA_JCS_2022:
		if multicodec.Code(keyType) != multicodec.Ed25519Pub {
			return fmt.Errorf("incompatible key type '%s' for cryptosuite '%s'", multicodec.Code(keyType), proof.Cryptosuite)
		}
		hashfn = sha256.New()
	default:
		return fmt.Errorf("unsupported cryptosuite: %s", proof.Cryptosuite)
	}

	input, err := hashLogVersion(doc, proof, hashfn)
	if err != nil {
		return fmt.Errorf("failed to hash log version: %w", err)
	}

	proofValue := proof.ProofValue
	_, signature, err := multibase.Decode(proofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proof value: %w", err)
	}
	fmt.Printf("signature: %x\n", signature)
	fmt.Printf("signature length: %d\n", len(signature))

	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		// a acdsa signature can be either 2 concatenated integers or asn1 encoded
		// This code checks if the signature valid asn1 encoded:
		// _, err = parseSig(signature, false)
		// if err != nil {
		// 	return fmt.Errorf("failed to parse signature: %w", err)
		// }
		// split the signature in half to get the r and s values
		r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
		s := big.NewInt(0).SetBytes(signature[len(signature)/2:])

		// try both type of signature encoding
		if !ecdsa.Verify(pubKey, input, r, s) {
			// try the other way around:
			r = big.NewInt(0).SetBytes(signature[len(signature)/2:])
			s = big.NewInt(0).SetBytes(signature[:len(signature)/2])
			if !ecdsa.Verify(pubKey, input, r, s) &&
				!ecdsa.VerifyASN1(pubKey, input, signature) {
				return fmt.Errorf("invalid signature")
			}
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pubKey, input, signature) {
			return fmt.Errorf("invalid signature")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	return nil
}

func hashLogVersion(document map[string]interface{}, proof Proof, hashfn hash.Hash) ([]byte, error) {
	// Remove the proofValue from the proof
	proof.ProofValue = ""

	// Create a canonicalized version of the proof and the did document
	optionData, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof: %w", err)
	}
	(*jsontext.Value)(&optionData).Canonicalize()

	// Create a canonicalized version of the docstate up until this version
	docData, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value: %w", err)
	}
	(*jsontext.Value)(&docData).Canonicalize()

	logger().Debug("canonicalized did doc", "value", string(docData))
	logger().Debug("canonicalized proof", "value", string(optionData))

	hashfn.Reset()
	hashfn.Write(docData)
	dataHash := hashfn.Sum(nil)
	hashfn.Reset()
	hashfn.Write(optionData)
	optionsHash := hashfn.Sum(nil)

	fmt.Printf("dataHash: %x\n", dataHash)
	fmt.Printf("optionsHash: %x\n", optionsHash)

	logger().Debug("hash", "data", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(dataHash[:]))
	logger().Debug("hash", "options", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(optionsHash[:]))

	input := append(dataHash[:], optionsHash[:]...)
	fmt.Printf("input: %x\n", input)
	return input, nil
}
