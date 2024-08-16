package trustdidweb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
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
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	VerificationMethod string `json:"verificationMethod"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	Challenge          string `json:"challenge"`
	ProofValue         string `json:"proofValue,omitempty"`
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

	verificationMethod := strings.Split(proof.VerificationMethod, "#")[1]
	if !slices.Contains(updateKeys, verificationMethod) {
		return fmt.Errorf("proof must be signed with an active update key")
	}

	var hashfn hash.Hash
	keyType, pubKey, err := extractPubKey(proof.VerificationMethod)
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
