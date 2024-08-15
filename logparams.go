package trustdidweb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
)

// Specification can be found here:
// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters

// LogParams represents the parameters of a log entry
type LogParams struct {
	Method        string   `json:"method,omitzero"`
	Scid          string   `json:"scid,omitzero"`
	UpdateKeys    []string `json:"updateKeys,omitzero"`
	Portable      bool     `json:"portable,omitzero"`
	Cryptosuite   string   `json:"cryptosuite,omitempty"`
	Prerotation   bool     `json:"prerotation,omitzero"`
	NextKeyHashes []string `json:"nextKeyHashes,omitzero"`
	// Witness       Witness
	Deactivated bool `json:"deactivated,omitzero"`
	TTL         int  `json:"ttl,omitzero"`
}

// NewInitialParams returns the parameters for the first log entry
// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters
func NewInitialParams(pubKeys []crypto.PublicKey, nextKeyHashes []string) (LogParams, error) {
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

		if updateKeys[i], err = encodePubKey(pubKey); err != nil {
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
