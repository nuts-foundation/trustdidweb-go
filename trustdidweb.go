package trustdidweb

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"strconv"
	"strings"
	"time"

	jsonpatchApplier "github.com/evanphx/json-patch/v5"
	"github.com/go-json-experiment/json"
	jsonpatchCreator "github.com/mattbaird/jsonpatch"
	b58 "github.com/mr-tron/base58/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

const TDWMethodv1 = "did:tdw:1"
const TDWMethodv03 = "did:tdw:0.3"

const CRYPTO_SUITE_ECDSA_JCS_2019 = "ecdsa-jcs-2019"
const CRYPTO_SUITE_EDDSA_JCS_2022 = "eddsa-jcs-2022"

type docState struct {
	Value DIDDocument `json:"value,omitempty"`
	Patch interface{} `json:"patch,omitempty"`
}

type versionId struct {
	Version int
	Hash    entryHash
}

func (v *versionId) MarshalJSON() ([]byte, error) {
	// during the initial creation of the log entry, the version is 0 or unset
	if v.Version == 0 {
		return json.Marshal(v.Hash)
	}
	return json.Marshal(v.String())
}

func (v *versionId) String() string {
	if v.Version == 0 {
		return string(v.Hash)
	}
	return fmt.Sprintf("%d-%s", v.Version, v.Hash)
}

func (v *versionId) UnmarshalJSON(b []byte) error {
	if strings.Contains(string(b), "-") {
		versionString, _ := strconv.Unquote(string(b))

		s := strings.Split(versionString, "-")
		if len(s) != 2 {
			return errors.New("invalid versionId format")
		}
		err := json.Unmarshal([]byte(s[0]), &v.Version)
		if err != nil {
			return fmt.Errorf("failed to unmarshal version: %w", err)
		}
		err = json.Unmarshal([]byte(strconv.Quote(s[1])), &v.Hash)
		if err != nil {
			return fmt.Errorf("failed to unmarshal hash: %w", err)
		}
	} else {
		v.Version = 0
		return json.Unmarshal(b, &v.Hash)
	}

	return nil
}

type entryHash string

// Digest returns the digest and the hash function used to create it
func (s entryHash) Digest() ([]byte, uint64, error) {
	decoded, err := b58.DecodeAlphabet(string(s), b58.BTCAlphabet)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to b58 decode scid: %w", err)
	}
	offset := 0

	hashType, n := binary.Uvarint(decoded[0:8])
	if hashType == 0 && n <= 0 {
		return nil, 0, fmt.Errorf("invalid hash-func-type")
	}
	offset += n

	hashLength, n := binary.Uvarint(decoded[n:])
	if hashLength == 0 && n <= 0 {
		return nil, 0, fmt.Errorf("invalid digest-length")
	}
	offset += n

	digest := decoded[offset:]
	if len(digest) != int(hashLength) {
		return nil, 0, fmt.Errorf("invalid digest-value length")

	}
	return digest, hashType, nil
}

func newEntryHash(data []byte, hashType uint64) entryHash {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, hashType)
	b := buf[:n]

	switch multicodec.Code(hashType) {
	case multicodec.Sha2_256:
		digest := sha256.Sum256(data)

		// calculate and encode the length of the digest
		buf = make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(buf, uint64(len(digest)))
		b = append(b, buf[:n]...)

		b = append(b, digest[:]...)
	default:
		return ""
	}

	hash := b58.EncodeAlphabet(b, b58.BTCAlphabet)
	return entryHash([]byte(hash))
}

func (s entryHash) Verify(data []byte) error {
	digest, hashType, err := s.Digest()
	if err != nil {
		return err
	}

	switch multicodec.Code(hashType) {
	case multicodec.Sha2_256:
		calculated := sha256.Sum256(data)
		if !bytes.Equal(digest, calculated[:]) {
			return fmt.Errorf("digest mismatch")
		}
	default:
		return fmt.Errorf("unsupported hash type")
	}

	return nil
}

type DIDLog []LogEntry

func (log DIDLog) MarshalJSON() ([]byte, error) {
	return json.Marshal([]LogEntry(log))
}

func (log DIDLog) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	for i, entry := range log {
		// only append a newline if it's not the first entry
		if i > 0 {
			buf.WriteByte('\n')
		}
		line, err := entry.MarshalJSONL()
		if err != nil {
			return nil, err
		}
		buf.Write(line)
	}
	return buf.Bytes(), nil
}

func (log *DIDLog) UnmarshalText(b []byte) error {
	lines := bytes.Split(b, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		entry := LogEntry{}
		if err := entry.UnmarshalJSONL(line); err != nil {
			return err
		}
		*log = append(*log, entry)
	}
	return nil
}

// Returns the DID Document created from applying all the log entries
func (log DIDLog) Document() (DIDDocument, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("empty log")
	}

	var docBytes []byte
	var err error

	for i, entry := range log {
		// first entry contains a value
		if i == 0 {
			if entry.DocState.Value == nil {
				return nil, fmt.Errorf("missing docstate value in first log entry")
			}
			docBytes, err = json.Marshal(entry.DocState.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal value of the first log entry: %w", err)
			}
		} else {
			// try a full document first
			if entry.DocState.Value != nil {
				docBytes, err = json.Marshal(entry.DocState.Value)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal value: %w", err)
				}
			} else if entry.DocState.Patch != nil {
				patchBytes, err := json.Marshal(entry.DocState.Patch)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal patch: %w", err)
				}
				patch, err := jsonpatchApplier.DecodePatch(patchBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to decode patch: %w", err)
				}
				docBytes, err = patch.Apply(docBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to apply patch: %w", err)
				}
			} else {
				return nil, fmt.Errorf("missing value or patch in log entry")
			}
		}
	}

	logger().Debug("document", "doc", string(docBytes))

	doc := DIDDocument{}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

	return doc, nil
}

func logger() *slog.Logger {
	return slog.Default().WithGroup("trustdidweb")
}

func renderPathTemplate(didTemplate, scid string) string {
	return strings.ReplaceAll(didTemplate, "{SCID}", scid)
}

// Can be replaced with a function that returns the current time in a deterministic way
// for testing purposes
var timeFunc = time.Now

func ParseLog(b []byte) (DIDLog, error) {
	log := DIDLog{}
	err := log.UnmarshalText(b)
	return log, err
}

type DIDDocument map[string]interface{}

func NewMinimalDIDDocument(didTemplate string) (DIDDocument, error) {
	if !strings.HasPrefix(didTemplate, "did:tdw:{SCID}") {
		return nil, fmt.Errorf("invalid did template: missing required 'did:tdw:{SCID}' prefix")
	}

	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/did/v1",
		},
		"id": renderPathTemplate(didTemplate, "{SCID}"),
	}

	return doc, nil
}

// ReplaceSCIDPlaceholder replaces the {SCID} placeholder in the document with the provided SCID
func (doc *DIDDocument) ReplaceSCIDPlaceholder(scid string) error {
	docAsBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}
	docAsBytes = []byte(strings.ReplaceAll(string(docAsBytes), "{SCID}", scid))

	var newDoc DIDDocument
	if err := json.Unmarshal(docAsBytes, &newDoc); err != nil {
		return fmt.Errorf("failed to unmarshal document: %w", err)
	}
	*doc = newDoc
	return nil
}

// Create creates a new DIDLog with a single log entry
// It calculates the SCID of the first log entry and replaces the placeholder in the path template
// It signs the entry with the provided signer
func Create(doc DIDDocument, signer crypto.Signer, nextKeyhashes ...NextKeyHash) (DIDLog, error) {
	params, err := NewInitialParams([]crypto.PublicKey{signer.Public()}, nextKeyhashes)
	if err != nil {
		return nil, err
	}

	le := LogEntry{
		DocState:    docState{Value: doc},
		Params:      params,
		VersionTime: timeFunc(),
	}

	logger().Debug("create", "entry", le)

	// calculate the SCID
	versionId, err := DIDLog{le}.calculateVersionId(0)
	if err != nil {
		return nil, err
	}
	scid := string(versionId.Hash)

	logger().Debug("create", "scid", scid)

	// replace placeholders with the actual values containing the did string
	le.DocState.Value.ReplaceSCIDPlaceholder(scid)
	le.Params.Scid = scid
	le.VersionId = versionId

	versionId, err = DIDLog{le}.calculateVersionId(1)
	if err != nil {
		return nil, err
	}
	le.VersionId = versionId

	logger().Debug("create", "entry", le)

	proof, err := DIDLog{le}.buildProof(signer)
	if err != nil {
		return nil, err
	}
	le.Proof = []Proof{proof}

	return DIDLog{le}, nil
}

func (log DIDLog) Update(params LogParams, modifiedDoc map[string]interface{}, signer crypto.Signer) (DIDLog, error) {
	fmt.Print("\n\nUpdate:\n\n")

	currentDoc, err := log.Document()
	if err != nil {
		return DIDLog{}, err
	}

	currentDocBytes, err := json.Marshal(currentDoc)
	if err != nil {
		return DIDLog{}, err
	}

	modifiedDocBytes, err := json.Marshal(modifiedDoc)
	if err != nil {
		return DIDLog{}, err
	}

	patch, err := jsonpatchCreator.CreatePatch(currentDocBytes, modifiedDocBytes)
	if err != nil {
		return DIDLog{}, err
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return DIDLog{}, err
	}

	logger().Debug("update", "patch", string(patchBytes))

	entry := LogEntry{
		VersionTime: timeFunc(),
		Params:      params,
		DocState:    docState{Patch: patch},
	}

	nextVersion := len(log) + 1
	versionId, err := append(log, entry).calculateVersionId(nextVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to hash entry: %w", err)
	}
	entry.VersionId = versionId

	proof, err := append(log, entry).buildProof(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to build proof: %w", err)
	}
	entry.Proof = []Proof{proof}

	return append(log, entry), nil
}

// NewSigner returns the signer of the configured crypto suite
func NewSigner(cryptoSuite string) (crypto.Signer, error) {
	switch cryptoSuite {
	case CRYPTO_SUITE_ECDSA_JCS_2019:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case CRYPTO_SUITE_EDDSA_JCS_2022:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return &key, err
	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", cryptoSuite)
	}
}

// buildProof creates a proof for the latest entry in the log
func (log DIDLog) buildProof(signer crypto.Signer) (Proof, error) {
	fmt.Print("\n\nbuildProof:\n\n")

	entry := log[len(log)-1]

	verificationMethod, err := verificationMethodFromSigner(signer)
	if err != nil {
		return Proof{}, fmt.Errorf("failed to get verification method: %w", err)
	}

	var suite string
	var hashfn hash.Hash
	var signerOpts crypto.SignerOpts

	switch key := signer.Public().(type) {
	case *ecdsa.PublicKey:
		suite = CRYPTO_SUITE_ECDSA_JCS_2019
		signerOpts = nil
		switch key.Curve {
		case elliptic.P256():
			hashfn = sha256.New()
		case elliptic.P384():
			hashfn = sha512.New384()
		default:
			return Proof{}, fmt.Errorf("unsupported curve: %s", key.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		suite = CRYPTO_SUITE_EDDSA_JCS_2022
		hashfn = sha256.New()
		signerOpts = &ed25519.Options{}
	default:
		return Proof{}, fmt.Errorf("unsupported public key type: %T", signer.Public())
	}

	proof := Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        suite,
		VerificationMethod: verificationMethod,
		Created:            timeFunc().Format(time.RFC3339),
		ProofPurpose:       "authentication",
		Challenge:          entry.VersionId.String(),
	}

	// var hashfn = sha512.New384()
	doc, err := log.Document()
	if err != nil {
		return Proof{}, fmt.Errorf("failed to get document: %w", err)
	}
	input, err := hashLogVersion(doc, proof, hashfn)
	if err != nil {
		return Proof{}, fmt.Errorf("failed to hash entry: %w", err)
	}

	fmt.Printf("input length: %d\n", len(input))

	fmt.Printf("input: %s\n", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(input))

	// sign the entry
	signature, err := signer.Sign(rand.Reader, input, signerOpts)
	if err != nil {
		return Proof{}, fmt.Errorf("failed to sign entry: %w", err)
	}

	fmt.Printf("signature: %s\n", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature))

	encodedProof, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return Proof{}, fmt.Errorf("failed to encode signature: %w", err)
	}
	proof.ProofValue = string(encodedProof)

	return proof, nil
}

// calculateEntryHash calculates the hash of the
func (log DIDLog) calculateVersionId(version int) (versionId, error) {
	fmt.Print("\ncalculateVersionId:\n")
	fmt.Printf("version: %d\n", version)

	var entry LogEntry
	var prevVersionId versionId
	switch version {
	case 0:
		entry = log[0]
		prevVersionId = versionId{Version: 0, Hash: entryHash("{SCID}")}
		entry.Params.Scid = "{SCID}"
	case 1:
		entry = log[0]
		prevVersionId = versionId{Version: 0, Hash: entryHash(entry.Params.Scid)}
	default:
		entry = log[version-1]
		prevVersionId = log[version-2].VersionId
	}

	calculatedVersionHash, err := entry.calculateEntryHash(prevVersionId)
	if err != nil {
		return versionId{}, fmt.Errorf("failed to calculate entry hash: %w", err)
	}
	return versionId{Version: version, Hash: entryHash(calculatedVersionHash)}, nil
}

func (log DIDLog) Verify() error {
	fmt.Print("\n\nVerify:\n\n")
	// empty log should not be considered valid
	if len(log) == 0 {
		return fmt.Errorf("empty log")
	}

	var scid string

	for i, entry := range log {
		fmt.Printf("\nentry i: %d\n", i)

		if i+1 != entry.VersionId.Version {
			return fmt.Errorf("invalid log sequence number, expected: %d, got: %d", i+1, entry.VersionId.Version)
		}

		if i == 0 {
			fmt.Printf("verify scid first entry\n")
			if entry.Params.Scid == "" {
				return fmt.Errorf("missing scid in the first log entry params")
			}

			// set the scid
			scid = entry.Params.Scid

			// create a copy
			var initEntry LogEntry
			entryBytes, err := json.Marshal(entry)
			if err != nil {
				return fmt.Errorf("failed to marshal entry: %w", err)
			}
			err = json.Unmarshal(entryBytes, &initEntry)
			if err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}

			// replace all instances of the scid with the placeholder
			docBytes, err := json.Marshal(initEntry.DocState.Value)
			if err != nil {
				return fmt.Errorf("failed to marshal docstate: %w", err)
			}
			initialDoc := strings.ReplaceAll(string(docBytes), scid, "{SCID}")
			err = json.Unmarshal([]byte(initialDoc), &initEntry.DocState.Value)
			if err != nil {
				return fmt.Errorf("failed to unmarshal docstate: %w", err)
			}

			calculatedVersionId, err := DIDLog{initEntry}.calculateVersionId(0)
			if err != nil {
				return fmt.Errorf("failed to calculate scid: %w", err)
			}
			if scid != string(calculatedVersionId.Hash) {
				return fmt.Errorf("invalid scid")
			}
		} else {
			if log[:i].IsDeactivated() {
				return fmt.Errorf("invalid entry after deactivation")
			}
			// check if the scid is the same as the first one
			if entry.Params.Scid != "" && entry.Params.Scid != scid {
				return fmt.Errorf("scid cannot be changed")
			}

			// check if new updatekeys are added and if they are listed in the nextKeyHashes
			if len(entry.Params.UpdateKeys) > 0 {
				for _, updateKey := range entry.Params.UpdateKeys {
					for j, keyHash := range log[:i].getNextKeyHahses() {
						err := keyHash.VerifyUpdateKey(updateKey)
						if err != nil && j == len(log[:i].getNextKeyHahses())-1 {
							return fmt.Errorf("update key must be in the active nextKeyHashes list")
						}
					}
				}
			}
		}

		// previous entry needed to verify if the correct key was used
		var prevEntry LogEntry
		var prevVersionID versionId

		if i == 0 {
			prevEntry = entry
			// first entry uses the scid instead of the previous version hash
			prevVersionID = versionId{Hash: entryHash(entry.Params.Scid)}
		} else {
			prevEntry = log[i-1]
			prevVersionID = prevEntry.VersionId
		}

		calculatedVersionHash, err := entry.calculateEntryHash(prevVersionID)
		if err != nil {
			return fmt.Errorf("failed to calculate entry hash: %w", err)
		}
		if entry.VersionId.Hash != entryHash(calculatedVersionHash) {
			return fmt.Errorf("failed to verify entry hash")
		}
		challenge := entry.VersionId.String()
		updateKeys := log[:i].getUpdateKeys()

		// first entry uses its own update keys
		if i == 0 {
			updateKeys = log[:i+1].getUpdateKeys()
		}

		for _, proof := range entry.Proof {
			doc, err := log[:i+1].Document()
			if err != nil {
				return err
			}

			err = proof.Verify(challenge, updateKeys, doc)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (log DIDLog) Deactivate(signer crypto.Signer) (DIDLog, error) {
	fmt.Print("\n\nDeactivate:\n\n")

	if len(log) == 0 {
		return nil, fmt.Errorf("empty log")
	}

	// check if the log is already deactivated
	if log.IsDeactivated() {
		return nil, fmt.Errorf("log is already deactivated")
	}

	// create a new log entry
	params := LogParams{Deactivated: true}

	return log.Update(params, nil, signer)
}

func (log DIDLog) getUpdateKeys() []string {
	if len(log) == 0 {
		return nil
	}
	var updateKeys []string

	for _, entry := range log {
		if entry.Params.Deactivated {
			return nil
		}

		// if the entry key is defined, overwrite the updateKeys. Even if it is empty!
		if entry.Params.UpdateKeys != nil {
			updateKeys = entry.Params.UpdateKeys
		}
	}
	return updateKeys
}

func (log DIDLog) getNextKeyHahses() []NextKeyHash {
	if len(log) == 0 {
		return nil
	}
	var nextKeyHashes []NextKeyHash

	for _, entry := range log {
		if entry.Params.Deactivated {
			return nil
		}

		if entry.Params.NextKeyHashes != nil {
			nextKeyHashes = entry.Params.NextKeyHashes
		}
	}
	return nextKeyHashes
}

func (log DIDLog) IsDeactivated() bool {
	if len(log) == 0 {
		return false
	}
	for _, entry := range log {
		if entry.Params.Deactivated {
			return true
		}
	}
	return false
}
