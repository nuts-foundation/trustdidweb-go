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
	"math/big"
	"strconv"
	"strings"
	"time"

	jsonpatchApplier "github.com/evanphx/json-patch/v5"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	jsonpatchCreator "github.com/mattbaird/jsonpatch"
	b58 "github.com/mr-tron/base58/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

const TDWMethodv1 = "did:tdw:1"
const TDWMethodv03 = "did:tdw:0.3"

const CRYPTO_SUITE_ECDSA_JCS_2019 = "ecdsa-jcs-2019"
const CRYPTO_SUITE_EDDSA_JCS_2022 = "eddsa-jcs-2022"

type LogEntry struct {
	VersionId   versionId `json:"versionId"`
	VersionTime time.Time `json:"versionTime"`
	Params      LogParams `json:"params"`
	DocState    docState  `json:"docState,omitempty"`
	Proof       []Proof   `json:"proof,omitempty"`
}

type docState struct {
	Value interface{} `json:"value,omitempty"`
	Patch interface{} `json:"patch,omitempty"`
}

type versionId struct {
	Version int
	Hash    EntryHash
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

type EntryHash string

// Digest returns the digest and the hash function used to create it
func (s EntryHash) Digest() ([]byte, uint64, error) {
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

func NewEntryHash(data []byte, hashType uint64) EntryHash {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, hashType)
	b := buf[:n]

	// Sha2_256 Code = 0x12 // sha2-256
	// Sha2_512 Code = 0x13 // sha2-512
	// Sha3_512 Code = 0x14 // sha3-512
	// Sha3_384 Code = 0x15 // sha3-384
	// Sha3_256 Code = 0x16 // sha3-256

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

	scid := b58.EncodeAlphabet(b, b58.BTCAlphabet)
	return EntryHash([]byte(scid))
}

func (s EntryHash) Verify(data []byte) error {
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

// logLine is an intermidiate representation of a log entry for JSON marshalling
type logLine []interface{}

func (l *logLine) ToLogEntry() (LogEntry, error) {

	type logLineStruct struct {
		VersionID   interface{} `json:"versionId"`
		VersionTime interface{} `json:"versionTime"`
		Params      interface{} `json:"params"`
		DocState    interface{} `json:"docState"`
		Proof       interface{} `json:"proof"`
	}

	lls := logLineStruct{
		VersionID:   (*l)[0],
		VersionTime: (*l)[1],
		Params:      (*l)[2],
		DocState:    (*l)[3],
		// Proof:       (*l)[4],
	}

	if len(*l) == 5 {
		lls.Proof = (*l)[4]
	} else {
		lls.Proof = nil
	}

	lBytes, err := json.Marshal(lls)
	if err != nil {
		return LogEntry{}, err
	}
	entry := LogEntry{}
	err = json.Unmarshal(lBytes, &entry)
	if err != nil {
		return LogEntry{}, err
	}
	return entry, nil
}

// MarshalJSONL returns the JSON-line representation of the log entry
func (l LogEntry) MarshalJSONL() ([]byte, error) {
	line := []interface{}{l.VersionId, l.VersionTime, l.Params, l.DocState}

	if len(l.Proof) > 0 {
		line = append(line, l.Proof)
	}

	b, err := json.Marshal(line)
	if err != nil {
		return nil, err
	}
	(*jsontext.Value)(&b).Canonicalize()
	return b, nil
}

func (l *LogEntry) UnmarshalJSONL(b []byte) error {
	line := logLine{}
	// line := []interface{}{}
	if err := json.Unmarshal(b, &line); err != nil {
		return err
	}

	entry, err := line.ToLogEntry()
	if err != nil {
		return err
	}

	*l = entry
	return nil
}

// LogParams represents the parameters of a log entry
type LogParams struct {
	Method        string   `json:"method"`
	Scid          string   `json:"scid"`
	UpdateKeys    []string `json:"updateKeys"`
	Hash          string   `json:"-"`
	Cryptosuite   string   `json:"cryptosuite,omitempty"`
	Prerotation   bool     `json:"prerotation"`
	NextKeyHashes []string `json:"nextKeyHashes"`
	Moved         string   `json:"moved,omitempty"`
	Deactivated   bool     `json:"deactivated,omitzero"`
	TTL           int      `json:"ttl,omitzero"`
}

type DIDLog []LogEntry

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
func (log DIDLog) Document() (map[string]interface{}, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("empty log")
	}

	var docBytes []byte
	var err error

	for i, entry := range log {
		// first entry contains a value
		if i == 0 {
			if entry.DocState.Value == nil {
				return nil, fmt.Errorf("missing value in first log entry")
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

	doc := map[string]interface{}{}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

	return doc, nil
}

func logger() *slog.Logger {
	return slog.Default().WithGroup("trustdidweb")
}

type TrustDIDWeb struct {
	// Template for the path of the did document (e.g. did:tdw:sub.domain.example/{SCID})
	// Where the {SCID} placeholder will be replaced with the SCID of the first log entry
	pathTemplate string
	// one of the supported crypto suites (e.g., eddsa-jcs-2022)
	cryptoSuite string
}

func NewTrustDIDWeb(pathTemplate, cryptoSuite string) *TrustDIDWeb {
	return &TrustDIDWeb{
		pathTemplate: pathTemplate,
		cryptoSuite:  cryptoSuite,
	}
}

func (t *TrustDIDWeb) renderPathTemplate(scid string) string {
	return strings.ReplaceAll(t.pathTemplate, "{SCID}", scid)
}

// Can be replaced with a function that returns the current time in a deterministic way
// for testing purposes
var timeFunc = time.Now

// encodePubKey encodes a public key to a multicodec format
func encodePubKey(pubKey crypto.PublicKey) (string, error) {
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

// NewParams returns the parameters for the first log entry
// https://bcgov.github.io/trustdidweb/#didtdw-did-method-parameters
func (t *TrustDIDWeb) NewParams(pubKeys []crypto.PublicKey, nextKeyHashes []string) (*LogParams, error) {
	updateKeys := make([]string, len(pubKeys))
	var err error
	for i, pubKey := range pubKeys {
		if updateKeys[i], err = encodePubKey(pubKey); err != nil {
			return nil, fmt.Errorf("failed to encode public key: %w", err)
		}
	}
	var prerotation bool
	if len(nextKeyHashes) > 0 {
		prerotation = true
	}

	return &LogParams{
		Method:        TDWMethodv03,
		Scid:          "{SCID}",
		Prerotation:   prerotation,
		UpdateKeys:    updateKeys,
		NextKeyHashes: nextKeyHashes,
	}, nil
}

func ParseLog(b []byte) (DIDLog, error) {
	log := DIDLog{}
	err := log.UnmarshalText(b)
	return log, err
}

// Create creates a new DIDLog with a single log entry
// It calculates the SCID of the first log entry and replaces the placeholder in the path template
// It signs the entry with the provided signer
func (t *TrustDIDWeb) Create(params LogParams, signer crypto.Signer) (DIDLog, error) {

	// set SCID to the placeholder value
	scid := "{SCID}"

	doc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1",
		},
		"id": t.renderPathTemplate(scid),
	}

	params.Scid = scid

	le := LogEntry{
		VersionId:   versionId{Version: 0, Hash: EntryHash(scid)},
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
	scid = string(versionId.Hash)

	logger().Debug("create", "scid", scid)

	// replace placeholders with the actual values containing the did string
	le.DocState.Value.(map[string]interface{})["id"] = t.renderPathTemplate(scid)
	le.Params.Scid = scid
	le.VersionId = versionId

	versionId, err = DIDLog{le}.calculateVersionId(1)
	if err != nil {
		return nil, err
	}
	le.VersionId = versionId

	logger().Debug("create", "entry", le)

	log := DIDLog{le}
	proof, err := log.buildProof(1, signer)
	if err != nil {
		return nil, err
	}
	log[0].Proof = []Proof{proof}

	return log, nil
}

func (t *TrustDIDWeb) Update(log DIDLog, params LogParams, modifiedDoc map[string]interface{}, signer crypto.Signer) (DIDLog, error) {

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

	versionId, err := append(log, entry).calculateVersionId(2)
	if err != nil {
		return nil, fmt.Errorf("failed to hash entry: %w", err)
	}
	entry.VersionId = versionId

	proof, err := append(log, entry).buildProof(entry.VersionId.Version, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to build proof: %w", err)
	}
	entry.Proof = []Proof{proof}

	return append(log, entry), nil
}

// NewSigner returns the signer of the configured crypto suite
func (t *TrustDIDWeb) NewSigner() (crypto.Signer, error) {
	switch t.cryptoSuite {
	case CRYPTO_SUITE_ECDSA_JCS_2019:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case CRYPTO_SUITE_EDDSA_JCS_2022:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", t.cryptoSuite)
	}
}

func verificationMethodFromSigner(signer crypto.Signer) (string, error) {
	pubKey := signer.Public()
	encodedKey, err := encodePubKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode public key: %w", err)
	}
	return fmt.Sprintf("did:key:%s#%s", encodedKey, encodedKey), nil
}

func (log DIDLog) buildProof(version int, signer crypto.Signer) (Proof, error) {
	fmt.Print("\n\nbuildProof:\n\n")

	entry := log[version-1]

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

	// pubKey := signer.Public()
	// fmt.Printf("pubKey: X: %s, Y: %s\n", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pubKey.X.Bytes()), base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pubKey.Y.Bytes()))

	// var hashfn = sha512.New384()
	input, err := log.hashLogVersion(version, proof, hashfn)
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

// hashLogVersion removes the proofValue from the optionData (proof), canonicalizes both
// the optionData and the DocState and hashes them using the provided hash algorithm
func (log DIDLog) hashLogVersion(version int, proof Proof, hashfn hash.Hash) ([]byte, error) {
	// Remove the proofValue from the proof
	proof.ProofValue = ""

	// Create a canonicalized version of the proof and the did document
	optionData, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof: %w", err)
	}
	(*jsontext.Value)(&optionData).Canonicalize()

	// Create a canonicalized version of the docstate up until this version
	doc, err := log[:version].Document()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal doc state value: %w", err)
	}
	docData, err := json.Marshal(doc)
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

func extractEcdsaPubKey(key []byte, curve elliptic.Curve) (crypto.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, key)
	if x == nil {
		return nil, fmt.Errorf("failed to unmarshal compressed public key")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func extractPubKey(verificationMethod string) (uint64, crypto.PublicKey, error) {
	encodedPubKey := strings.Split(verificationMethod, "#")[1]
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

func (log DIDLog) calculateVersionId(version int) (versionId, error) {
	var entry LogEntry
	var prevVersionId versionId
	switch version {
	case 0:
		entry = log[0]
		prevVersionId = versionId{Version: 0, Hash: EntryHash("{SCID}")}
	case 1:
		entry = log[0]
		prevVersionId = versionId{Version: 0, Hash: EntryHash(entry.Params.Scid)}
	default:
		entry = log[version-1]
		prevVersionId = log[version-1].VersionId
	}

	entryWithoutProof := entry
	entryWithoutProof.Proof = nil

	prevVersionId.Version = 0
	calculatedVersionHash, err := calculateEntryHash(entryWithoutProof, prevVersionId)
	if err != nil {
		return versionId{}, fmt.Errorf("failed to calculate entry hash: %w", err)
	}
	return versionId{Version: version, Hash: EntryHash(calculatedVersionHash)}, nil
}

func (log DIDLog) Verify() error {
	fmt.Print("\n\nVerify:\n\n")

	for i, entry := range log {
		if i+1 != entry.VersionId.Version {
			return fmt.Errorf("log entries are not in sequence")
		}

		// previous entry needed to verify if the correct key was used
		var prevEntry LogEntry
		if i > 0 {
			prevEntry = log[i-1]
		} else {
			prevEntry = entry
		}

		entryWithoutProof := entry
		entryWithoutProof.Proof = nil

		var versionHash EntryHash
		// first entry uses the scid instead of the previous version hash
		if i == 0 {
			versionHash = EntryHash(prevEntry.Params.Scid)
		}

		calculatedVersionHash, err := calculateEntryHash(entryWithoutProof, versionId{Hash: versionHash})
		if err != nil {
			return fmt.Errorf("failed to calculate entry hash: %w", err)
		}
		if entry.VersionId.Hash != EntryHash(calculatedVersionHash) {
			return fmt.Errorf("version hash mismatch, expected: %s, got: %s", calculatedVersionHash, entry.VersionId.Hash)
		}
		challenge := entry.VersionId.String()

		for _, proof := range entry.Proof {
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
			if !strings.Contains(proof.VerificationMethod, prevEntry.Params.UpdateKeys[0]) {
				return fmt.Errorf("proof must be signed with the update key from the previous log entry")
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

			input, err := log.hashLogVersion(entry.VersionId.Version, proof, hashfn)
			if err != nil {
				return fmt.Errorf("failed to hash entry: %w", err)
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
						return fmt.Errorf("failed to verify proof")
					}
				}
			case ed25519.PublicKey:
				if !ed25519.Verify(pubKey, input, signature) {
					return fmt.Errorf("failed to verify proof")
				}
			default:
				return fmt.Errorf("unsupported public key type: %T", pubKey)
			}
		}
	}

	return nil
}

// func parseSignature(sig []byte) (r, s []byte, err error) {
// 	var inner cryptobyte.String
// 	input := cryptobyte.String(sig)
// 	var t asn1.Tag
// 	if !s.ReadAnyASN1(out, &t)  {
//     return nil, nil, errors.New("invalid ASN.1 Sequence")
//   }
//
//   if t != asn1.SEQUENCE {
//     return nil, nil, errors.New("invalid ASN.1 Sequence")
//   }
// 	// 	return nil, nil, errors.New("invalid ASN.1 Sequence")
//
// 	if !input.ReadASN1(&inner, asn1.SEQUENCE) {
// 	// 	return nil, nil, errors.New("invalid ASN.1 Sequence")
// 	// }
// 	if !input.Empty() {
// 		return nil, nil, errors.New("trailling data after ASN.1 sequence")
// 	}
//
// 	if !inner.ReadASN1Integer(&r) {
// 		return nil, nil, errors.New("invalid ASN.1, could not read r")
// 	}
// 	if !inner.ReadASN1Integer(&s) {
// 		return nil, nil, errors.New("invalid ASN.1, could not read s")
// 	}
// 	if !inner.Empty() {
// 		return nil, nil, errors.New("trailing data after ASN.1 integers")
// 	}
// 	return r, s, nil
// }

func (t *TrustDIDWeb) calculateSCID(firstLogEntry LogEntry) (string, error) {
	return calculateEntryHash(firstLogEntry, versionId{Hash: "{SCID}"})
}

func calculateEntryHash(entry LogEntry, prevVersionId versionId) (string, error) {
	fmt.Print("\n\ncalculateEntryHash:\n\n")
	fmt.Printf("entry: %v\n", entry)
	// Canonicalized version of the first log entry
	entry.VersionId = prevVersionId
	b, err := entry.MarshalJSONL()
	if err != nil {
		return "", err
	}

	fmt.Printf("b: %s\n", b)

	entryHash := NewEntryHash(b, uint64(multicodec.Sha2_256))
	if entryHash == "" {
		return "", fmt.Errorf("failed to calculate entry hash")
	}

	return string(entryHash), nil
}

// The code below is code taken from the go codebase to parse an ASN.1 encoded ecdsa signature. It give more debug information than the standard ecdsa.Verify function and helps with debugging the signature verification

type Signature struct {
	R, S *big.Int
}

const (
	// MinSigLen is the minimum length of a DER encoded signature and is when both R
	// and S are 1 byte each.
	// 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
	MinSigLen = 8

	// MaxSigLen is the maximum length of a DER encoded signature and is
	// when both R and S are 33 bytes each.  It is 33 bytes because a
	// 256-bit integer requires 32 bytes and an additional leading null byte
	// might be required if the high bit is set in the value.
	//
	// 0x30 + <1-byte> + 0x02 + 0x21 + <33 bytes> + 0x2 + 0x21 + <33 bytes>
	MaxSigLen = 72
)

func parseSig(sigStr []byte, der bool) (*Signature, error) {
	// Originally this code used encoding/asn1 in order to parse the
	// signature, but a number of problems were found with this approach.
	// Despite the fact that signatures are stored as DER, the difference
	// between go's idea of a bignum (and that they have sign) doesn't agree
	// with the openssl one (where they do not). The above is true as of
	// Go 1.1. In the end it was simpler to rewrite the code to explicitly
	// understand the format which is this:
	// 0x30 <length of whole message> <0x02> <length of R> <R> 0x2
	// <length of S> <S>.

	// The signature must adhere to the minimum and maximum allowed length.
	totalSigLen := len(sigStr)
	if totalSigLen < MinSigLen {
		return nil, errors.New("malformed signature: too short")
	}
	if der && totalSigLen > MaxSigLen {
		return nil, errors.New("malformed signature: too long")
	}

	// 0x30
	index := 0
	if sigStr[index] != 0x30 {
		return nil, errors.New("malformed signature: no header magic")
	}
	index++
	// length of remaining message
	siglen := sigStr[index]
	index++

	// siglen should be less than the entire message and greater than
	// the minimal message size.
	if int(siglen+2) > len(sigStr) || int(siglen+2) < MinSigLen {
		return nil, errors.New("malformed signature: bad length")
	}
	// trim the slice we're working on so we only look at what matters.
	sigStr = sigStr[:siglen+2]

	// 0x02
	if sigStr[index] != 0x02 {
		return nil,
			errors.New("malformed signature: no 1st int marker")
	}
	index++

	// Length of signature R.
	rLen := int(sigStr[index])
	// must be positive, must be able to fit in another 0x2, <len> <s>
	// hence the -3. We assume that the length must be at least one byte.
	index++
	if rLen <= 0 || rLen > len(sigStr)-index-3 {
		return nil, errors.New("malformed signature: bogus R length")
	}

	// Then R itself.
	rBytes := sigStr[index : index+rLen]
	// if der {
	// switch err := canonicalPadding(rBytes); err {
	// case errNegativeValue:
	// 	return nil, errors.New("signature R is negative")
	// case errExcessivelyPaddedValue:
	// 	return nil, errors.New("signature R is excessively padded")
	// }
	// }

	// Strip leading zeroes from R.
	for len(rBytes) > 0 && rBytes[0] == 0x00 {
		rBytes = rBytes[1:]
	}

	// R must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	// var r btcec.ModNScalar
	if len(rBytes) > 32 {
		str := "invalid signature: R is larger than 256 bits"
		return nil, errors.New(str)
	}
	// if overflow := r.SetByteSlice(rBytes); overflow {
	// 	str := "invalid signature: R >= group order"
	// 	return nil, errors.New(str)
	// }
	// if r.IsZero() {
	// 	str := "invalid signature: R is 0"
	// 	return nil, errors.New(str)
	// }
	index += rLen
	// 0x02. length already checked in previous if.
	if sigStr[index] != 0x02 {
		return nil, errors.New("malformed signature: no 2nd int marker")
	}
	index++

	// Length of signature S.
	sLen := int(sigStr[index])
	index++
	// S should be the rest of the string.
	if sLen <= 0 || sLen > len(sigStr)-index {
		return nil, errors.New("malformed signature: bogus S length")
	}

	// Then S itself.
	sBytes := sigStr[index : index+sLen]
	// if der {
	// switch err := canonicalPadding(sBytes); err {
	// case errNegativeValue:
	// 	return nil, errors.New("signature S is negative")
	// case errExcessivelyPaddedValue:
	// 	return nil, errors.New("signature S is excessively padded")
	// }
	// }

	// Strip leading zeroes from S.
	for len(sBytes) > 0 && sBytes[0] == 0x00 {
		sBytes = sBytes[1:]
	}

	// S must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	// var s btcec.ModNScalar
	if len(sBytes) > 32 {
		str := "invalid signature: S is larger than 256 bits"
		return nil, errors.New(str)
	}
	// if overflow := s.SetByteSlice(sBytes); overflow {
	// 	str := "invalid signature: S >= group order"
	// 	return nil, errors.New(str)
	// }
	// if s.IsZero() {
	// 	str := "invalid signature: S is 0"
	// 	return nil, errors.New(str)
	// }
	index += sLen

	// sanity check length parsing
	if index != len(sigStr) {
		return nil, fmt.Errorf("malformed signature: bad final length %v != %v",
			index, len(sigStr))
	}

	return &Signature{}, nil
}
