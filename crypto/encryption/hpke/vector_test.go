package hpke

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type hexByteSlice []byte

//nolint:wrapcheck // No need to wrap the error
func (m *hexByteSlice) UnmarshalJSON(b []byte) error {
	var data string
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	// Decode hex
	raw, err := hex.DecodeString(data)
	*m = raw
	return err
}

type encryptionVector struct {
	Aad        hexByteSlice `json:"aad"`
	Ciphertext hexByteSlice `json:"ct"`
	Nonce      hexByteSlice `json:"nonce"`
	Plaintext  hexByteSlice `json:"pt"`
}

type exportVector struct {
	ExportContext hexByteSlice `json:"exporter_context"`
	ExportLength  int          `json:"L"`
	ExportValue   hexByteSlice `json:"exported_value"`
}

type vector struct {
	ModeID             uint8              `json:"mode"`
	KemID              uint16             `json:"kem_id"`
	KdfID              uint16             `json:"kdf_id"`
	AeadID             uint16             `json:"aead_id"`
	Info               hexByteSlice       `json:"info"`
	Ier                hexByteSlice       `json:"ier,omitempty"`
	IkmR               hexByteSlice       `json:"ikmR"`
	IkmE               hexByteSlice       `json:"ikmE,omitempty"`
	IkmS               hexByteSlice       `json:"ikmS,omitempty"`
	SkRm               hexByteSlice       `json:"skRm"`
	SkEm               hexByteSlice       `json:"skEm,omitempty"`
	SkSm               hexByteSlice       `json:"skSm,omitempty"`
	Psk                hexByteSlice       `json:"psk,omitempty"`
	PskID              hexByteSlice       `json:"psk_id,omitempty"`
	PkSm               hexByteSlice       `json:"pkSm,omitempty"`
	PkRm               hexByteSlice       `json:"pkRm"`
	PkEm               hexByteSlice       `json:"pkEm,omitempty"`
	Enc                hexByteSlice       `json:"enc"`
	SharedSecret       hexByteSlice       `json:"shared_secret"`
	KeyScheduleContext hexByteSlice       `json:"key_schedule_context"`
	Secret             hexByteSlice       `json:"secret"`
	Key                hexByteSlice       `json:"key"`
	BaseNonce          hexByteSlice       `json:"base_nonce"`
	ExporterSecret     hexByteSlice       `json:"exporter_secret"`
	Encryptions        []encryptionVector `json:"encryptions"`
	Exports            []exportVector     `json:"exports"`
}

func TestRFCVector(t *testing.T) {
	t.Parallel()

	root := os.DirFS("./testdata")

	vectorFile, err := root.Open("test-vectors.json.gz")
	require.NoError(t, err)

	gzr, err := gzip.NewReader(vectorFile)
	require.NoError(t, err)

	// Decompress in memory (max 25MB)
	var out bytes.Buffer
	_, err = io.Copy(&out, io.LimitReader(gzr, 25<<20))
	require.NoError(t, err)

	// Decode JSON objects
	var vectors []vector
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&vectors))

	for i, vector := range vectors {
		vector := vector
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			t.Parallel()

			s := New(KEM(vector.KemID), KDF(vector.KdfID), AEAD(vector.AeadID))
			kem, kdf, aead := s.Params()
			if !s.IsValid() {
				t.Skipf("Skipping test with invalid suite params (%x/%x/%x)", kem, kdf, aead)
			}

			sender, receiver := buildSenderAndReceiver(t, &vector, kem, s)
			require.NotNil(t, sender)
			require.NotNil(t, receiver)

			sealer, opener := protocolSetup(t, &vector, sender, receiver, kem, s)
			require.NotNil(t, sealer)
			require.NotNil(t, opener)

			// Restore original type to access private properties.
			csealer, _ := sealer.(*context)
			copener, _ := opener.(*context)

			checkKeyschedule(t, &vector, aead, csealer)
			checkKeyschedule(t, &vector, aead, copener)
			checkEncryptions(t, &vector, csealer, copener)
			checkExports(t, &vector, csealer)
			checkExports(t, &vector, copener)
		})
	}
}

func checkExports(t *testing.T, v *vector, ctx *context) {
	t.Helper()

	for _, ce := range v.Exports {
		out, err := ctx.Export(ce.ExportContext, uint16(ce.ExportLength))
		require.NoError(t, err)
		require.Equal(t, []byte(ce.ExportValue), out)
	}
}

func checkEncryptions(t *testing.T, v *vector, sealer, opener *context) {
	t.Helper()

	for i, ve := range v.Encryptions {
		require.Equal(t, []byte(ve.Nonce), sealer.computeNonce(uint64(i)))
		require.Equal(t, []byte(ve.Nonce), opener.computeNonce(uint64(i)))

		ct, err := sealer.Seal(ve.Plaintext, ve.Aad)
		require.NoError(t, err)

		pt, err := opener.Open(ve.Ciphertext, ve.Aad)
		require.NoError(t, err)

		require.Equal(t, []byte(ve.Plaintext), pt)
		require.Equal(t, []byte(ve.Ciphertext), ct)
	}
}

func checkKeyschedule(t *testing.T, v *vector, aeadID AEAD, ctx *context) {
	t.Helper()

	require.NotNil(t, ctx)
	require.Equal(t, []byte(v.KeyScheduleContext), ctx.keyScheduleCtx)
	require.Equal(t, []byte(v.SharedSecret), ctx.sharedSecret)
	require.Equal(t, []byte(v.Secret), ctx.secret)
	if aeadID != AEAD_EXPORT_ONLY {
		require.Equal(t, []byte(v.Key), ctx.key)
		require.Equal(t, []byte(v.BaseNonce), ctx.baseNonce)
	}
	require.Equal(t, []byte(v.ExporterSecret), ctx.exporterSecret)
}

func buildSenderAndReceiver(t *testing.T, v *vector, kemID KEM, s Suite) (Sender, Receiver) {
	t.Helper()

	scheme := kemID.Scheme()
	// Decode materials
	pkR, err := scheme.DeserializePublicKey(v.PkRm)
	require.NoError(t, err)

	skR, err := scheme.DeserializePrivateKey(v.SkRm)
	require.NoError(t, err)

	sender := s.Sender(pkR, v.Info)
	receiver := s.Receiver(skR, v.Info)

	return sender, receiver
}

func protocolSetup(t *testing.T, v *vector, snd Sender, rcv Receiver, kemID KEM, s Suite) (sealer Sealer, opener Opener) {
	t.Helper()

	var (
		enc                      []byte
		skS                      *ecdh.PrivateKey
		pkS                      *ecdh.PublicKey
		errS, errR, errSK, errPK error
	)

	// Downgrade the type to get access to private functions
	sender := snd.(*sender)
	seedReader := bytes.NewReader(v.IkmE)

	scheme := kemID.Scheme()

	switch v.ModeID {
	case uint8(modeBase):
		enc, sealer, errS = sender.setupBase(seedReader)
		if errS == nil {
			opener, errR = rcv.SetupBase(enc)
		}
	case uint8(modePsk):
		enc, sealer, errS = sender.setupPSK(seedReader, v.Psk, v.PskID)
		if errS == nil {
			opener, errR = rcv.SetupPSK(enc, v.Psk, v.PskID)
		}
	case uint8(modeAuth):
		skS, errSK = scheme.DeserializePrivateKey(v.SkSm)
		if errSK == nil {
			pkS, errPK = scheme.DeserializePublicKey(v.PkSm)
			if errPK == nil {
				enc, sealer, errS = sender.setupAuth(seedReader, skS)
				if errS == nil {
					opener, errR = rcv.SetupAuth(enc, pkS)
				}
			}
		}
	case uint8(modeAuthPsk):
		skS, errSK = scheme.DeserializePrivateKey(v.SkSm)
		if errSK == nil {
			pkS, errPK = scheme.DeserializePublicKey(v.PkSm)
			if errPK == nil {
				enc, sealer, errS = sender.setupAuthPSK(seedReader, v.Psk, v.PskID, skS)
				if errS == nil {
					opener, errR = rcv.SetupAuthPSK(enc, v.Psk, v.PskID, pkS)
				}
			}
		}
	default:
		t.Errorf("unsupported mode %x", v.ModeID)
	}

	require.NoError(t, errS)
	require.NoError(t, errR)
	require.NoError(t, errSK)
	require.NoError(t, errPK)

	return sealer, opener
}
