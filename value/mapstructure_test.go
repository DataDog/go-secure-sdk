package value

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
)

func TestMapstructure_Decode(t *testing.T) {
	type secret struct {
		Redacted RedactedString `mapstructure:"redacted"`
	}

	out := &secret{}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.TextUnmarshallerHookFunc(),
		),
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		Result:           out,
	})
	require.NoError(t, err)

	err = dec.Decode(map[string]interface{}{
		"redacted": "protected",
	})
	require.NoError(t, err)
}
