package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEllipticKey(t *testing.T) {
	t.Run("ECurve256", func(t *testing.T) {
		t.Run("generating keys", func(t *testing.T) {
			_, err := GenerateKey(ECurve256)

			assert.NoError(t, err)
		})
	})
}
