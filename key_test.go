package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateECKey(t *testing.T) {
	t.Run("CurveP256", func(t *testing.T) {
		_, err := GeneratePrivateECKey(CurveP256)

		assert.NoError(t, err)
	})

	t.Run("CurveP521", func(t *testing.T) {
		_, err := GeneratePrivateECKey(CurveP521)

		assert.NoError(t, err)
	})
}
