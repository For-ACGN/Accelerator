package accelerator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(nil)
	require.NoError(t, err)
	_ = client.Close()
}
