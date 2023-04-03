package accelerator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// IPv4 + TCP   54 bytes
	frame1 = "0a5114c5bdc500ff80891a0f0800450005dceac3400080061a39ac1f14011d732b8af3e257b9b9ae99e33dd56009501003fdac0b0000"
	frame2 = "0a5114c5bdc500ff80891a0f0800450005dceac4400080061a38ac1f14011d732b8af3e257b9b9ae9f973dd56009501003fd99d60000"
	frame3 = "0a5114c5bdc500ff80891a0f0800450005dceac5400080061a37ac1f14011d732b8af3e257b9b9aea54b3dd56009501003fd4f4e0000"
)

func TestCompressHeader(t *testing.T) {
	frame1b, err := hex.DecodeString(frame1)
	require.NoError(t, err)
	frame2b, err := hex.DecodeString(frame2)
	require.NoError(t, err)
	frame3b, err := hex.DecodeString(frame3)
	require.NoError(t, err)

	output := bytes.NewBuffer(nil)

	w := newCHWriter(output)

	_, err = w.Write(frame1b)
	require.NoError(t, err)
	fmt.Println(output.Len(), output.Bytes())

	_, err = w.Write(frame2b)
	require.NoError(t, err)
	fmt.Println(output.Len(), output.Bytes())

	_, err = w.Write(frame3b)
	require.NoError(t, err)
	fmt.Println(output.Len(), output.Bytes())

	// 13/54

	r := newCHReader(output)

	f := make([]byte, 54)
	_, err = r.Read(f)
	fmt.Println(f)
	require.Equal(t, frame1, hex.EncodeToString(f))

	f = make([]byte, 54)
	_, err = r.Read(f)
	fmt.Println(f)
	require.Equal(t, frame2, hex.EncodeToString(f))

	f = make([]byte, 54)
	_, err = r.Read(f)
	fmt.Println(f)
	require.Equal(t, frame3, hex.EncodeToString(f))

	// 7/76
}
