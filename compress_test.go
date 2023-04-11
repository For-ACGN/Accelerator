package accelerator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	testEthernet1 = "d8ba1192c572d8af159ac5d10800" // IPv4
	testEthernet2 = "d8ba1192c572d8af159ac5d20800" // IPv4
	testEthernet3 = "d8ba1192c572d8af159ac5d386dd" // IPv6
	testEthernet4 = "d8ba1192c572d8af159ac5d486dd" // IPv6

	testIPv4H1 = "450405c8574d40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H2 = "450405c8574e40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H3 = "450405c8575d40003711b63514983c5fc0a81f0a" // UDP
	testIPv4H4 = "450405c8575e40003711b63514983c5fc0a81f0a" // UDP

	testIPv6H1 = "6043670805a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // TCP
	testIPv6H2 = "6043670805a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f2" // TCP
	testIPv6H3 = "6043670805a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f3" // UDP
	testIPv6H4 = "6043670805a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f4" // UDP

	testTCPH1 = "01bbebd71561ddfc151e1385501003d037390000"
	testTCPH2 = "01bbebd71661ddfc151e1385501003d037390000"

	testUDPH1 = "fb7b003500385f66"
	testUDPH2 = "fb7b003600385f66"

	testIPv4TCPFrame10 = testEthernet1 + testIPv4H1 + testTCPH1
	testIPv4TCPFrame11 = testEthernet1 + testIPv4H1 + testTCPH2
	testIPv4TCPFrame12 = testEthernet1 + testIPv4H2 + testTCPH1
	testIPv4TCPFrame13 = testEthernet1 + testIPv4H2 + testTCPH2
	testIPv4TCPFrame14 = testEthernet2 + testIPv4H1 + testTCPH1
	testIPv4TCPFrame15 = testEthernet2 + testIPv4H1 + testTCPH2
	testIPv4TCPFrame16 = testEthernet2 + testIPv4H2 + testTCPH1
	testIPv4TCPFrame17 = testEthernet2 + testIPv4H2 + testTCPH2

	testIPv4UDPFrame20 = testEthernet1 + testIPv4H3 + testUDPH1
	testIPv4UDPFrame21 = testEthernet1 + testIPv4H3 + testUDPH2
	testIPv4UDPFrame22 = testEthernet1 + testIPv4H4 + testUDPH1
	testIPv4UDPFrame23 = testEthernet1 + testIPv4H4 + testUDPH2
	testIPv4UDPFrame24 = testEthernet2 + testIPv4H3 + testUDPH1
	testIPv4UDPFrame25 = testEthernet2 + testIPv4H3 + testUDPH2
	testIPv4UDPFrame26 = testEthernet2 + testIPv4H4 + testUDPH1
	testIPv4UDPFrame27 = testEthernet2 + testIPv4H4 + testUDPH2

	testIPv6TCPFrame10 = testEthernet3 + testIPv6H1 + testTCPH1
	testIPv6TCPFrame11 = testEthernet3 + testIPv6H1 + testTCPH2
	testIPv6TCPFrame12 = testEthernet3 + testIPv6H2 + testTCPH1
	testIPv6TCPFrame13 = testEthernet3 + testIPv6H2 + testTCPH2
	testIPv6TCPFrame14 = testEthernet4 + testIPv6H1 + testTCPH1
	testIPv6TCPFrame15 = testEthernet4 + testIPv6H1 + testTCPH2
	testIPv6TCPFrame16 = testEthernet4 + testIPv6H2 + testTCPH1
	testIPv6TCPFrame17 = testEthernet4 + testIPv6H2 + testTCPH2

	testIPv6UDPFrame20 = testEthernet3 + testIPv6H3 + testUDPH1
	testIPv6UDPFrame21 = testEthernet3 + testIPv6H3 + testUDPH2
	testIPv6UDPFrame22 = testEthernet3 + testIPv6H4 + testUDPH1
	testIPv6UDPFrame23 = testEthernet3 + testIPv6H4 + testUDPH2
	testIPv6UDPFrame24 = testEthernet4 + testIPv6H3 + testUDPH1
	testIPv6UDPFrame25 = testEthernet4 + testIPv6H3 + testUDPH2
	testIPv6UDPFrame26 = testEthernet4 + testIPv6H4 + testUDPH1
	testIPv6UDPFrame27 = testEthernet4 + testIPv6H4 + testUDPH2
)

func TestCfhWriter(t *testing.T) {
	t.Run("common", func(t *testing.T) {

	})
}

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

	output := bytes.NewBuffer(make([]byte, 0, 1024*1024))

	w := newCFHWriter(output)

	now := time.Now()

	for i := 0; i < 7000; i++ {
		_, err = w.Write(frame1b)
		checkError(t, err)
		// fmt.Println(output.Len(), output.Bytes())

		_, err = w.Write(frame2b)
		checkError(t, err)
		// fmt.Println(output.Len(), output.Bytes())

		_, err = w.Write(frame3b)
		checkError(t, err)
		// fmt.Println(output.Len(), output.Bytes())

		frame1b[34] = byte(i)
		frame2b[34] = byte(i)
		frame3b[34] = byte(i)
	}

	fmt.Println(time.Since(now).Milliseconds(), "ms")

	fmt.Println(output.Len())
	// fmt.Println(output.Bytes())
	// 13/54

	r := newCFHReader(output)

	now = time.Now()
	f := make([]byte, 54)

	for i := 0; i < 7000; i++ {
		_, err = r.Read(f)
		checkError(t, err)
		// fmt.Println(f)
		// require.Equal(t, frame1, hex.EncodeToString(f))

		_, err = r.Read(f)
		checkError(t, err)
		// fmt.Println(f)
		// require.Equal(t, frame2, hex.EncodeToString(f))

		_, err = r.Read(f)
		checkError(t, err)
		// fmt.Println(f)
		// require.Equal(t, frame3, hex.EncodeToString(f))
	}

	fmt.Println(time.Since(now).Milliseconds(), "ms")

	// 7/76
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}

}

func TestCompressBenchmark(t *testing.T) {
	var bb [][]byte
	bb = make([][]byte, 256)
	for i := 0; i < len(bb); i++ {
		bb[i] = make([]byte, 54)
		bb[i][16] = 159
	}

	src := make([]byte, 54)

	now := time.Now()

	var c int
	for i := 0; i < 22369; i++ {
		for j := 0; j < len(bb); j++ {
			bs := bb[j]

			bytes.Equal(bs[:12], src[:12])
			bytes.Equal(bs[26:30+4+2+2], src[26:30+4+2+2])

			// bytes.Equal(bs[:14], src[:14])

			// bytes.Equal(bs[4:8], src[4:8])
			// bytes.Equal(bs[8:12], src[8:12])
			// bytes.Equal(bs[12:16], src[12:16])

			// bytes.Equal(bs[16:20], src[16:20])
			// bytes.Equal(bs[20:24], src[20:24])
			// bytes.Equal(bs[24:28], src[24:28])
			// bytes.Equal(bs[28:32], src[28:32])

			// for k := 0; k < len(bs); k++ {
			// 	if bs[k] != src[k] {
			// 		c++
			// 	}
			// }
		}
	}

	fmt.Println(time.Since(now).Milliseconds(), "ms")

	fmt.Println(c)
}
