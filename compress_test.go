package accelerator

import (
	"bytes"
	"testing"

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

	testIPv4TCPFrame1 = []byte(testEthernet1 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrame2 = []byte(testEthernet1 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrame3 = []byte(testEthernet1 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrame4 = []byte(testEthernet1 + testIPv4H2 + testTCPH2)
	testIPv4TCPFrame5 = []byte(testEthernet2 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrame6 = []byte(testEthernet2 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrame7 = []byte(testEthernet2 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrame8 = []byte(testEthernet2 + testIPv4H2 + testTCPH2)

	testIPv4UDPFrame1 = []byte(testEthernet1 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrame2 = []byte(testEthernet1 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrame3 = []byte(testEthernet1 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrame4 = []byte(testEthernet1 + testIPv4H4 + testUDPH2)
	testIPv4UDPFrame5 = []byte(testEthernet2 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrame6 = []byte(testEthernet2 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrame7 = []byte(testEthernet2 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrame8 = []byte(testEthernet2 + testIPv4H4 + testUDPH2)

	testIPv6TCPFrame1 = []byte(testEthernet3 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrame2 = []byte(testEthernet3 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrame3 = []byte(testEthernet3 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrame4 = []byte(testEthernet3 + testIPv6H2 + testTCPH2)
	testIPv6TCPFrame5 = []byte(testEthernet4 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrame6 = []byte(testEthernet4 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrame7 = []byte(testEthernet4 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrame8 = []byte(testEthernet4 + testIPv6H2 + testTCPH2)

	testIPv6UDPFrame1 = []byte(testEthernet3 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrame2 = []byte(testEthernet3 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrame3 = []byte(testEthernet3 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrame4 = []byte(testEthernet3 + testIPv6H4 + testUDPH2)
	testIPv6UDPFrame5 = []byte(testEthernet4 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrame6 = []byte(testEthernet4 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrame7 = []byte(testEthernet4 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrame8 = []byte(testEthernet4 + testIPv6H4 + testUDPH2)
)

func TestCFHWriter(t *testing.T) {
	t.Run("common", func(t *testing.T) {

	})
}

func TestCFHWriter_fastSearchDictionary(t *testing.T) {
	t.Run("IPv4 TCP", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 1024))

		w := newCFHWriter(output)

		n, err := w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

	})

	t.Run("IPv4 UDP", func(t *testing.T) {

	})

	t.Run("IPv6 TCP", func(t *testing.T) {

	})

	t.Run("IPv6 UDP", func(t *testing.T) {

	})
}

func TestCFHWriter_slowSearchDictionary(t *testing.T) {

}
