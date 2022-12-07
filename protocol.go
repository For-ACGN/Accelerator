package accelerator

// +--------------+-------------+
// | size(uint16) |  frame data |
// +--------------+-------------+
// |   2 bytes    |     var     |
// +--------------+-------------+

const (
	maxPacketSize   = 32 * 1024 // 32 KiB (size+data)
	frameHeaderSize = 2         // uint16, use big endian
)

type packet struct {
	buf  []byte
	size int
}

func newPacket() *packet {
	return &packet{
		buf:  make([]byte, maxPacketSize),
		size: 0,
	}
}
