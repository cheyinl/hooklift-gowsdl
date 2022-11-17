package soap

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"time"
)

func makeSecureId(prefixText string) string {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
	io.ReadFull(rand.Reader, buf[8:])
	return prefixText + hex.EncodeToString(buf)
}
