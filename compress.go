package accelerator

import (
	"bytes"
	"errors"
	"io"
)

type chWriter struct {
	writer   io.Writer
	template []byte
	buf      bytes.Buffer
}

func newCHWriter(w io.Writer) io.Writer {
	return &chWriter{writer: w}
}

func (w *chWriter) Write(b []byte) (int, error) {
	if len(b) > 255 {
		return 0, errors.New("too large buffer")
	}
	if w.template == nil {
		w.template = make([]byte, len(b))
		copy(w.template, b)
		_, err := w.writer.Write([]byte{byte(len(b))})
		if err != nil {
			return 0, err
		}
		_, err = w.writer.Write(w.template)
		if err != nil {
			return 0, err
		}
		return len(w.template), nil
	}
	w.buf.Reset()
	// compare the new data with the latest template
	for i := 0; i < len(w.template); i++ {
		if w.template[i] == b[i] {
			continue
		}
		w.buf.WriteByte(byte(i))
		w.buf.WriteByte(b[i])
		// update template
		w.template[i] = b[i]
	}
	// write changed data number
	_, err := w.writer.Write([]byte{byte(w.buf.Len() / 2)})
	if err != nil {
		return 0, err
	}
	// write changed data
	_, err = w.writer.Write(w.buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type chReader struct {
	reader   io.Reader
	template []byte
	buf      []byte
}

func newCHReader(r io.Reader) io.Reader {
	return &chReader{
		reader: r,
		buf:    make([]byte, 2),
	}
}

func (r *chReader) Read(b []byte) (int, error) {
	if len(b) > 255 {
		return 0, errors.New("too large buffer")
	}
	if r.template == nil {
		size := make([]byte, 1)
		_, err := io.ReadFull(r.reader, size)
		if err != nil {
			return 0, err
		}
		r.template = make([]byte, size[0])
		_, err = io.ReadFull(r.reader, r.template)
		if err != nil {
			return 0, err
		}
		copy(b, r.template)
		return len(b), nil
	}
	// read changed data number
	_, err := io.ReadFull(r.reader, r.buf[:1])
	if err != nil {
		return 0, err
	}
	num := int(r.buf[0])
	for i := 0; i < num; i++ {
		_, err = io.ReadFull(r.reader, r.buf)
		if err != nil {
			return 0, err
		}
		r.template[r.buf[0]] = r.buf[1]
	}
	copy(b, r.template)
	return len(b), nil
}
