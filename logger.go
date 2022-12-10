package accelerator

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

type logger struct {
	logger *log.Logger
	file   *os.File
}

func newLogger(path string) (*logger, error) {
	if path == "" {
		lg := log.New(os.Stdout, "", log.LstdFlags)
		return &logger{logger: lg}, nil
	}
	dir := filepath.Dir(path)
	if dir != "." {
		err := os.MkdirAll(dir, 0750)
		if err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0600) // #nosec
	if err != nil {
		return nil, err
	}
	lg := log.New(io.MultiWriter(os.Stdout, file), "", log.LstdFlags)
	return &logger{logger: lg, file: file}, nil
}

func (l *logger) Info(v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[info]")
	_, _ = fmt.Fprintln(buf, v...)
	l.logger.Println(buf)
}

func (l *logger) Infof(format string, v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[info]")
	_, _ = fmt.Fprintf(buf, format, v...)
	l.logger.Println(buf)
}

func (l *logger) Warning(v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[warning]")
	_, _ = fmt.Fprintln(buf, v...)
	l.logger.Println(buf)
}

func (l *logger) Warningf(format string, v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[warning]")
	_, _ = fmt.Fprintf(buf, format, v...)
	l.logger.Println(buf)
}

func (l *logger) Error(v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[error]")
	_, _ = fmt.Fprintln(buf, v...)
	l.logger.Println(buf)
}

func (l *logger) Errorf(format string, v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[error]")
	_, _ = fmt.Fprintf(buf, format, v...)
	l.logger.Println(buf)
}

func (l *logger) Fatal(v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[fatal]")
	_, _ = fmt.Fprintln(buf, v...)
	l.logger.Println(buf)
}

func (l *logger) Fatalf(format string, v ...interface{}) {
	buf := bytes.NewBuffer(make([]byte, 64))
	buf.WriteString("[fatal]")
	_, _ = fmt.Fprintf(buf, format, v...)
	l.logger.Println(buf)
}

func (l *logger) Close() error {
	var err error
	if l.file != nil {
		err = l.file.Close()
		if err != nil {
			l.Error("failed to close log file:", err)
		}
	}
	l.logger.SetOutput(io.Discard)
	return err
}
