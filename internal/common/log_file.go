package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	defaultLogMaxSize = 10 * 1024 * 1024
	defaultLogBackups = 5
)

type rotatingFileWriter struct {
	path       string
	maxSize    int64
	maxBackups int
	file       *os.File
}

func setLogFile(path string) error {
	writer, err := newRotatingFileWriter(path, defaultLogMaxSize, defaultLogBackups)
	if err != nil {
		return err
	}

	logMutex.Lock()
	if logCloser != nil {
		_ = logCloser.Close()
	}
	logOutput = writer
	logCloser = writer
	logMutex.Unlock()
	return nil
}

func newRotatingFileWriter(path string, maxSize int64, maxBackups int) (*rotatingFileWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("empty log path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &rotatingFileWriter{
		path:       path,
		maxSize:    maxSize,
		maxBackups: maxBackups,
		file:       file,
	}, nil
}

func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	if w.maxSize > 0 {
		if info, err := w.file.Stat(); err == nil && info.Size()+int64(len(p)) > w.maxSize {
			if err := w.rotate(); err != nil {
				return 0, err
			}
		}
	}
	return w.file.Write(p)
}

func (w *rotatingFileWriter) Close() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingFileWriter) open() error {
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.file = file
	return nil
}

func (w *rotatingFileWriter) rotate() error {
	if err := w.Close(); err != nil {
		return err
	}

	for i := w.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Remove(dst)
			_ = os.Rename(src, dst)
		}
	}
	if w.maxBackups > 0 {
		first := fmt.Sprintf("%s.1", w.path)
		_ = os.Remove(first)
		if _, err := os.Stat(w.path); err == nil {
			_ = os.Rename(w.path, first)
		}
	} else {
		_ = os.Remove(w.path)
	}

	return w.open()
}

var _ io.WriteCloser = (*rotatingFileWriter)(nil)
