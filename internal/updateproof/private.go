package updateproof

import (
	"errors"
	"io"
	"os"
)

func privateDirectory(pattern string) (string, error) {
	directory, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return "", errors.Join(err, os.RemoveAll(directory))
	}
	return directory, nil
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = file.Chmod(0600)
	if err == nil {
		var written int
		written, err = file.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
	}
	return errors.Join(err, file.Close())
}
