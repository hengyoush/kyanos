package loader

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/smira/go-xz"
	"io"
	"os"
	"strings"
)

func saveDataToFile(data []byte, targetPath string) error {
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("save data to %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, targetPath, err)
	}
	return nil
}

func decompressXzReader(src io.Reader) (data []byte, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err = fmt.Errorf("reading XZ file panicked: %s", r)
	}()

	xzReader, err := xz.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("xz decompress: %w", err)
	}

	tarReader := tar.NewReader(xzReader)
	btfBuffer := bytes.NewBuffer([]byte{})
outer:
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read entry from tarball: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			if strings.HasSuffix(hdr.Name, ".btf") {
				if _, err := io.Copy(btfBuffer, tarReader); err != nil {
					return nil, fmt.Errorf("uncompress file %s: %w", hdr.Name, err)
				}
				break outer
			}
		}
	}

	return btfBuffer.Bytes(), nil
}
