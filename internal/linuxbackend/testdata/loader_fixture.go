package linuxos

import (
	"os"
	"testing"
)

func QualificationLoaderReader(t *testing.T, root string) PathReader {
	fixtureDir(t, root)
	return PathReader{owner: uint32(os.Getuid()), group: uint32(os.Getgid()), anchor: root}
}
