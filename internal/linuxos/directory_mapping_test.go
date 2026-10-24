//go:build linux

package linuxos

import (
	"debug/elf"
	"testing"
)

// The common mapping boundary rejects unloaded, partial, overlapping, overflowing
// and out-of-file ranges; the adjacent single complete mapping remains valid.
func TestDirectoryLoaderFileRange(t *testing.T) {
	for _, mode := range []string{"valid", "unmapped", "partial", "overlap", "file-overflow", "address-overflow", "zero"} {
		t.Run(mode, func(t *testing.T) {
			load := &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 8, Vaddr: 100, Filesz: 32, Memsz: 40}}
			object := &elf.File{Progs: []*elf.Prog{load}}
			address, size := uint64(108), uint64(8)
			switch mode {
			case "unmapped":
				address = 150
			case "partial":
				address = 128
			case "overlap":
				object.Progs = append(object.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 40, Vaddr: 112, Filesz: 8, Memsz: 8}})
			case "file-overflow":
				load.Off = 63
			case "address-overflow":
				address = ^uint64(0) - 1
			case "zero":
				size = 0
			}
			off, ok := loaderFileRange(object, make([]byte, 64), address, size)
			if mode == "valid" {
				if !ok || off != 16 {
					t.Fatal(off, ok)
				}
			} else if ok {
				t.Fatal("invalid mapping admitted", off)
			}
		})
	}
}
