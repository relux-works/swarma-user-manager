//go:build linux

package linuxos

import (
	"bytes"
	"debug/elf"
	"io"
	"path/filepath"
	"strings"
)

// loaderDependencies reads PT_DYNAMIC and maps DT_STRTAB through PT_LOAD, as
// the runtime loader does. Optional sections cannot erase or redirect that view.
func loaderDependencies(object *elf.File, reader io.ReaderAt, fileSize uint64) ([]string, []string, error) {
	fail := func() ([]string, []string, error) {
		return nil, nil, refusal("directory_unknown", "closure_loader_view", nil)
	}
	var dynamic *elf.Prog
	for _, p := range object.Progs {
		if p.Type == elf.PT_DYNAMIC {
			if dynamic != nil {
				return fail()
			}
			dynamic = p
		}
	}
	sections := []*elf.Section{}
	for _, s := range object.Sections {
		if s.Type == elf.SHT_DYNAMIC {
			sections = append(sections, s)
		}
	}
	if dynamic == nil {
		if len(sections) != 0 {
			return fail()
		}
		return []string{}, []string{}, nil
	}
	width := uint64(16)
	if object.Class == elf.ELFCLASS32 {
		width = 8
	} else if object.Class != elf.ELFCLASS64 {
		return fail()
	}
	if dynamic.Filesz == 0 || dynamic.Filesz%width != 0 || dynamic.Off > fileSize || dynamic.Filesz > fileSize-dynamic.Off || dynamic.Filesz > dynamic.Memsz {
		return fail()
	}
	mappedDynamic, mapped := loaderFileRangeSize(object, fileSize, dynamic.Vaddr, dynamic.Filesz)
	if !mapped || mappedDynamic != dynamic.Off {
		return fail()
	}
	if len(object.Sections) > 0 && len(sections) != 1 {
		return fail()
	}
	for _, s := range sections {
		if s.Addr != dynamic.Vaddr || s.Offset != dynamic.Off || s.Size != dynamic.Filesz || s.Entsize != width {
			return fail()
		}
	}
	if dynamic.Filesz > 1<<20 {
		return fail()
	}
	dyn := make([]byte, dynamic.Filesz)
	if _, e := reader.ReadAt(dyn, int64(dynamic.Off)); e != nil {
		return fail()
	}
	vals := map[elf.DynTag][]uint64{}
	ended := false
	for off := uint64(0); off < uint64(len(dyn)); off += width {
		var tag elf.DynTag
		var value uint64
		if width == 16 {
			tag = elf.DynTag(object.ByteOrder.Uint64(dyn[off : off+8]))
			value = object.ByteOrder.Uint64(dyn[off+8 : off+16])
		} else {
			tag = elf.DynTag(object.ByteOrder.Uint32(dyn[off : off+4]))
			value = uint64(object.ByteOrder.Uint32(dyn[off+4 : off+8]))
		}
		if ended {
			if tag != elf.DT_NULL || value != 0 {
				return fail()
			}
			continue
		}
		if tag == elf.DT_NULL {
			ended = true
			continue
		}
		vals[tag] = append(vals[tag], value)
	}
	if !ended {
		return fail()
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_FILTER, elf.DT_AUXILIARY, elf.DT_AUDIT, elf.DT_DEPAUDIT} {
		if len(vals[tag]) != 0 {
			return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
		}
	}
	if len(vals[elf.DT_STRTAB]) != 1 || len(vals[elf.DT_STRSZ]) != 1 {
		return fail()
	}
	address, size := vals[elf.DT_STRTAB][0], vals[elf.DT_STRSZ][0]
	if size == 0 || size > fileSize || size > 8<<20 {
		return fail()
	}
	tableOffset, mapped := loaderFileRangeSize(object, fileSize, address, size)
	if !mapped {
		return fail()
	}
	table := make([]byte, size)
	if _, e := reader.ReadAt(table, int64(tableOffset)); e != nil {
		return fail()
	}
	for _, s := range sections {
		if int(s.Link) >= len(object.Sections) {
			return fail()
		}
		str := object.Sections[s.Link]
		if str.Type != elf.SHT_STRTAB || str.Addr != address || str.Offset != tableOffset || str.Size != size {
			return fail()
		}
		if str.Offset > fileSize || str.Size > fileSize-str.Offset {
			return fail()
		}
	}
	deps := []string{}
	for _, offset := range vals[elf.DT_NEEDED] {
		if offset >= uint64(len(table)) {
			return fail()
		}
		end := bytes.IndexByte(table[offset:], 0)
		if end <= 0 {
			return fail()
		}
		deps = append(deps, string(table[offset:offset+uint64(end)]))
	}
	runpath := []string{}
	if len(vals[elf.DT_RUNPATH]) > 1 {
		return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
	}
	if len(vals[elf.DT_RUNPATH]) == 1 {
		off := vals[elf.DT_RUNPATH][0]
		if off >= uint64(len(table)) {
			return fail()
		}
		end := bytes.IndexByte(table[off:], 0)
		if end < 1 {
			return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
		}
		runpath = strings.Split(string(table[off:off+uint64(end)]), ":")
		if len(runpath) > 32 {
			return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
		}
		for _, path := range runpath {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "$;\x00\n\r") {
				return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
			}
		}
	}
	// glibc fillin_rpath removes repeated directory spellings. Preserve the
	// first occurrence so name/scope evidence follows the same search order.
	unique := []string{}
	seenDirs := map[string]bool{}
	for _, dir := range runpath {
		if !seenDirs[dir] {
			unique = append(unique, dir)
			seenDirs[dir] = true
		}
	}
	runpath = unique
	for _, flags := range vals[elf.DT_FLAGS_1] {
		if flags&0x800 != 0 {
			return nil, nil, refusal("directory_unknown", "closure_loader_syntax", nil)
		}
	} // DF_1_NODEFLIB
	return deps, runpath, nil
}

// loaderFileRange admits exactly one file-backed mapping of the entire consumed
// virtual range. A second mapping touching even part of it is ambiguous.
func loaderFileRangeSize(object *elf.File, fileSize uint64, address, size uint64) (uint64, bool) {
	if size == 0 || address > ^uint64(0)-size {
		return 0, false
	}
	end := address + size
	count := 0
	var offset uint64
	for _, p := range object.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Filesz > p.Memsz || p.Vaddr > ^uint64(0)-p.Memsz || p.Off > fileSize || p.Filesz > fileSize-p.Off {
			return 0, false
		}
		if address >= p.Vaddr+p.Memsz || end <= p.Vaddr {
			continue
		}
		count++
		if count != 1 || address < p.Vaddr {
			return 0, false
		}
		delta := address - p.Vaddr
		if delta > p.Filesz || size > p.Filesz-delta {
			return 0, false
		}
		offset = p.Off + delta
	}
	return offset, count == 1
}

// Retain the existing byte-slice helper for bounded mapping fixtures.
func loaderFileRange(object *elf.File, data []byte, address, size uint64) (uint64, bool) {
	return loaderFileRangeSize(object, uint64(len(data)), address, size)
}
