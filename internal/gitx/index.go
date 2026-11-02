package gitx

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
)

// Index file object modes, in the usual git octal representation.
const (
	ModeTypeMask = 0170000
	ModeDir      = 0040000
	ModeRegular  = 0100644
	ModeExec     = 0100755
	ModeSymlink  = 0120000
	ModeGitlink  = 0160000
)

// IndexEntry is one tracked file from a git index (DIRC) file.
type IndexEntry struct {
	Path  string
	ID    ObjectID
	Mode  uint32
	Stage uint8
	Size  uint32
}

// ParseIndex parses a .git/index file. Versions 2, 3 and 4 are supported.
// The trailing checksum is validated.
func ParseIndex(data []byte) ([]IndexEntry, error) {
	if len(data) < 12+20 {
		return nil, fmt.Errorf("%w: index too short", ErrInvalidObject)
	}
	if string(data[0:4]) != "DIRC" {
		return nil, fmt.Errorf("%w: bad index signature", ErrInvalidObject)
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version < 2 || version > 4 {
		return nil, fmt.Errorf("%w: unsupported index version %d", ErrInvalidObject, version)
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > uint32(len(data)/60) {
		return nil, fmt.Errorf("%w: implausible index entry count %d", ErrInvalidObject, count)
	}
	sum := sha1.Sum(data[:len(data)-20])
	if !bytes.Equal(sum[:], data[len(data)-20:]) {
		return nil, fmt.Errorf("%w: index checksum mismatch", ErrInvalidObject)
	}
	entries := make([]IndexEntry, 0, count)
	off := 12
	prevPath := ""
	for i := uint32(0); i < count; i++ {
		entryStart := off
		if off+62 > len(data)-20 {
			return nil, fmt.Errorf("%w: truncated index entry %d", ErrInvalidObject, i)
		}
		mode := binary.BigEndian.Uint32(data[off+24 : off+28])
		size := binary.BigEndian.Uint32(data[off+36 : off+40])
		var id ObjectID
		copy(id[:], data[off+40:off+60])
		flags := binary.BigEndian.Uint16(data[off+60 : off+62])
		off += 62
		extended := flags&0x4000 != 0
		if extended && version >= 3 {
			if off+2 > len(data)-20 {
				return nil, fmt.Errorf("%w: truncated extended flags", ErrInvalidObject)
			}
			off += 2
		}
		var path string
		if version == 4 {
			strip, n := decodeVarint(data[off : len(data)-20])
			if n == 0 {
				return nil, fmt.Errorf("%w: bad path prefix in entry %d", ErrInvalidObject, i)
			}
			off += n
			nul := bytes.IndexByte(data[off:len(data)-20], 0)
			if nul < 0 {
				return nil, fmt.Errorf("%w: unterminated path in entry %d", ErrInvalidObject, i)
			}
			suffix := string(data[off : off+nul])
			off += nul + 1
			if strip > uint64(len(prevPath)) {
				return nil, fmt.Errorf("%w: path prefix overrun in entry %d", ErrInvalidObject, i)
			}
			path = prevPath[:len(prevPath)-int(strip)] + suffix
		} else {
			nul := bytes.IndexByte(data[off:len(data)-20], 0)
			if nul < 0 {
				return nil, fmt.Errorf("%w: unterminated path in entry %d", ErrInvalidObject, i)
			}
			path = string(data[off : off+nul])
			off += nul + 1
			pad := (8 - (off-entryStart)%8) % 8
			off += pad
		}
		if path == "" {
			return nil, fmt.Errorf("%w: empty path in entry %d", ErrInvalidObject, i)
		}
		prevPath = path
		entries = append(entries, IndexEntry{
			Path:  path,
			ID:    id,
			Mode:  mode,
			Stage: uint8((flags >> 12) & 0x3),
			Size:  size,
		})
	}
	// Remaining bytes are optional extensions; validate their framing so a
	// truncated index does not silently lose entries.
	rest := data[off : len(data)-20]
	for len(rest) > 0 {
		if len(rest) < 8 {
			return nil, fmt.Errorf("%w: truncated index extension", ErrInvalidObject)
		}
		size := binary.BigEndian.Uint32(rest[4:8])
		if int(size) > len(rest)-8 {
			return nil, fmt.Errorf("%w: truncated index extension body", ErrInvalidObject)
		}
		rest = rest[8+size:]
	}
	return entries, nil
}

// decodeVarint decodes git's offset encoding used by index v4 path prefixes
// and pack OFS_DELTA offsets.
func decodeVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	val := uint64(c & 0x7f)
	i := 0
	for c&0x80 != 0 {
		i++
		if i >= len(b) {
			return 0, 0
		}
		c = b[i]
		val = ((val + 1) << 7) | uint64(c&0x7f)
	}
	return val, i + 1
}

// ModeString renders a git mode the way git does.
func ModeString(mode uint32) string {
	switch mode & ModeTypeMask {
	case ModeDir:
		return "040000"
	case ModeRegular:
		return "100644"
	case ModeExec:
		return "100755"
	case ModeSymlink:
		return "120000"
	case ModeGitlink:
		return "160000"
	}
	return fmt.Sprintf("%06o", mode)
}

// ModeIsSymlink reports whether the entry is a symlink.
func ModeIsSymlink(mode uint32) bool { return mode&ModeTypeMask == ModeSymlink }

// ModeIsGitlink reports whether the entry is a submodule reference.
func ModeIsGitlink(mode uint32) bool { return mode&ModeTypeMask == ModeGitlink }

// ModeIsExec reports whether the entry is an executable regular file.
func ModeIsExec(mode uint32) bool { return mode&ModeTypeMask == ModeExec }

// CleanIndexPath normalises an index path and rejects traversal attempts.
func CleanIndexPath(p string) (string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	parts := make([]string, 0, 8)
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("path traversal in %q", p)
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("empty path after clean: %q", p)
	}
	return strings.Join(parts, "/"), nil
}
