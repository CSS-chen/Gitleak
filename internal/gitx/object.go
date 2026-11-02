// Package gitx implements the subset of the Git object model required to
// reconstruct a repository from an exposed .git directory served over HTTP.
package gitx

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Git object types.
const (
	TypeCommit = "commit"
	TypeTree   = "tree"
	TypeBlob   = "blob"
	TypeTag    = "tag"
)

// Limits used while decoding untrusted input.
const (
	// MaxObjectSize bounds a single decoded object (128 MiB).
	MaxObjectSize = 128 << 20
	// MaxZlibExpansion bounds decoded data from a raw zlib stream.
	MaxZlibExpansion = 256 << 20
)

var (
	// ErrObjectTooLarge is returned when a decoded object exceeds the limit.
	ErrObjectTooLarge = errors.New("gitx: object too large")
	// ErrInvalidObject is returned when bytes are not a valid git object.
	ErrInvalidObject = errors.New("gitx: invalid git object")
)

// ObjectID is a SHA-1 object name.
type ObjectID [20]byte

// String returns the 40 character lowercase hex representation.
func (o ObjectID) String() string { return hex.EncodeToString(o[:]) }

// IsZero reports whether the id is all zeroes.
func (o ObjectID) IsZero() bool { return o == ObjectID{} }

// ParseObjectID parses a 40 character hex object name.
func ParseObjectID(s string) (ObjectID, error) {
	var id ObjectID
	s = strings.TrimSpace(s)
	if len(s) != 40 {
		return id, fmt.Errorf("gitx: invalid object id %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("gitx: invalid object id %q: %w", s, err)
	}
	copy(id[:], b)
	return id, nil
}

// Object is a decoded git object.
type Object struct {
	Type string
	Data []byte
}

// Resolver resolves a stored object by id.
type Resolver interface {
	Get(id ObjectID) (Object, error)
}

// HashObject computes the canonical git object id of typ+data.
func HashObject(typ string, data []byte) ObjectID {
	h := sha1.New()
	h.Write([]byte(typ))
	h.Write([]byte(" "))
	h.Write([]byte(strconv.Itoa(len(data))))
	h.Write([]byte{0})
	h.Write(data)
	var id ObjectID
	copy(id[:], h.Sum(nil))
	return id
}

// DecodeZlib inflates a zlib stream with a hard output limit.
func DecodeZlib(raw []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidObject, err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, MaxZlibExpansion+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidObject, err)
	}
	if len(out) > MaxZlibExpansion {
		return nil, ErrObjectTooLarge
	}
	return out, nil
}

// DecodeLooseObject decodes an inflated-then-decompressed loose object.
func DecodeLooseObject(raw []byte) (string, []byte, error) {
	dec, err := DecodeZlib(raw)
	if err != nil {
		return "", nil, err
	}
	nul := bytes.IndexByte(dec, 0)
	if nul <= 0 || nul > 64 {
		return "", nil, fmt.Errorf("%w: bad object header", ErrInvalidObject)
	}
	header := string(dec[:nul])
	typ, sizeStr, ok := strings.Cut(header, " ")
	if !ok {
		return "", nil, fmt.Errorf("%w: bad object header", ErrInvalidObject)
	}
	switch typ {
	case TypeCommit, TypeTree, TypeBlob, TypeTag:
	default:
		return "", nil, fmt.Errorf("%w: unknown object type %q", ErrInvalidObject, typ)
	}
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || size < 0 {
		return "", nil, fmt.Errorf("%w: bad object size %q", ErrInvalidObject, sizeStr)
	}
	if size > MaxObjectSize {
		return "", nil, ErrObjectTooLarge
	}
	body := dec[nul+1:]
	if int64(len(body)) != size {
		return "", nil, fmt.Errorf("%w: size mismatch (header %d, got %d)", ErrInvalidObject, size, len(body))
	}
	return typ, body, nil
}

// EncodeLooseObject builds the zlib compressed on-disk form of an object.
func EncodeLooseObject(typ string, data []byte) ([]byte, error) {
	switch typ {
	case TypeCommit, TypeTree, TypeBlob, TypeTag:
	default:
		return nil, fmt.Errorf("%w: unknown object type %q", ErrInvalidObject, typ)
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := fmt.Fprintf(zw, "%s %d", typ, len(data)); err != nil {
		return nil, err
	}
	if _, err := zw.Write([]byte{0}); err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeObject parses a decoded object body according to its type.
func DecodeObject(typ string, data []byte) (Object, error) {
	switch typ {
	case TypeCommit, TypeTree, TypeBlob, TypeTag:
		return Object{Type: typ, Data: data}, nil
	default:
		return Object{}, fmt.Errorf("%w: unknown object type %q", ErrInvalidObject, typ)
	}
}

// FormatObjectHeader is exposed for tests.
func FormatObjectHeader(typ string, size int) string {
	return typ + " " + strconv.Itoa(size)
}
