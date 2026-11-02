package gitx

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// This file implements reading git pack files: the version 1 and version 2
// pack indexes (.idx) and the pack file itself (.pack), including OFS_DELTA
// and REF_DELTA object bodies.

const (
	// idxMagic is the 4 byte signature at the start of a version 2 pack index.
	idxMagic = 0xFF744F63

	idxFanoutSize  = 256 * 4
	idxTrailerSize = 20 + 20 // pack checksum + index checksum
	idxV2HeaderLen = 4 + 4   // magic + version

	// packHeaderLen is the size of the pack file header ("PACK", version,
	// object count), which is also the offset of the first object entry.
	packHeaderLen = 12

	// Object types as encoded in a pack object entry header.
	packTypeCommit   = 1
	packTypeTree     = 2
	packTypeBlob     = 3
	packTypeTag      = 4
	packTypeOFSDelta = 6
	packTypeREFDelta = 7

	// maxPackObjectSize bounds the decoded size of one object read from a
	// pack. The pack format itself allows larger objects, but this reader is
	// deliberately bounded because packs may be attacker controlled.
	maxPackObjectSize = 256 << 20

	// maxPackDeltaDepth bounds how many delta levels are followed for a single
	// object.
	maxPackDeltaDepth = 64

	// Cache limits for resolved objects. Objects larger than the byte budget
	// simply are not cached.
	maxPackCacheEntries = 1 << 16
	maxPackCacheBytes   = 64 << 20
)

const packMaxUint64 uint64 = 1<<64 - 1

var (
	// errPackIndexCorrupt reports a malformed or truncated pack index.
	errPackIndexCorrupt = errors.New("gitx: corrupt pack index")
	// errPackCorrupt reports a malformed or truncated pack file.
	errPackCorrupt = errors.New("gitx: corrupt pack")
	// errPackObjectNotFound reports an object id that is not present in the
	// pack index backing a PackFile.
	errPackObjectNotFound = errors.New("gitx: object not found in pack")
)

// PackIndex is a parsed git pack index (.idx), either version 1 or version 2.
// It maps object ids to byte offsets in the matching pack file.
type PackIndex struct {
	version int
	ids     []ObjectID // sorted ascending
	offsets []uint64   // parallel to ids
}

// ParsePackIndex parses a git pack index held in data. Both version 1 and
// version 2 indexes are supported. The returned index does not reference data;
// every needed value is copied out.
//
// Malformed, truncated or checksum-mismatched input yields an error and never
// panics.
func ParsePackIndex(data []byte) (*PackIndex, error) {
	if len(data) < idxV2HeaderLen {
		return nil, fmt.Errorf("%w: file is %d bytes", errPackIndexCorrupt, len(data))
	}
	if binary.BigEndian.Uint32(data[0:4]) == idxMagic {
		return parsePackIndexV2(data)
	}
	return parsePackIndexV1(data)
}

func parsePackIndexV2(data []byte) (*PackIndex, error) {
	if len(data) < idxV2HeaderLen+idxFanoutSize+idxTrailerSize {
		return nil, fmt.Errorf("%w: version 2 index is %d bytes, need at least %d", errPackIndexCorrupt, len(data), idxV2HeaderLen+idxFanoutSize+idxTrailerSize)
	}
	if v := binary.BigEndian.Uint32(data[4:8]); v != 2 {
		return nil, fmt.Errorf("%w: unsupported index version %d", errPackIndexCorrupt, v)
	}
	fan, err := packParseFanout(data[idxV2HeaderLen : idxV2HeaderLen+idxFanoutSize])
	if err != nil {
		return nil, err
	}
	n := uint64(fan[255])
	// Every object needs 20 (sha) + 4 (crc) + 4 (offset) bytes. Check this
	// before allocating anything.
	remaining := uint64(len(data)) - idxV2HeaderLen - idxFanoutSize - idxTrailerSize
	if n > remaining/28 {
		return nil, fmt.Errorf("%w: fanout declares %d objects but the file is only %d bytes", errPackIndexCorrupt, n, len(data))
	}
	hashStart := uint64(idxV2HeaderLen + idxFanoutSize)
	crcStart := hashStart + 20*n
	offStart := crcStart + 4*n
	largeStart := offStart + 4*n

	ids := make([]ObjectID, int(n))
	for i := range ids {
		p := hashStart + uint64(i)*20
		copy(ids[i][:], data[p:p+20])
	}
	if err := packValidateSortedIDs(ids); err != nil {
		return nil, err
	}
	if err := packValidateFanout(fan, ids); err != nil {
		return nil, err
	}

	raw := make([]uint32, int(n))
	largeCount := 0
	for i := range raw {
		p := offStart + uint64(i)*4
		raw[i] = binary.BigEndian.Uint32(data[p : p+4])
		if raw[i]&0x80000000 != 0 {
			largeCount++
		}
	}
	largeEnd := largeStart + uint64(largeCount)*8
	if largeEnd+idxTrailerSize != uint64(len(data)) {
		return nil, fmt.Errorf("%w: version 2 index is %d bytes, expected %d", errPackIndexCorrupt, len(data), largeEnd+idxTrailerSize)
	}

	offsets := make([]uint64, int(n))
	for i := range offsets {
		r := raw[i]
		if r&0x80000000 == 0 {
			offsets[i] = uint64(r)
			continue
		}
		li := uint64(r & 0x7fffffff)
		if li >= uint64(largeCount) {
			return nil, fmt.Errorf("%w: large offset index %d out of range (%d large offsets)", errPackIndexCorrupt, li, largeCount)
		}
		p := largeStart + li*8
		offsets[i] = binary.BigEndian.Uint64(data[p : p+8])
	}
	if err := packValidateIndexChecksum(data); err != nil {
		return nil, err
	}
	return &PackIndex{version: 2, ids: ids, offsets: offsets}, nil
}

func parsePackIndexV1(data []byte) (*PackIndex, error) {
	if len(data) < idxFanoutSize+idxTrailerSize {
		return nil, fmt.Errorf("%w: version 1 index is %d bytes, need at least %d", errPackIndexCorrupt, len(data), idxFanoutSize+idxTrailerSize)
	}
	fan, err := packParseFanout(data[:idxFanoutSize])
	if err != nil {
		return nil, err
	}
	n := uint64(fan[255])
	remaining := uint64(len(data)) - idxFanoutSize - idxTrailerSize
	if n > remaining/24 {
		return nil, fmt.Errorf("%w: fanout declares %d objects but the file is only %d bytes", errPackIndexCorrupt, n, len(data))
	}
	if uint64(idxFanoutSize)+24*n+idxTrailerSize != uint64(len(data)) {
		return nil, fmt.Errorf("%w: version 1 index has unexpected length %d for %d objects", errPackIndexCorrupt, len(data), n)
	}
	ids := make([]ObjectID, int(n))
	offsets := make([]uint64, int(n))
	for i := 0; i < int(n); i++ {
		p := uint64(idxFanoutSize) + uint64(i)*24
		offsets[i] = uint64(binary.BigEndian.Uint32(data[p : p+4]))
		copy(ids[i][:], data[p+4:p+24])
	}
	if err := packValidateSortedIDs(ids); err != nil {
		return nil, err
	}
	if err := packValidateFanout(fan, ids); err != nil {
		return nil, err
	}
	if err := packValidateIndexChecksum(data); err != nil {
		return nil, err
	}
	return &PackIndex{version: 1, ids: ids, offsets: offsets}, nil
}

func packParseFanout(b []byte) ([256]uint32, error) {
	var fan [256]uint32
	if len(b) < idxFanoutSize {
		return fan, fmt.Errorf("%w: truncated fanout table", errPackIndexCorrupt)
	}
	var prev uint32
	for i := 0; i < 256; i++ {
		v := binary.BigEndian.Uint32(b[i*4 : i*4+4])
		if i > 0 && v < prev {
			return fan, fmt.Errorf("%w: fanout entry %d is smaller than its predecessor", errPackIndexCorrupt, i)
		}
		fan[i] = v
		prev = v
	}
	return fan, nil
}

func packValidateFanout(fan [256]uint32, ids []ObjectID) error {
	var hist [256]uint32
	for _, id := range ids {
		hist[id[0]]++
	}
	var running uint32
	for i := 0; i < 256; i++ {
		running += hist[i]
		if fan[i] != running {
			return fmt.Errorf("%w: fanout entry %d is %d, want %d", errPackIndexCorrupt, i, fan[i], running)
		}
	}
	return nil
}

func packValidateSortedIDs(ids []ObjectID) error {
	for i := 1; i < len(ids); i++ {
		if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
			return fmt.Errorf("%w: object ids at positions %d and %d are not strictly increasing", errPackIndexCorrupt, i-1, i)
		}
	}
	return nil
}

func packValidateIndexChecksum(data []byte) error {
	if len(data) < idxTrailerSize {
		return fmt.Errorf("%w: truncated trailer", errPackIndexCorrupt)
	}
	want := data[len(data)-20:]
	sum := sha1.Sum(data[:len(data)-20])
	if !bytes.Equal(sum[:], want) {
		return fmt.Errorf("%w: index checksum mismatch", errPackIndexCorrupt)
	}
	return nil
}

// Len returns the number of objects referenced by the index.
func (p *PackIndex) Len() int {
	if p == nil {
		return 0
	}
	return len(p.ids)
}

// IDs returns a copy of the object ids in the index, in ascending order.
func (p *PackIndex) IDs() []ObjectID {
	if p == nil {
		return nil
	}
	out := make([]ObjectID, len(p.ids))
	copy(out, p.ids)
	return out
}

// Find returns the pack offset of id and whether the index contains it.
func (p *PackIndex) Find(id ObjectID) (uint64, bool) {
	if p == nil {
		return 0, false
	}
	i := sort.Search(len(p.ids), func(i int) bool {
		return bytes.Compare(p.ids[i][:], id[:]) >= 0
	})
	if i < len(p.ids) && p.ids[i] == id {
		return p.offsets[i], true
	}
	return 0, false
}

// Offset is an alias for Find.
func (p *PackIndex) Offset(id ObjectID) (uint64, bool) {
	return p.Find(id)
}

// resolveCall tracks one in-progress resolution of a pack offset so that
// concurrent callers share the work (singleflight).
type resolveCall struct {
	done chan struct{}
	obj  Object
	err  error

	// parent is the call whose body triggered this resolution, or nil for a
	// top-level request. It identifies cycles that a single goroutine would
	// otherwise deadlock on.
	parent *resolveCall

	// waiting is the call this call is currently blocked on. Guarded by
	// PackFile.mu. It is used to detect cross-goroutine wait cycles.
	waiting *resolveCall
}

// PackFile reads objects out of a single git pack file given its index.
//
// A PackFile is safe for concurrent use by multiple goroutines. Resolved
// objects are cached; returned Object.Data slices must be treated as read-only.
//
// packData is retained without copying and must stay valid for the lifetime of
// the PackFile. base, which may be nil, is used to resolve REF_DELTA bases that
// are not part of this pack (for example objects in a different pack or loose
// objects); it is typically another *PackFile.
type PackFile struct {
	idx  *PackIndex
	data []byte
	base Resolver

	mu         sync.Mutex
	cache      map[uint64]Object
	cacheBytes int64
	calls      map[uint64]*resolveCall
}

// PackFile implements Resolver.
var _ Resolver = (*PackFile)(nil)

// NewPackFile validates the pack header and binds packData to idx. The header
// is checked for the PACK signature, a supported version (2 or 3) and an object
// count that matches idx.Len(); individual object entries are validated lazily
// by Get and GetByOffset.
//
// base may be nil. It is consulted for REF_DELTA base objects that the pack
// index does not contain.
func NewPackFile(idx *PackIndex, packData []byte, base Resolver) (*PackFile, error) {
	if idx == nil {
		return nil, fmt.Errorf("%w: nil pack index", errPackCorrupt)
	}
	if len(packData) < packHeaderLen {
		return nil, fmt.Errorf("%w: pack file is %d bytes, need at least %d", errPackCorrupt, len(packData), packHeaderLen)
	}
	if string(packData[0:4]) != "PACK" {
		return nil, fmt.Errorf("%w: bad pack signature", errPackCorrupt)
	}
	switch v := binary.BigEndian.Uint32(packData[4:8]); v {
	case 2, 3:
	default:
		return nil, fmt.Errorf("%w: unsupported pack version %d", errPackCorrupt, v)
	}
	count := binary.BigEndian.Uint32(packData[8:12])
	if uint64(count) != uint64(idx.Len()) {
		return nil, fmt.Errorf("%w: pack header declares %d objects but the index has %d", errPackCorrupt, count, idx.Len())
	}
	return &PackFile{
		idx:   idx,
		data:  packData,
		base:  base,
		cache: make(map[uint64]Object),
		calls: make(map[uint64]*resolveCall),
	}, nil
}

// Get resolves the object with the given id from the pack.
func (p *PackFile) Get(id ObjectID) (Object, error) {
	if p == nil || p.idx == nil {
		return Object{}, fmt.Errorf("%w: nil pack file", errPackCorrupt)
	}
	off, ok := p.idx.Find(id)
	if !ok {
		return Object{}, fmt.Errorf("%w: %s", errPackObjectNotFound, id)
	}
	return p.fetch(off, 0, nil)
}

// GetByOffset resolves the object stored at the given pack offset.
func (p *PackFile) GetByOffset(off uint64) (Object, error) {
	if p == nil || p.idx == nil {
		return Object{}, fmt.Errorf("%w: nil pack file", errPackCorrupt)
	}
	return p.fetch(off, 0, nil)
}

// fetch resolves the object at off. self is the resolveCall currently being
// executed by this goroutine (nil for a top-level request); it is used for
// cycle detection and is never held while blocking on another call.
func (p *PackFile) fetch(off uint64, depth int, self *resolveCall) (Object, error) {
	if depth > maxPackDeltaDepth {
		return Object{}, fmt.Errorf("%w: object at offset %d: delta chain deeper than %d", errPackCorrupt, off, maxPackDeltaDepth)
	}
	p.mu.Lock()
	if obj, ok := p.cache[off]; ok {
		p.mu.Unlock()
		return obj, nil
	}
	if c, ok := p.calls[off]; ok {
		if self != nil {
			// Waiting on one of our own ancestors would deadlock because that
			// ancestor cannot finish until we return.
			for a := self; a != nil; a = a.parent {
				if a == c {
					p.mu.Unlock()
					return Object{}, fmt.Errorf("%w: object at offset %d: delta base loops back into its own resolution", errPackCorrupt, off)
				}
			}
			// Also detect cycles that span several goroutines.
			if packWaitChainReaches(c, self) {
				p.mu.Unlock()
				return Object{}, fmt.Errorf("%w: object at offset %d: cross-goroutine delta wait cycle", errPackCorrupt, off)
			}
			self.waiting = c
		}
		p.mu.Unlock()
		<-c.done
		if self != nil {
			p.mu.Lock()
			if self.waiting == c {
				self.waiting = nil
			}
			p.mu.Unlock()
		}
		return c.obj, c.err
	}
	c := &resolveCall{done: make(chan struct{}), parent: self}
	p.calls[off] = c
	p.mu.Unlock()

	obj, err := p.decode(off, depth, c)

	p.mu.Lock()
	if err == nil && len(p.cache) < maxPackCacheEntries && p.cacheBytes+int64(len(obj.Data)) <= maxPackCacheBytes {
		p.cache[off] = obj
		p.cacheBytes += int64(len(obj.Data))
	}
	delete(p.calls, off)
	c.obj, c.err = obj, err
	p.mu.Unlock()
	close(c.done)
	return obj, err
}

// packWaitChainReaches reports whether following waiting edges from head
// reaches target. Callers must hold PackFile.mu. An implausibly long chain is
// treated as a cycle so that a malformed pack cannot hang a caller.
func packWaitChainReaches(head, target *resolveCall) bool {
	for i := 0; i < 1<<16; i++ {
		if head == nil {
			return false
		}
		if head == target {
			return true
		}
		head = head.waiting
	}
	return true
}

// decode parses and resolves one pack object entry starting at off.
func (p *PackFile) decode(off uint64, depth int, self *resolveCall) (Object, error) {
	data := p.data
	if off < packHeaderLen {
		return Object{}, fmt.Errorf("%w: object offset %d overlaps the pack header", errPackCorrupt, off)
	}
	if off >= uint64(len(data)) {
		return Object{}, fmt.Errorf("%w: object offset %d is beyond the end of the %d byte pack", errPackCorrupt, off, len(data))
	}
	pos := off
	b := data[pos]
	pos++
	typ := (b >> 4) & 0x07
	size := uint64(b & 0x0f)
	shift := uint(4)
	for b&0x80 != 0 {
		if pos >= uint64(len(data)) {
			return Object{}, fmt.Errorf("%w: object at offset %d: truncated size header", errPackCorrupt, off)
		}
		b = data[pos]
		pos++
		if shift >= 64 {
			return Object{}, fmt.Errorf("%w: object at offset %d: size header overflow", errPackCorrupt, off)
		}
		v := uint64(b & 0x7f)
		if v > packMaxUint64>>shift {
			return Object{}, fmt.Errorf("%w: object at offset %d: size header overflow", errPackCorrupt, off)
		}
		size |= v << shift
		shift += 7
	}
	if size > maxPackObjectSize {
		return Object{}, fmt.Errorf("%w: object at offset %d declares %d bytes", ErrObjectTooLarge, off, size)
	}

	switch typ {
	case packTypeCommit, packTypeTree, packTypeBlob, packTypeTag:
		body, err := p.inflateEntry(pos, off, size)
		if err != nil {
			return Object{}, err
		}
		return Object{Type: packTypeName(typ), Data: body}, nil

	case packTypeOFSDelta:
		baseOff, next, err := p.readOFSDeltaBase(pos, off)
		if err != nil {
			return Object{}, err
		}
		delta, err := p.inflateEntry(next, off, size)
		if err != nil {
			return Object{}, err
		}
		base, err := p.fetch(baseOff, depth+1, self)
		if err != nil {
			return Object{}, err
		}
		out, err := packApplyDelta(base.Data, delta)
		if err != nil {
			return Object{}, fmt.Errorf("%w: object at offset %d: %w", errPackCorrupt, off, err)
		}
		return Object{Type: base.Type, Data: out}, nil

	case packTypeREFDelta:
		if pos+20 > uint64(len(data)) {
			return Object{}, fmt.Errorf("%w: object at offset %d: truncated REF_DELTA base id", errPackCorrupt, off)
		}
		var baseID ObjectID
		copy(baseID[:], data[pos:pos+20])
		pos += 20
		delta, err := p.inflateEntry(pos, off, size)
		if err != nil {
			return Object{}, err
		}
		base, err := p.resolveDeltaBase(baseID, off, depth, self)
		if err != nil {
			return Object{}, err
		}
		out, err := packApplyDelta(base.Data, delta)
		if err != nil {
			return Object{}, fmt.Errorf("%w: object at offset %d: %w", errPackCorrupt, off, err)
		}
		return Object{Type: base.Type, Data: out}, nil
	}
	return Object{}, fmt.Errorf("%w: object at offset %d: unknown object type %d", errPackCorrupt, off, typ)
}

// inflateEntry reads a zlib stream at pos, verifies that it decodes to want
// bytes and wraps any error with the object offset.
func (p *PackFile) inflateEntry(pos, off, want uint64) ([]byte, error) {
	if pos > uint64(len(p.data)) {
		return nil, fmt.Errorf("%w: object at offset %d: body starts beyond the end of the pack", errPackCorrupt, off)
	}
	body, err := DecodeZlib(p.data[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: object at offset %d: %w", errPackCorrupt, off, err)
	}
	if uint64(len(body)) != want {
		return nil, fmt.Errorf("%w: object at offset %d: header declares %d bytes but zlib produced %d", errPackCorrupt, off, want, len(body))
	}
	return body, nil
}

// readOFSDeltaBase decodes the negative offset that follows an OFS_DELTA
// header. It returns the absolute base offset and the position just after the
// encoded offset.
func (p *PackFile) readOFSDeltaBase(pos, off uint64) (uint64, uint64, error) {
	data := p.data
	if pos >= uint64(len(data)) {
		return 0, 0, fmt.Errorf("%w: object at offset %d: truncated OFS_DELTA offset", errPackCorrupt, off)
	}
	b := data[pos]
	pos++
	c := uint64(b & 0x7f)
	for b&0x80 != 0 {
		if pos >= uint64(len(data)) {
			return 0, 0, fmt.Errorf("%w: object at offset %d: truncated OFS_DELTA offset", errPackCorrupt, off)
		}
		b = data[pos]
		pos++
		if c >= packMaxUint64>>7 {
			return 0, 0, fmt.Errorf("%w: object at offset %d: OFS_DELTA offset overflow", errPackCorrupt, off)
		}
		c = ((c + 1) << 7) | uint64(b&0x7f)
	}
	if c == 0 || c >= off {
		return 0, 0, fmt.Errorf("%w: object at offset %d: invalid OFS_DELTA base distance %d", errPackCorrupt, off, c)
	}
	baseOff := off - c
	if baseOff < packHeaderLen {
		return 0, 0, fmt.Errorf("%w: object at offset %d: OFS_DELTA base offset %d overlaps the pack header", errPackCorrupt, off, baseOff)
	}
	return baseOff, pos, nil
}

// resolveDeltaBase resolves a REF_DELTA base id: first inside this pack, then
// through the configured external resolver.
func (p *PackFile) resolveDeltaBase(baseID ObjectID, off uint64, depth int, self *resolveCall) (Object, error) {
	if p.idx != nil {
		if baseOff, ok := p.idx.Find(baseID); ok {
			return p.fetch(baseOff, depth+1, self)
		}
	}
	if p.base != nil {
		obj, err := p.base.Get(baseID)
		if err != nil {
			return Object{}, fmt.Errorf("%w: object at offset %d: REF_DELTA base %s: %w", errPackCorrupt, off, baseID, err)
		}
		return obj, nil
	}
	return Object{}, fmt.Errorf("%w: object at offset %d: REF_DELTA base %s is neither in this pack nor resolvable by the base resolver", errPackCorrupt, off, baseID)
}

func packTypeName(typ byte) string {
	switch typ {
	case packTypeCommit:
		return TypeCommit
	case packTypeTree:
		return TypeTree
	case packTypeBlob:
		return TypeBlob
	case packTypeTag:
		return TypeTag
	}
	return ""
}

// packApplyDelta applies a git delta instruction stream to base and returns the
// result. The delta stream declares the base size and result size; both are
// validated, and no allocation larger than the declared result size is made.
func packApplyDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	baseSize, err := packReadDeltaVarint(delta, &pos)
	if err != nil {
		return nil, err
	}
	if baseSize != uint64(len(base)) {
		return nil, fmt.Errorf("delta declares a %d byte base but the base object is %d bytes", baseSize, len(base))
	}
	resultSize, err := packReadDeltaVarint(delta, &pos)
	if err != nil {
		return nil, err
	}
	if resultSize > maxPackObjectSize {
		return nil, fmt.Errorf("%w: delta declares a %d byte result", ErrObjectTooLarge, resultSize)
	}
	capHint := resultSize
	if capHint > 1<<20 {
		capHint = 1 << 20
	}
	out := make([]byte, 0, capHint)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		if op == 0 {
			return nil, errors.New("delta uses reserved opcode 0")
		}
		if op&0x80 == 0 {
			n := int(op & 0x7f)
			if n > len(delta)-pos {
				return nil, fmt.Errorf("delta insert of %d bytes is truncated", n)
			}
			if uint64(len(out))+uint64(n) > resultSize {
				return nil, fmt.Errorf("delta produces more than the declared %d result bytes", resultSize)
			}
			out = append(out, delta[pos:pos+n]...)
			pos += n
			continue
		}
		var copyOff, copySize uint64
		for i := uint(0); i < 4; i++ {
			if op&(1<<i) == 0 {
				continue
			}
			if pos >= len(delta) {
				return nil, errors.New("delta copy offset is truncated")
			}
			copyOff |= uint64(delta[pos]) << (8 * i)
			pos++
		}
		for i := uint(0); i < 3; i++ {
			if op&(0x10<<i) == 0 {
				continue
			}
			if pos >= len(delta) {
				return nil, errors.New("delta copy size is truncated")
			}
			copySize |= uint64(delta[pos]) << (8 * i)
			pos++
		}
		if copySize == 0 {
			copySize = 0x10000
		}
		if copyOff >= uint64(len(base)) {
			return nil, fmt.Errorf("delta copy offset %d is outside the %d byte base", copyOff, len(base))
		}
		if copySize > uint64(len(base))-copyOff {
			return nil, fmt.Errorf("delta copy of %d bytes at offset %d exceeds the %d byte base", copySize, copyOff, len(base))
		}
		if uint64(len(out))+copySize > resultSize {
			return nil, fmt.Errorf("delta produces more than the declared %d result bytes", resultSize)
		}
		out = append(out, base[copyOff:copyOff+copySize]...)
	}
	if uint64(len(out)) != resultSize {
		return nil, fmt.Errorf("delta produced %d bytes, declared %d", len(out), resultSize)
	}
	return out, nil
}

// packReadDeltaVarint reads one 7-bit little endian varint from data.
func packReadDeltaVarint(data []byte, pos *int) (uint64, error) {
	var v uint64
	var shift uint
	for {
		if *pos >= len(data) {
			return 0, errors.New("delta header is truncated")
		}
		b := data[*pos]
		*pos = *pos + 1
		if shift >= 64 {
			return 0, errors.New("delta header varint overflows 64 bits")
		}
		x := uint64(b & 0x7f)
		if x > packMaxUint64>>shift {
			return 0, errors.New("delta header varint overflows 64 bits")
		}
		v |= x << shift
		if b&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}
