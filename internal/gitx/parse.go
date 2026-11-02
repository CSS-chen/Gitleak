package gitx

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TreeEntry is one entry of a git tree object.
type TreeEntry struct {
	Mode uint32
	Name string
	ID   ObjectID
}

// ParseTree parses a tree object body.
func ParseTree(data []byte) ([]TreeEntry, error) {
	entries := make([]TreeEntry, 0, 16)
	off := 0
	for off < len(data) {
		sp := bytes.IndexByte(data[off:], ' ')
		if sp <= 0 {
			return nil, fmt.Errorf("%w: tree entry without mode", ErrInvalidObject)
		}
		mode, err := strconv.ParseUint(string(data[off:off+sp]), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: bad tree mode", ErrInvalidObject)
		}
		off += sp + 1
		nul := bytes.IndexByte(data[off:], 0)
		if nul < 0 {
			return nil, fmt.Errorf("%w: unterminated tree name", ErrInvalidObject)
		}
		name := string(data[off : off+nul])
		off += nul + 1
		if off+20 > len(data) {
			return nil, fmt.Errorf("%w: truncated tree object id", ErrInvalidObject)
		}
		var id ObjectID
		copy(id[:], data[off:off+20])
		off += 20
		if name == "" {
			return nil, fmt.Errorf("%w: empty tree entry name", ErrInvalidObject)
		}
		entries = append(entries, TreeEntry{Mode: uint32(mode), Name: name, ID: id})
	}
	return entries, nil
}

// Commit is the parsed metadata of a commit object.
type Commit struct {
	Tree    ObjectID
	Parents []ObjectID
	Author  string
	Email   string
	When    time.Time
	Message string
}

// ParseCommit parses a commit object body.
func ParseCommit(data []byte) (*Commit, error) {
	c := &Commit{}
	rest := data
	for {
		nl := bytes.IndexByte(rest, '\n')
		if nl < 0 {
			break
		}
		line := string(rest[:nl])
		rest = rest[nl+1:]
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch key {
		case "tree":
			id, err := ParseObjectID(val)
			if err != nil {
				return nil, fmt.Errorf("%w: bad commit tree", ErrInvalidObject)
			}
			c.Tree = id
		case "parent":
			id, err := ParseObjectID(val)
			if err == nil {
				c.Parents = append(c.Parents, id)
			}
		case "author":
			c.Author, c.Email, c.When = parseIdent(val)
		}
	}
	if c.Tree.IsZero() {
		return nil, fmt.Errorf("%w: commit without tree", ErrInvalidObject)
	}
	c.Message = string(rest)
	return c, nil
}

// parseIdent parses "Name <email> 1234567890 +0800".
func parseIdent(s string) (name, email string, when time.Time) {
	lt := strings.LastIndex(s, "<")
	if lt < 0 {
		return strings.TrimSpace(s), "", time.Time{}
	}
	gt := strings.LastIndex(s, ">")
	if gt < lt {
		return strings.TrimSpace(s), "", time.Time{}
	}
	name = strings.TrimSpace(s[:lt])
	email = s[lt+1 : gt]
	rest := strings.Fields(strings.TrimSpace(s[gt+1:]))
	if len(rest) >= 1 {
		if secs, err := strconv.ParseInt(rest[0], 10, 64); err == nil {
			when = time.Unix(secs, 0).Local()
		}
	}
	return name, email, when
}

// Tag is the parsed metadata of an annotated tag object.
type Tag struct {
	Object ObjectID
	Type   string
	Name   string
}

// ParseTag parses an annotated tag object body.
func ParseTag(data []byte) (*Tag, error) {
	t := &Tag{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch key {
		case "object":
			id, err := ParseObjectID(val)
			if err != nil {
				return nil, fmt.Errorf("%w: bad tag object", ErrInvalidObject)
			}
			t.Object = id
		case "type":
			t.Type = val
		case "tag":
			t.Name = val
		}
	}
	if t.Object.IsZero() {
		return nil, fmt.Errorf("%w: tag without object", ErrInvalidObject)
	}
	return t, nil
}
