package app

import "fmt"

// sprintf is a tiny indirection so helpers can format messages.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// containsString reports whether list contains s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
