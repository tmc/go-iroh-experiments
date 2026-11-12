package irciroh

import "strings"

// Fold folds a channel name or a nick to the form used for comparison,
// for hashing, and for lookup, following the rfc1459 casemapping this
// advertises in its 005. Two names that fold alike are one name, and
// every place that decides whether two names are the same has to agree
// about that or a name can be claimed twice.
//
// Beyond ASCII case, rfc1459 folds []\~ onto {}|^, which IRC inherited
// from the Scandinavian alphabets its authors were writing for. It
// looks like a curiosity and is not one: tmc[1] and tmc{1} are one nick
// to every client that reads the 005, so a store that told them apart
// would hold two entries for a name its users cannot tell apart.
func Fold(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case 'A' <= r && r <= 'Z':
			return r + 'a' - 'A'
		case r == '[':
			return '{'
		case r == ']':
			return '}'
		case r == '\\':
			return '|'
		case r == '~':
			return '^'
		}
		return r
	}, s)
}
