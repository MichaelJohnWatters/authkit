package authkit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// The 100,000 passwords the UK's NCSC found most used in breaches
// (100k-most-used-passwords-NCSC.txt in SecLists, MIT), keeping only those
// long enough to pass MinPasswordLength, lowercased: about 46,500. Checked
// here, on the server, so nothing about a password leaves it.
//
//go:embed common_passwords.txt.gz
var commonPasswordsGz []byte

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	zr, err := gzip.NewReader(bytes.NewReader(commonPasswordsGz))
	if err != nil {
		panic("auth: common password list: " + err.Error())
	}
	set := make(map[string]struct{}, 47000)
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		set[sc.Text()] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		panic("auth: common password list: " + err.Error())
	}
	return set
})

// IsCommonPassword reports whether plain is on the list, ignoring case.
func IsCommonPassword(plain string) bool {
	_, ok := commonPasswords()[strings.ToLower(plain)]
	return ok
}
