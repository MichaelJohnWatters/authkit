package authkit

import "testing"

func TestIsCommonPassword(t *testing.T) {
	for _, p := range []string{"password1", "Password123", "ILOVEYOU", "qwertyuiop", "sunshine1"} {
		if !IsCommonPassword(p) {
			t.Errorf("%q: not on the list", p)
		}
	}
	for _, p := range []string{"correct-horse-battery", "a-long-password", "kickstand-yoga-2026!"} {
		if IsCommonPassword(p) {
			t.Errorf("%q: on the list", p)
		}
	}
	if n := len(commonPasswords()); n < 40000 {
		t.Errorf("list has %d passwords, want ~46,500", n)
	}
}
