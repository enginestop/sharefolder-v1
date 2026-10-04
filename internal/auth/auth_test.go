package auth

import (
	"context"
	"strings"
	"testing"
)

func TestArgonPolicyAndCancelledQueue(t *testing.T) {
	for _, p := range []string{"a", "123", "", " ", strings.Repeat("x", 256)} {
		hash, e := Hash(p)
		if e != nil || !Check(p, hash) || Check(p+"wrong", hash) {
			t.Fatal("unrestricted password failed verification")
		}
	}
	hash, e := Hash("TwelveOrMore!2026")
	if e != nil {
		t.Fatal(e)
	}
	if !Check("TwelveOrMore!2026", hash) || Check("IncorrectValue!2026", hash) {
		t.Fatal("password verification failed")
	}
	hashing <- struct{}{}
	hashing <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = CheckContext(ctx, "TwelveOrMore!2026", hash)
	<-hashing
	<-hashing
	if e == nil {
		t.Fatal("cancelled queue waited")
	}
}
