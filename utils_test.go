package main

import (
	"bytes"
	"testing"
)

func TestSerialization(t *testing.T) {
	f1 := randomBytes(10)
	f2 := randomBytes(10000)
	f3 := randomBytes(100)

	k := serialize(f1, f2, f3)

	d := deserialize(k)

	if !bytes.Equal(d[0], f1) || !bytes.Equal(d[1], f2) || !bytes.Equal(d[2], f3) {
		t.Error("Erreur dans la deserialization")
	}
}
