package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDecodeExecuteCanonicalAndNestedBytes(t *testing.T) {
	target, _ := ParseAddress(testTarget)
	value, _ := ParseUint256("12345678901234567890")
	inner := []byte{0x12, 0x34, 0x56, 0x78, 0xb6, 0x1d, 0x27, 0xf6, 0x00}
	encoded := encodeExecute(Call{Target: target, Value: Wei{value}, data: inner})
	call, err := DecodeExecute(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if call.Target != target || call.Value.String() != value.String() || call.Selector.String() != "0x12345678" || !bytes.Equal(call.Data(), inner) {
		t.Fatal("decoded call differs")
	}
	if !bytes.Equal(encodeExecute(call), encoded) {
		t.Fatal("noncanonical round trip")
	}
	encoded[len(encoded)-1] = 0xff
	if !bytes.Equal(call.Data(), inner) {
		t.Fatal("decoder retained caller buffer")
	}
	returned := call.Data()
	returned[0] = 0
	if call.Selector.String() != "0x12345678" || call.Data()[0] != 0x12 {
		t.Fatal("data accessor leaked internal buffer")
	}
}

func TestDecodeExecuteRejectsAmbiguousForms(t *testing.T) {
	input := testInput(t)
	base, err := hex.DecodeString(input.CallData[2:])
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(change func([]byte) []byte) []byte { return change(bytes.Clone(base)) }
	cases := map[string][]byte{
		"truncated":            base[:len(base)-1],
		"wrong outer selector": mutate(func(b []byte) []byte { b[0] ^= 1; return b }),
		"batch selector":       mutate(func(b []byte) []byte { copy(b[:4], []byte{0x47, 0xe1, 0xda, 0x2a}); return b }),
		"bad offset":           mutate(func(b []byte) []byte { b[4+95] = 0x80; return b }),
		"offset high byte":     mutate(func(b []byte) []byte { b[4+64] = 1; return b }),
		"address high byte":    mutate(func(b []byte) []byte { b[4] = 1; return b }),
		"zero target":          mutate(func(b []byte) []byte { clear(b[4+12 : 4+32]); return b }),
		"length overflow":      mutate(func(b []byte) []byte { b[4+96] = 1; return b }),
		"short inner selector": mutate(func(b []byte) []byte { binary.BigEndian.PutUint64(b[4+96+24:4+96+32], 3); return b }),
		"nonzero padding":      mutate(func(b []byte) []byte { b[len(b)-1] = 1; return b }),
		"trailing bytes":       append(bytes.Clone(base), make([]byte, 32)...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecute(raw); err == nil {
				t.Fatal("accepted malformed call")
			}
		})
	}
}
