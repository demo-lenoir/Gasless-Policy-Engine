package policy

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func FuzzDecodeExecute(f *testing.F) {
	target, _ := ParseAddress(testTarget)
	canonical := encodeExecute(Call{Target: target, data: []byte{0x12, 0x34, 0x56, 0x78, 0xaa}})
	f.Add(canonical)
	f.Add(canonical[:10])
	f.Add([]byte{0x47, 0xe1, 0xda, 0x2a})
	f.Fuzz(func(t *testing.T, raw []byte) {
		call, err := DecodeExecute(raw)
		if err != nil {
			return
		}
		if call.Target.IsZero() || len(call.Data()) < 4 || !bytes.Equal(raw, encodeExecute(call)) {
			t.Fatal("accepted noncanonical or ambiguous call")
		}
		copied := call.Data()
		copied[0] ^= 0xff
		if bytes.Equal(copied, call.Data()) {
			t.Fatal("call data accessor returned internal buffer")
		}
	})
}

func FuzzNormalize(f *testing.F) {
	target, _ := ParseAddress(testTarget)
	canonical := encodeExecute(Call{Target: target, data: []byte{0x12, 0x34, 0x56, 0x78, 0xaa}})
	f.Add("0x"+hex.EncodeToString(canonical), "31337", "100000")
	f.Add("0x", "0", "-1")
	f.Add("0x47e1da2a", "1", "100000")
	f.Fuzz(func(t *testing.T, callData, chainID, gas string) {
		if len(callData) > 2+maxAccountCallDataBytes*2 || len(chainID) > 256 || len(gas) > 256 {
			return
		}
		input := testInput(t)
		input.CallData = callData
		input.ChainID = chainID
		input.CallGasLimit = gas
		first, err := Normalize(input)
		second, secondErr := Normalize(input)
		if (err == nil) != (secondErr == nil) || !reflect.DeepEqual(first, second) {
			t.Fatal("normalization is nondeterministic")
		}
		if err != nil {
			return
		}
		outer := first.OuterCallData()
		call := first.Call()
		if !bytes.Equal(outer, encodeExecute(call)) || call.Selector != Selector(call.Data()[:4]) {
			t.Fatal("normalization changed executed call")
		}
	})
}
