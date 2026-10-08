package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var executeSelector = Selector{0xb6, 0x1d, 0x27, 0xf6} // execute(address,uint256,bytes)

const maxAccountCallDataBytes = 128 * 1024

type Call struct {
	Target   Address
	Value    Wei
	Selector Selector
	data     []byte
}

func (c Call) Data() []byte { return bytes.Clone(c.data) }

// DecodeExecute accepts only the canonical ABI form of the fixed single-call account.
func DecodeExecute(input []byte) (Call, error) {
	var call Call
	if len(input) < 4+96+32+32 || len(input) > maxAccountCallDataBytes {
		return call, errors.New("unsupported execute calldata length")
	}
	if !bytes.Equal(input[:4], executeSelector[:]) {
		return call, errors.New("unsupported account execution selector")
	}
	head := input[4 : 4+96]
	if !bytes.Equal(head[:12], make([]byte, 12)) {
		return call, errors.New("noncanonical target address")
	}
	copy(call.Target[:], head[12:32])
	if call.Target.IsZero() {
		return Call{}, errors.New("zero target")
	}
	copy(call.Value.bytes[:], head[32:64])
	if !bytes.Equal(head[64:95], make([]byte, 31)) || head[95] != 96 {
		return Call{}, errors.New("noncanonical bytes offset")
	}
	lengthWord := input[4+96 : 4+96+32]
	if !bytes.Equal(lengthWord[:24], make([]byte, 24)) {
		return Call{}, errors.New("calldata length overflows uint64")
	}
	length := binary.BigEndian.Uint64(lengthWord[24:])
	if length < 4 || length > maxAccountCallDataBytes {
		return Call{}, errors.New("target calldata lacks selector or is oversized")
	}
	padded := ((length + 31) / 32) * 32
	if uint64(len(input)) != 4+96+32+padded {
		return Call{}, errors.New("noncanonical calldata size")
	}
	dataStart := 4 + 96 + 32
	call.data = bytes.Clone(input[dataStart : dataStart+int(length)])
	copy(call.Selector[:], call.data[:4])
	if !bytes.Equal(input[dataStart+int(length):], make([]byte, int(padded-length))) {
		return Call{}, errors.New("nonzero calldata padding")
	}
	return call, nil
}

// encodeExecute is used to assert canonical decoder round trips in tests.
func encodeExecute(call Call) []byte {
	padded := (len(call.data) + 31) / 32 * 32
	out := make([]byte, 4+96+32+padded)
	copy(out[:4], executeSelector[:])
	copy(out[4+12:4+32], call.Target[:])
	copy(out[4+32:4+64], call.Value.bytes[:])
	out[4+95] = 96
	binary.BigEndian.PutUint64(out[4+96+24:4+96+32], uint64(len(call.data)))
	copy(out[4+96+32:], call.data)
	return out
}
