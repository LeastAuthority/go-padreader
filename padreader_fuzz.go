//+build gofuzz

package padreader

import (
	"bytes"
	gfuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzPaddedSize(data []byte) int {
	var input uint64

	f := gfuzz.NewFromGoFuzz(data)
	f.Fuzz(&input)

	_ = PaddedSize(input)
	return fleece.FuzzNormal
}

func FuzzRead(data []byte) int {
	var size uint64

	f := gfuzz.NewFromGoFuzz(data)
	f.Fuzz(&size)

	reader, _ := New(bytes.NewBuffer(data), size)
	_, err := reader.Read(data)
	if err != nil {
		return fleece.FuzzNormal
	}
	return fleece.FuzzInteresting
}