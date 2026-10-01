package pkarrnaming_test

import (
	"fmt"

	"github.com/tmc/go-iroh-experiments/pkarrnaming"
	"github.com/tmc/go-iroh/blobs"
)

func ExampleRecordString() {
	record := blobs.HashSeqHash(blobs.NewHash([]byte("example")))
	text := pkarrnaming.RecordString(record)
	parsed, err := pkarrnaming.ParseRecord(text)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed == record)
	// Output: true
}
