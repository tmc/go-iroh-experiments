package s3baostore_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh-experiments/s3baostore"
)

func ExampleStore_ImportBytes() {
	ctx := context.Background()
	store := s3baostore.New()
	hash, err := store.ImportBytes([]byte("hello"))
	if err != nil {
		panic(err)
	}
	blob, err := store.Open(ctx, hash)
	if err != nil {
		panic(err)
	}
	reader, err := blob.DataReader(ctx)
	if err != nil {
		panic(err)
	}
	defer reader.Close()
	size, known := blob.Size()
	if !known {
		panic("blob size is unknown")
	}
	data := make([]byte, size)
	_, err = reader.ReadAt(data, 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	// Output: hello
}
