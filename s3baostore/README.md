# s3baostore

`s3baostore` is an iroh-blobs provider backed by a remote HTTP/S3 object store.
Importing a URL reads the object once to compute its BLAKE3 root and BAO
outboard; the data itself stays remote, and later reads use HTTP range requests
against the origin. Public S3 objects and presigned S3 URLs work through the same
HTTP path.

The module includes:

- one-pass import that computes the BLAKE3 root and BAO outboard from a URL
- range-request–backed reads so blob bytes are never copied locally
- support for public and presigned S3 URLs

It is a clean-room Go port of the Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) remote blob
store work.

```sh
go get github.com/tmc/go-iroh-experiments/s3baostore
```

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/s3baostore)
for the API.
