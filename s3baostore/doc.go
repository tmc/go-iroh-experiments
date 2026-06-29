// Package s3baostore stores BAO outboards for HTTP/S3-hosted blobs.
//
// Importing a URL reads the object once to compute its BLAKE3 root and BAO
// outboard. The data itself stays remote; later reads use HTTP range requests.
// Public S3 objects and presigned S3 URLs are supported through the same HTTP
// path.
package s3baostore
