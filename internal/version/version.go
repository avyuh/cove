package version

// These defaults make source builds identifiable. Release builds replace them
// with -ldflags -X; keep them as variables so all existing Version users share
// the injected value.
var (
	Version = "0.1.0"
	Commit  = "none"
	Date    = "unknown"
)
