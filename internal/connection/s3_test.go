package connection

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"cove/internal/clierr"
	"cove/internal/config"
)

func TestS3URIRejectionsAreUsageErrorsAndDoNotMutate(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"missing prefix", "s3://my-bucket"},
		{"query", "s3://my-bucket/pfx/?versionId=1"},
		{"fragment", "s3://my-bucket/pfx/#part"},
		{"backslash", "s3://my-bucket/pfx\\bad/"},
		{"dot segment", "s3://my-bucket/pfx/../private/"},
		{"encoded separator", "s3://my-bucket/pfx%2Fprivate/"},
		{"wildcard", "s3://my-bucket/pfx*/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, path := setupAddTest(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = Add([]string{"s3", tt.uri, "--region", "us-east-1", "--account", "123456789012", "--yes"})
			var cli *clierr.Error
			if !errors.As(err, &cli) || cli.Code != clierr.EXUsage {
				t.Fatalf("error = %#v, want EX_USAGE", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("rejected URI mutated config:\n%s", after)
			}
		})
	}
}

func TestS3CapabilityMatrix(t *testing.T) {
	tests := []struct {
		name                     string
		readWrite, deleteObjects bool
		methods, operations      []string
	}{
		{
			name:       "read only",
			methods:    []string{"GET", "HEAD"},
			operations: []string{"s3:GetObject", "s3:HeadObject", "s3:ListBucket"},
		},
		{
			name:      "read write",
			readWrite: true,
			methods:   []string{"GET", "HEAD", "PUT"},
			operations: []string{
				"s3:GetObject", "s3:HeadObject", "s3:ListBucket", "s3:PutObject", "s3:CopyObject",
			},
		},
		{
			name:          "read write delete",
			readWrite:     true,
			deleteObjects: true,
			methods:       []string{"GET", "HEAD", "PUT", "DELETE"},
			operations: []string{
				"s3:GetObject", "s3:HeadObject", "s3:ListBucket", "s3:PutObject", "s3:CopyObject", "s3:DeleteObject",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := compileS3("s3://my-bucket/pfx/", "work", "us-east-1", "123456789012", tt.readWrite, tt.deleteObjects, &config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.Stanza.AllowedMethods, tt.methods) || !reflect.DeepEqual(p.Stanza.AllowedOperations, tt.operations) {
				t.Fatalf("capabilities = methods=%v operations=%v, want methods=%v operations=%v", p.Stanza.AllowedMethods, p.Stanza.AllowedOperations, tt.methods, tt.operations)
			}
			wantResources := []string{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/pfx/*"}
			if !reflect.DeepEqual(p.Stanza.AllowedResources, wantResources) {
				t.Fatalf("resources = %v, want %v", p.Stanza.AllowedResources, wantResources)
			}
		})
	}
	if _, err := compileS3("s3://my-bucket/pfx/", "work", "us-east-1", "123456789012", false, true, &config.Config{}); err == nil || !strings.Contains(err.Error(), "--delete requires --read-write") {
		t.Fatalf("delete without read-write error = %v", err)
	}
}

func TestS3EndpointAndAccountCompilation(t *testing.T) {
	p, err := compileS3("s3://my-bucket/pfx/", "named-profile", "us-east-1", "123456789012", false, false, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Stanza.Host != "my-bucket.s3.us-east-1.amazonaws.com" {
		t.Fatalf("host = %q", p.Stanza.Host)
	}
	if p.Verified || !strings.Contains(previewS3Plan(p), "123456789012 (not STS-verified)") {
		t.Fatalf("explicit account preview = %q", previewS3Plan(p))
	}
	for _, value := range []string{p.Stanza.AccessKeyID, p.Stanza.SecretAccessKey, p.Stanza.SessionToken} {
		if value != "" {
			t.Fatalf("compiled S3 policy retained credential value %q", value)
		}
	}
	if p.Stanza.Profile != "named-profile" || p.Stanza.MaxBodyBytes != s3MaxBodyBytes {
		t.Fatalf("compiled stanza = %+v", p.Stanza)
	}

	if _, err := compileS3("s3://my-bucket/pfx/", "work", "", "123456789012", false, false, &config.Config{}); err == nil || !strings.Contains(err.Error(), "--region REGION") {
		t.Fatalf("missing region error = %v", err)
	}
	if _, err := compileS3("s3://my-bucket/pfx/", "work", "us-east-1", "bad", false, false, &config.Config{}); err == nil || !strings.Contains(err.Error(), "12-digit") {
		t.Fatalf("invalid account error = %v", err)
	}
}

func TestS3UnsupportedEndpointsAreConfigErrors(t *testing.T) {
	for _, host := range []string{
		"s3-accelerate.amazonaws.com",
		"my-bucket.s3.dualstack.us-east-1.amazonaws.com",
		"my-bucket.s3-accesspoint.us-east-1.amazonaws.com",
		"*.amazonaws.com",
	} {
		t.Run(host, func(t *testing.T) {
			body := `[[sigv4]]
host = "` + host + `"
profile = "named-profile"
account_id = "123456789012"
service = "s3"
region = "us-east-1"
allowed_methods = ["GET", "HEAD"]
allowed_operations = ["s3:GetObject", "s3:HeadObject", "s3:ListBucket"]
allowed_resources = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/pfx/*"]
max_body_bytes = 67108864
`
			_, err := config.LoadBytes([]byte(body))
			var cli *clierr.Error
			if !errors.As(err, &cli) || cli.Code != clierr.EXConfig {
				t.Fatalf("error = %#v, want EX_CONFIG", err)
			}
		})
	}
}
