package blobpipeline

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// azureSource is the real Source: Azure Blob Storage via the azblob SDK. It is
// the ONLY file in graph2otel that imports an Azure storage type — every
// collector depends on the Source interface instead, so the Azure SDK never
// leaks into collector code and the whole engine stays unit-testable offline
// against a fake (#89).
//
// Auth reuses the tenant's existing azcore.TokenCredential (auth.TenantAuth.Cred)
// with no new credential plumbing: the SDK requests the storage audience
// (https://storage.azure.com/.default) itself. The role that credential needs is
// Storage Blob Data Reader — and specifically the DATA-plane role, which is the
// trap on this path: Owner grants container list/create (a control-plane Action)
// but NOT blob content reads (a DataAction), so an under-privileged identity
// lists blobs happily and 403s only on the read.
type azureSource struct {
	client *azblob.Client
}

// NewAzureSource returns a Source reading from the storage account at
// accountURL (e.g. "https://graph2otelm7kni.blob.core.windows.net") using cred.
//
// The returned Source is read-only in the sense that matters: it only ever
// calls list and ranged-download. Nothing here can write or delete a blob, so
// no misconfiguration of graph2otel can destroy data it has not read —
// retention is owned solely by the storage account's lifecycle rule (#89).
//
// accountURL is validated here rather than left to the SDK: azblob.NewClient
// accepts a malformed URL and only fails on the first request, which would turn
// a config typo into a recurring per-tick error rather than a startup failure
// naming the bad value. https is required because azcore refuses to attach a
// bearer token to a plaintext endpoint, so an http:// account URL cannot work
// at all — better to say so at startup than to fail every tick.
func NewAzureSource(accountURL string, cred azcore.TokenCredential) (Source, error) {
	u, err := url.Parse(accountURL)
	if err != nil {
		return nil, fmt.Errorf("blobpipeline: account URL %q is not a URL: %w", accountURL, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("blobpipeline: account URL %q must be an https URL with a host, "+
			"e.g. https://<account>.blob.core.windows.net", accountURL)
	}
	client, err := azblob.NewClient(accountURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("blobpipeline: azure source for %q: %w", accountURL, err)
	}
	return &azureSource{client: client}, nil
}

// List implements Source.
func (s *azureSource) List(ctx context.Context, container, prefix string) ([]BlobInfo, error) {
	opts := &azblob.ListBlobsFlatOptions{}
	if prefix != "" {
		opts.Prefix = &prefix
	}
	var out []BlobInfo
	pager := s.client.NewListBlobsFlatPager(container, opts)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s/%s: %w", container, prefix, err)
		}
		for _, item := range page.Segment.BlobItems {
			if item == nil || item.Name == nil || item.Properties == nil || item.Properties.ContentLength == nil {
				continue
			}
			out = append(out, BlobInfo{Name: *item.Name, Size: *item.Properties.ContentLength})
		}
	}
	return out, nil
}

// ReadRange implements Source. count must be positive: azblob treats a zero
// Offset AND zero Count as "the whole blob", so passing a zero count through
// would silently download an entire multi-megabyte blob instead of nothing.
func (s *azureSource) ReadRange(ctx context.Context, container, name string, offset, count int64) ([]byte, error) {
	if count <= 0 {
		return nil, nil
	}
	resp, err := s.client.DownloadStream(ctx, container, name, &azblob.DownloadStreamOptions{
		Range: azblob.HTTPRange{Offset: offset, Count: count},
	})
	if err != nil {
		return nil, fmt.Errorf("download %s/%s [%d,%d): %w", container, name, offset, offset+count, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded by count, which Poll already caps at ContainerConfig.MaxBytesPerTick.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s/%s [%d,%d): %w", container, name, offset, offset+count, err)
	}
	return data, nil
}
