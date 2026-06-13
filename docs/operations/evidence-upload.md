# Evidence Upload

Because the Perceptor server is hosted remotely, you must upload forensic evidence before processing.

## Option 1: HTTP Upload API
The HTTP upload API is built for reliability. It chunks large files, allowing uploads to resume if the network connection drops.

### Initialization
```bash
curl -X POST https://perceptor.example.com/upload/init \
  -H "Authorization: Bearer <tenant-token>" \
  -H "Content-Type: application/json" \
  -d '{"filename": "image.E01", "size_bytes": 5368709120}'
```

### Uploading Chunks
```bash
curl -X PUT https://perceptor.example.com/upload/<upload_id>/chunk/<offset> \
  --data-binary @chunk_file
```

### Finalization
```bash
curl -X POST https://perceptor.example.com/upload/<upload_id>/finalize \
  -H "Authorization: Bearer <tenant-token>" \
  -H "Content-Type: application/json" \
  -d '{"sha256": "expected_hash_here"}'
```

## Option 2: Rsync (Fastest for bulk data)
If rsync is enabled, you can push data directly:

```bash
RSYNC_PASSWORD=perceptor rsync -avP /local/evidence/ perceptor@perceptor.example.com::evidence/
```
*Note: Ensure your rsync push targets the correct tenant directory if using strict isolation.*
