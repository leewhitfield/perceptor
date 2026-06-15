# Evidence Ingress

Perceptor does not currently support a public evidence upload service.

For now, place evidence on the analysis host through examiner-controlled means
such as a local disk, private file transfer, or mounted storage approved for the
case. Then register or process that evidence with the Perceptor CLI.

## Current Rules

- Do not expose a public HTTP upload endpoint.
- Do not expose writeable evidence storage over the public internet.
- Do not store credentials or transfer tokens in repository files.
- Verify evidence hashes after transfer and before processing.
- Keep original evidence paths read-only during processing.

## Future Work

Hosted evidence ingress belongs in the AWS deployment design:

[AWS Deployment Design](../design/aws-deployment.md)
