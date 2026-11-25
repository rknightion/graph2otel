# Teams call-record notifications

The optional HTTPS listener reduces the time between Graph publishing a call
record and graph2otel fetching it. It does not increase coverage. The
`teams.call_records` poller still owns discovery and recovery. A callback only
supplies the call ID; the poller fetches the authoritative record and version
using the same tenant credential, enrichment and dedupe checkpoint. A direct
fetch never advances the polling window.

## Opt in

Set `call_notifications` as shown in [the example config](../config.example.yaml).
For each opted-in tenant, enable `teams.call_records` (the Teams profile enables
it) and set `call_notification_client_state_file` to a mounted file containing
32 cryptographically random bytes encoded as 64 hex characters. Use a different
secret for each tenant. Mount the PEM certificate chain and key as files too.
Keep the contents of all three files out of config, environment variables and
Helm values. Restart to reload them.

Publish only `/graph/call-records` on its own HTTPS listener, never the admin
server. The URL Graph sees must use a publicly trusted certificate. If a proxy
terminates public TLS, use a verified HTTPS connection from the proxy to the
listener as well. Do not log request queries or bodies at the proxy. The Helm
chart renders a separate ClusterIP Service only when enabled; it creates no
Ingress, NodePort or load balancer. Use `extraVolumes` and `extraVolumeMounts`
for existing Kubernetes Secrets. Keep one replica and a persistent checkpoint
volume. Do not use environment overrides to change chart-managed listener or
admin ports; set them in values so they agree with the Service.

## What happens when delivery fails

The listener authenticates basic notifications with the client-state secret,
tenant ID and current subscription ID. It accepts a bounded batch only if all
entries fit. Queue pressure returns HTTP 503 so Graph can retry. After an
accepted delivery, a crash or failed fetch can still lose the latency benefit;
the queue is not durable and polling is the safety net. A successful validation
echo only proves endpoint reachability and does not authenticate a delivery.

Graph lists subscriptions for the authenticated app and tenant but does not
return the client-state secret. On restart, graph2otel reuses a basic
subscription only if both callback URLs and the resource and change type
match. Use a dedicated callback and don't create competing call-record
subscriptions under the same app and tenant. To change the callback or
client-state secret, first disable notifications and let the existing
subscription expire (or have its owner remove it), then restart with the new
configuration. graph2otel will not delete a conflicting subscription. Disabling
the receiver stops renewal; polling continues.

Subscription behaviour is based on Microsoft documentation and synthetic
fixtures, not live measurements. A removal notification can accelerate
recreation if Graph sends it. Don't rely on lifecycle notifications for
coverage; the renewal loop and regular polling do not require them.
