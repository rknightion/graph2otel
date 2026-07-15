{{- define "graph2otel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "graph2otel.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "graph2otel.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "graph2otel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "graph2otel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "graph2otel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "graph2otel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "graph2otel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "graph2otel.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- include "graph2otel.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
The rendered config.yaml. Always sourced from .Values.config so there is a
single source of truth and no chart<->config drift. The full default config
map lives in values.yaml under `config:`; Helm deep-merges maps, so
single-key overrides (e.g. --set config.log_level=debug) keep working. No
secrets appear here — tenant auth is injected exclusively via AZURE_*
environment variables from the envFrom Secret (see secret.yaml), which
config.example.yaml documents as never being config-file material.
*/}}
{{- define "graph2otel.config" -}}
{{ .Values.config | toYaml }}
{{- end -}}
