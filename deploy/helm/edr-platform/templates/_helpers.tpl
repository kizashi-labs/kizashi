{{/*
EDR Platform Helm Chart - Template Helpers
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "edr-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
If release name contains chart name it will be used as a full name.
*/}}
{{- define "edr-platform.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label value: chart-name-version
*/}}
{{- define "edr-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "edr-platform.labels" -}}
helm.sh/chart: {{ include "edr-platform.chart" . }}
{{ include "edr-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (used in matchLabels and Service selectors).
*/}}
{{- define "edr-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edr-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Server-specific labels and selector labels.
*/}}
{{- define "edr-platform.server.labels" -}}
{{ include "edr-platform.labels" . }}
app.kubernetes.io/component: server
{{- end }}

{{- define "edr-platform.server.selectorLabels" -}}
{{ include "edr-platform.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Frontend-specific labels and selector labels.
*/}}
{{- define "edr-platform.frontend.labels" -}}
{{ include "edr-platform.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{- define "edr-platform.frontend.selectorLabels" -}}
{{ include "edr-platform.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Postgres-specific labels and selector labels.
*/}}
{{- define "edr-platform.postgres.labels" -}}
{{ include "edr-platform.labels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{- define "edr-platform.postgres.selectorLabels" -}}
{{ include "edr-platform.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
NATS-specific labels and selector labels.
*/}}
{{- define "edr-platform.nats.labels" -}}
{{ include "edr-platform.labels" . }}
app.kubernetes.io/component: nats
{{- end }}

{{- define "edr-platform.nats.selectorLabels" -}}
{{ include "edr-platform.selectorLabels" . }}
app.kubernetes.io/component: nats
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "edr-platform.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "edr-platform.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Server image reference (registry/repo:tag).
*/}}
{{- define "edr-platform.server.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" -}}
{{- $repo := .Values.server.image.repository -}}
{{- $tag := .Values.server.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
Frontend image reference.
*/}}
{{- define "edr-platform.frontend.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" -}}
{{- $repo := .Values.frontend.image.repository -}}
{{- $tag := .Values.frontend.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
Postgres image reference.
*/}}
{{- define "edr-platform.postgres.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" -}}
{{- $repo := .Values.postgres.image.repository -}}
{{- $tag := .Values.postgres.image.tag -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
NATS image reference.
*/}}
{{- define "edr-platform.nats.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" -}}
{{- $repo := .Values.nats.image.repository -}}
{{- $tag := .Values.nats.image.tag -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
Render imagePullSecrets list.
*/}}
{{- define "edr-platform.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
