{{/*
=============================================================================
Kizashi - Helm Template Helpers
=============================================================================
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "kizashi.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully-qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to
63 characters (by the DNS naming spec).
If the release name already contains the chart name it will be used as-is.
*/}}
{{- define "kizashi.fullname" -}}
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
Create chart label value: "<chart-name>-<chart-version>"
*/}}
{{- define "kizashi.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "kizashi.labels" -}}
helm.sh/chart: {{ include "kizashi.chart" . }}
{{ include "kizashi.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kizashi-edr
{{- end }}

{{/*
Selector labels (used in matchLabels and Service selectors).
*/}}
{{- define "kizashi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kizashi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific selector labels.
Usage: include "kizashi.componentSelectorLabels" (dict "root" . "component" "api")
*/}}
{{- define "kizashi.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "kizashi.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component-specific common labels (selector labels + chart labels).
Usage: include "kizashi.componentLabels" (dict "root" . "component" "api")
*/}}
{{- define "kizashi.componentLabels" -}}
helm.sh/chart: {{ include "kizashi.chart" .root }}
{{ include "kizashi.componentSelectorLabels" . }}
{{- if .root.Chart.AppVersion }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: kizashi-edr
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "kizashi.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kizashi.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the name of the credentials secret.
When createSecrets=true the chart manages it; otherwise the user must supply it.
*/}}
{{- define "kizashi.secretName" -}}
{{- .Values.secretName | default (printf "%s-credentials" (include "kizashi.fullname" .)) }}
{{- end }}

{{/*
Return the PostgreSQL password secret name and key.
Prefers global.postgresql.existingSecret, falls back to the chart-managed secret.
*/}}
{{- define "kizashi.dbSecretName" -}}
{{- if .Values.global.postgresql.existingSecret }}
{{- .Values.global.postgresql.existingSecret }}
{{- else }}
{{- include "kizashi.secretName" . }}
{{- end }}
{{- end }}

{{- define "kizashi.dbSecretKey" -}}
{{- if .Values.global.postgresql.existingSecret }}
{{- .Values.global.postgresql.existingSecretKey | default "postgresql-password" }}
{{- else }}
postgresql-password
{{- end }}
{{- end }}

{{/*
Return the JWT secret name and key.
Prefers global.jwt.existingSecret, falls back to the chart-managed secret.
*/}}
{{- define "kizashi.jwtSecretName" -}}
{{- if .Values.global.jwt.existingSecret }}
{{- .Values.global.jwt.existingSecret }}
{{- else }}
{{- include "kizashi.secretName" . }}
{{- end }}
{{- end }}

{{- define "kizashi.jwtSecretKey" -}}
{{- if .Values.global.jwt.existingSecret }}
{{- .Values.global.jwt.existingSecretKey | default "jwt-secret" }}
{{- else }}
jwt-secret
{{- end }}
{{- end }}

{{/*
Build the DATABASE_URL for the API server.
Format: postgres://<user>:<password>@<host>:<port>/<database>?sslmode=require
The password is injected via a secret env var, so we reference the env var name here.
*/}}
{{- define "kizashi.databaseURL" -}}
{{- printf "postgres://%s@%s:%d/%s?sslmode=require"
    .Values.global.postgresql.user
    .Values.global.postgresql.host
    (.Values.global.postgresql.port | int)
    .Values.global.postgresql.database }}
{{- end }}

{{/*
Build a comma-separated NATS URL string from the urls list.
*/}}
{{- define "kizashi.natsURL" -}}
{{- join "," .Values.global.nats.urls }}
{{- end }}

{{/*
Return the image registry prefix (with trailing slash if set).
Prefers component-level registry; falls back to global.imageRegistry.
*/}}
{{- define "kizashi.imageRegistry" -}}
{{- $registry := .root.Values.global.imageRegistry }}
{{- if $registry }}
{{- printf "%s/" $registry }}
{{- end }}
{{- end }}

{{/*
Render a full image reference for a component.
Usage: include "kizashi.image" (dict "root" . "image" .Values.api.image)
*/}}
{{- define "kizashi.image" -}}
{{- $registry := .root.Values.global.imageRegistry }}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry .image.repository .image.tag }}
{{- else }}
{{- printf "%s:%s" .image.repository .image.tag }}
{{- end }}
{{- end }}

{{/*
Render imagePullSecrets block when global.imagePullSecrets is set.
*/}}
{{- define "kizashi.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}
