{{/*
Expand the name of the chart.
*/}}
{{- define "pistonprotection.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "pistonprotection.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "pistonprotection.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "pistonprotection.labels" -}}
helm.sh/chart: {{ include "pistonprotection.chart" . }}
{{ include "pistonprotection.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "pistonprotection.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pistonprotection.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "pistonprotection.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pistonprotection.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Gateway component labels
*/}}
{{- define "pistonprotection.gateway.labels" -}}
{{ include "pistonprotection.labels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{- define "pistonprotection.gateway.selectorLabels" -}}
{{ include "pistonprotection.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Worker component labels
*/}}
{{- define "pistonprotection.worker.labels" -}}
{{ include "pistonprotection.labels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{- define "pistonprotection.worker.selectorLabels" -}}
{{ include "pistonprotection.selectorLabels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Operator component labels
*/}}
{{- define "pistonprotection.operator.labels" -}}
{{ include "pistonprotection.labels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{- define "pistonprotection.operator.selectorLabels" -}}
{{ include "pistonprotection.selectorLabels" . }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Frontend component labels
*/}}
{{- define "pistonprotection.frontend.labels" -}}
{{ include "pistonprotection.labels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{- define "pistonprotection.frontend.selectorLabels" -}}
{{ include "pistonprotection.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Database connection URL
*/}}
{{- define "pistonprotection.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
postgresql://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ include "pistonprotection.fullname" . }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
postgresql://{{ .Values.postgresql.external.username }}:{{ .Values.postgresql.external.password }}@{{ .Values.postgresql.external.host }}:{{ .Values.postgresql.external.port }}/{{ .Values.postgresql.external.database }}
{{- end }}
{{- end }}

{{/*
Redis connection URL
*/}}
{{- define "pistonprotection.redisUrl" -}}
{{- if .Values.redis.enabled }}
redis://:{{ .Values.redis.auth.password }}@{{ include "pistonprotection.fullname" . }}-redis-master:6379
{{- else }}
redis://:{{ .Values.redis.external.password }}@{{ .Values.redis.external.host }}:{{ .Values.redis.external.port }}
{{- end }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "pistonprotection.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
