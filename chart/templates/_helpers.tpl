{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "fullname" -}}
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
Override full names of upstream charts for deterministic host names
*/}}
{{- define "artemis.fullname" -}}
{{- include "fullname" . -}}
{{- end -}}

{{- define "postgresql.fullname" -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rabbitmq.fullname" -}}
{{- printf "%s-%s" .Release.Name "rabbitmq" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "redis.fullname" -}}
{{- printf "%s-%s" .Release.Name "redis" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Override credentials and hosts of services with ones configured here
*/}}
{{- define "artemis.psql.username" -}}
{{- .Values.global.psql.username | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.password" -}}
{{- .Values.global.psql.password | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.host" -}}
{{- printf "%s.%s.svc" (include "postgresql.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "artemis.psql.port" -}}
{{- .Values.global.psql.port | default 6379 -}}
{{- end -}}

{{- define "artemis.psql.database" -}}
{{- .Values.global.psql.database | default "artemis" -}}
{{- end -}}

{{- define "postgresql.username" -}}
{{- include "artemis.psql.username" . -}}
{{- end -}}

{{- define "postgresql.port" -}}
{{- include "artemis.psql.port" . -}}
{{- end -}}

{{- define "postgresql.secretName" -}}
{{- printf "%s-postgresql-secret" .Release.Name -}}
{{- end -}}

{{- define "postgresql.useExistingSecret" -}}
{{- true -}}
{{- end -}}

{{- define "postgresql.database" -}}
{{- include "artemis.psql.database" . -}}
{{- end -}}

{{- define "artemis.rabbitmq.host" -}}
{{- printf "%s.%s.svc" (include "rabbitmq.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "artemis.rabbitmq.username" -}}
{{- .Values.global.rabbitmq.auth.username -}}
{{- end -}}

{{- define "artemis.rabbitmq.password" -}}
{{- .Values.global.rabbitmq.auth.password -}}
{{- end -}}

{{- define "artemis.rabbitmq.port" -}}
{{- 5672 -}}
{{- end -}}

{{- define "artemis.redis.host" -}}
{{- printf "%s-master.%s.svc" (include "redis.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "artemis.redis.port" -}}
{{- 6379 -}}
{{- end -}}

{{- define "artemis.useExistingConfigMap" -}}
{{- true -}}
{{- end -}}

{{- define "artemis.configMapName" -}}
{{- printf "%s-config" (include "fullname" .) -}}
{{- end -}}
