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
{{- define "artemis-core.fullname" -}}
  {{- printf "%s-%s" .Release.Name "artemis-core" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Override full names of upstream charts for deterministic host names
*/}}
{{- define "artemis.fullname" -}}
  {{- printf "%s-%s" .Release.Name "artemis" | trunc 63 | trimSuffix "-" -}}
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
Override Artemis configuration
*/}}
{{- define "artemis.config.useExistingConfigMap" -}}
  {{- true -}}
{{- end -}}

{{- define "artemis.config.configMapName" -}}
  {{- printf "%s-config" (include "artemis-core.fullname" .) -}}
{{- end -}}

{{/*
Override credentials and hosts of services with ones configured here. Global values take precedence, then values defined for the specific chart and only then we fall back to default usernames/passwords or generated host names.
*/}}
{{- define "artemis.psql.username" -}}
  {{- pluck "username" .Values.global.psql .Values.psql | first | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.password" -}}
  {{- pluck "password" .Values.global.psql .Values.psql | first | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.host" -}}
  {{- coalesce (pluck "host" .Values.global.psql .Values.psql | first) (printf "%s.%s.svc" (include "postgresql.fullname" .) .Release.Namespace) -}}
{{- end -}}

{{- define "artemis.psql.port" -}}
  {{- pluck "port" .Values.global.psql .Values.psql | first | default 5432 -}}
{{- end -}}

{{- define "artemis.psql.database" -}}
  {{- pluck "database" .Values.global.psql .Values.psql | first | default "artemis" -}}
{{- end -}}

{{- define "postgresql.username" -}}
  {{- coalesce .Values.global.psql.username .Values.postgresqlUsername | default "artemis" -}}
{{- end -}}

{{- define "postgresql.port" -}}
  {{- coalesce .Values.global.psql.port .Values.service.port | default 5432 -}}
{{- end -}}

{{- define "postgresql.secretName" -}}
  {{- printf "%s-postgresql-secret" (include "artemis-core.fullname" .) -}}
{{- end -}}

{{- define "postgresql.useExistingSecret" -}}
  {{- true -}}
{{- end -}}

{{- define "postgresql.database" -}}
  {{- coalesce .Values.global.psql.database .Values.postgresqlDatabase | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.useExistingSecret" -}}
  {{- true -}}
{{- end -}}

{{- define "artemis.psql.secretName" -}}
  {{- include "postgresql.secretName" . -}}
{{- end -}}

{{- define "artemis.rabbitmq.host" -}}
  {{- printf "%s.%s.svc" (include "rabbitmq.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "artemis.rabbitmq.username" -}}
  {{- coalesce .Values.global.rabbitmq.auth.username .Values.rabbitmq.username -}}
{{- end -}}

{{- define "artemis.rabbitmq.password" -}}
  {{- coalesce .Values.global.rabbitmq.auth.password .Values.rabbitmq.password -}}
{{- end -}}

{{- define "artemis.redis.host" -}}
  {{- printf "%s-master.%s.svc" (include "redis.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "rabbitmq.secretPasswordName" -}}
  {{- printf "%s-rabbitmq-secret" (include "artemis-core.fullname" .) -}}
{{- end -}}

{{- define "rabbitmq.secretErlangName" -}}
  {{- include "rabbitmq.secretPasswordName" . -}}
{{- end -}}

{{- define "artemis.rabbitmq.useExistingSecret" -}}
  {{- true -}}
{{- end -}}

{{- define "artemis.rabbitmq.secretName" -}}
  {{- include "rabbitmq.secretPasswordName" . -}}
{{- end -}}

{{/*
Set default adminer server. If defined, values from `.Values.global.psql.*` take precedence over `.Values.defaultHost` and `.Values.defaultPort`. If neither one is defined, host falls back to installed PostgreSQL service.
*/}}
{{- define "adminer.defaultServer" -}}
  {{- $host := coalesce .Values.global.psql.host .Values.defaultHost (printf "%s.%s.svc" (include "postgresql.fullname" .) .Release.Namespace) -}}
  {{- $port := (coalesce .Values.global.psql.port .Values.defaultPort | toString) -}}
  {{- printf "%s:%s" $host $port | trimSuffix ":" -}}
{{- end -}}
