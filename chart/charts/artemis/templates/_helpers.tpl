{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "artemis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "artemis.fullname" -}}
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
{{- define "artemis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "artemis.labels" -}}
helm.sh/chart: {{ include "artemis.chart" . }}
{{ include "artemis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "artemis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "artemis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Construct image string
*/}}
{{- define "artemis.image" -}}
{{- $global := (pluck "global" .Values | first) -}}
{{- $registryName := coalesce (pluck "imageRegistry" $global | first) .Values.image.registry -}}
{{- $repositoryName := .Values.image.repository -}}
{{- $tag := .Values.image.tag | toString -}}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}

{{/*
Template for `.vault_pass` path. If `.Values.vaultPassword` is not provided, it is
assumed, the `.vault_pass` was provided in `conf/` directory.
*/}}
{{- define "artemis.vaultPassPath" -}}
{{- printf "%s/%s" (include "artemis.configDirMountPath" .) ".vault_pass" -}}
{{- end -}}

{{/*
Flag to signal whether external configMap with Artemis configuration was provided
*/}}
{{- define "artemis.config.useExistingConfigMap" -}}
{{- ternary true false .Values.existingConfigMap -}}
{{- end -}}

{{/*
Define configMap name. If provided, `.Values.existingConfigMap` takes precedence,
otherwise fallback to generated configMap.
*/}}
{{- define "artemis.config.configMapName" -}}
{{- if .Values.existingConfigMap -}}
{{-   .Values.existingConfigMap -}}
{{- else -}}
{{-   printf "%s-config" (include "artemis.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Calculate config checksum.
*/}}
{{- define "artemis.config.checksum" -}}
{{- include (print $.Template.BasePath "/config-configmap.yaml") $ | sha256sum -}}
{{- end -}}

{{/*
Mount path for artemis configuration
*/}}
{{- define "artemis.config.mountPath" -}}
{{- printf "/etc/artemis" -}}
{{- end -}}

{{/*
Database schema revision. If not provided in values, defaults to artemis version
*/}}
{{- define "artemis.dbSchemaRevision" -}}
{{- .Values.dbSchemaRevision | default .Chart.appVersion -}}
{{- end -}}

{{/*
Kerberos
*/}}
{{- define "artemis.kerberos.image" -}}
{{- $global := (pluck "global" .Values | first) -}}
{{- $registryName := coalesce (pluck "imageRegistry" $global | first) .Values.kerberos.image.registry -}}
{{- $repositoryName := .Values.kerberos.image.repository -}}
{{- $tag := .Values.kerberos.image.tag | toString -}}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}

{{- define "artemis.kerberos.ccacheDir" -}}
{{- printf "/dev/shm/ccache" -}}
{{- end -}}

{{/*
PostgreSQL config
*/}}
{{- define "artemis.psql.username" -}}
{{- .Values.psql.username | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.password" -}}
{{- .Values.psql.password | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.database" -}}
{{- .Values.psql.database | default "artemis" -}}
{{- end -}}

{{- define "artemis.psql.host" -}}
{{- .Values.psql.host | default "127.0.0.1" -}}
{{- end -}}

{{- define "artemis.psql.port" -}}
{{- .Values.psql.port | default 6379 -}}
{{- end -}}

{{/*
RabbitMQ config
*/}}
{{- define "artemis.rabbitmq.username" -}}
{{- .Values.rabbitmq.username | default "artemis" -}}
{{- end -}}

{{- define "artemis.rabbitmq.password" -}}
{{- .Values.rabbitmq.password | default "artemis" -}}
{{- end -}}

{{- define "artemis.rabbitmq.host" -}}
{{- .Values.rabbitmq.host | default "127.0.0.1" -}}
{{- end -}}

{{- define "artemis.rabbitmq.port" -}}
{{- .Values.rabbitmq.port | default 5672 -}}
{{- end -}}

{{/*
Redis config
*/}}
{{- define "artemis.redis.enabled" -}}
{{- default false .Values.redis.enabled -}}
{{- end -}}

{{- define "artemis.redis.host" -}}
{{- .Values.redis.host | default "127.0.0.1" -}}
{{- end -}}

{{- define "artemis.redis.port" -}}
{{- .Values.redis.port | default 6379 -}}
{{- end -}}
