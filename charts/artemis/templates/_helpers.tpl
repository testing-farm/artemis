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
{{- define "artemis.imageUntagged" -}}
  {{- $global := (pluck "global" .Values | first) -}}
  {{- $registryName := coalesce (pluck "imageRegistry" $global | first) .Values.image.registry -}}
  {{- $repositoryName := .Values.image.repository -}}
  {{- printf "%s/%s" $registryName $repositoryName -}}
{{- end -}}

{{- define "artemis.image" -}}
  {{- $tag := default .Chart.AppVersion .Values.image.tag | toString -}}
  {{- printf "%s:%s" (include "artemis.imageUntagged" .) $tag -}}
{{- end -}}

{{- define "artemis.initdb.image" -}}
  {{- printf "%s:latest" (include "artemis.imageUntagged" .) -}}
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
  {{- not (empty .Values.existingConfigMap) -}}
{{- end -}}

{{/*
Define configMap name. If provided, `.Values.existingConfigMap` takes precedence,
otherwise fallback to generated configMap.
*/}}
{{- define "artemis.config.configMapName" -}}
  {{- if .Values.existingConfigMap -}}
    {{- .Values.existingConfigMap -}}
  {{- else -}}
    {{- printf "%s-config" (include "artemis.fullname" .) -}}
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
PostgreSQL
*/}}
{{- define "artemis.psql.host" -}}
  {{- pluck "host" .Values.psql .Values.global.psql | first -}}
{{- end -}}

{{- define "artemis.psql.port" -}}
  {{- pluck "port" .Values.psql .Values.global.psql | first -}}
{{- end -}}

{{/*
RabbitMQ
*/}}
{{- define "artemis.rabbitmq.host" -}}
  {{- pluck "host" .Values.rabbitmq .Values.global.rabbitmq | first -}}
{{- end -}}

{{- define "artemis.rabbitmq.port" -}}
  {{- pluck "port" .Values.rabbitmq .Values.global.rabbitmq | first -}}
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

{{/*
Secrets
*/}}
{{- define "artemis.psql.useExistingSecret" -}}
  {{- if .Values.psql.existingSecret -}}
    {{- true -}}
  {{- end -}}
{{- end -}}

{{- define "artemis.psql.secretName" -}}
  {{- .Values.psql.existingSecret | default (printf "%s-postgresql" (include "artemis.fullname" .)) -}}
{{- end -}}

{{- define "artemis.rabbitmq.useExistingSecret" -}}
  {{- if .Values.rabbitmq.existingSecret -}}
    {{- true -}}
  {{- end -}}
{{- end -}}

{{- define "artemis.rabbitmq.secretName" -}}
  {{- .Values.rabbitmq.existingSecret | default (printf "%s-rabbitmq" (include "artemis.fullname" .)) -}}
{{- end -}}

{{/*
Helper function to concatenate list of strings into a single string
*/}}
{{- define "artemis.concatList" -}}
  {{- $sep := .separator -}}
  {{- $list := .list -}}
  {{- $result := dict "str" "" -}}
  {{- range $list -}}
    {{- $_ := printf "%s%s%s" $result.str $sep . | set $result "str" -}}
  {{- end -}}
  {{- $result.str | trimPrefix $sep | print -}}
{{- end -}}
