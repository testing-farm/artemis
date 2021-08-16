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
Define templates for component names
*/}}
{{- define "artemis.api.name" -}}
{{- $name := (include "artemis.name" .) }}
{{- printf "%s-api" $name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.api.fullname" -}}
{{- $fullname := (include "artemis.fullname" .) }}
{{- printf "%s-api" $fullname | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.dispatcher.name" -}}
{{- $name := (include "artemis.name" .) }}
{{- printf "%s-dispatcher" $name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.dispatcher.fullname" -}}
{{- $fullname := (include "artemis.fullname" .) }}
{{- printf "%s-dispatcher" $fullname | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.scheduler.name" -}}
{{- $name := (include "artemis.name" .) }}
{{- printf "%s-scheduler" $name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.scheduler.fullname" -}}
{{- $fullname := (include "artemis.fullname" .) }}
{{- printf "%s-scheduler" $fullname | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.worker.name" -}}
{{- $name := (include "artemis.name" .) }}
{{- printf "%s-worker" $name | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.worker.fullname" -}}
{{- $fullname := (include "artemis.fullname" .) }}
{{- printf "%s-worker" $fullname | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "artemis.api.host" -}}
{{- printf "%s.%s.svc" (include "artemis.api.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "artemis.api.port" -}}
{{- .Values.api.port | default 8001 -}}
{{- end -}}

{{- define "artemis.image" -}}
{{- .Values.image -}}
{{- end -}}

{{- define "artemis.configDirMountPath" -}}
{{- printf "/etc/artemis" -}}
{{- end -}}

{{- define "artemis.vaultPassPath" -}}
{{- printf "%s/%s" (include "artemis.configDirMountPath" .) ".vault_pass" -}}
{{- end -}}

{{/*
Kerberos
*/}}
{{- define "artemis.kerberos.image" -}}
{{- .Values.kerberos.image -}}
{{- end -}}

{{- define "artemis.kerberos.ccacheDir" -}}
{{- printf "/tmp/krb5cc" -}}
{{- end -}}

{{- define "artemis.useExistingConfigMap" -}}
{{/* Probably can be done more elegantly */}}
{{- if .Values.existingConfigMap -}}
  {{- true -}}
{{- else -}}
  {{- false -}}
{{- end -}}
{{- end -}}

{{- define "artemis.configMapName" -}}
{{- if .Values.existingConfigMap -}}
  {{- .Values.existingConfigMap -}}
{{- else -}}
  {{- printf "%s-config" (include "artemis.fullname" .) -}}
{{- end -}}
{{- end -}}
