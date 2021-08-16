{{/* vim: set filetype=mustache: */}}

{{/*
Redis config
*/}}

{{- define "artemis.redis.host" -}}
{{- .Values.redis.host | default "127.0.0.1" -}}
{{- end -}}

{{- define "artemis.redis.port" -}}
{{- .Values.redis.port | default 6379 -}}
{{- end -}}
