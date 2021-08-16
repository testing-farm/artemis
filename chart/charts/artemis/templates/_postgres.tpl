{{/* vim: set filetype=mustache: */}}

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
