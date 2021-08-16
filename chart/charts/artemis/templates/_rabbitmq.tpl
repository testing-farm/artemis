{{/* vim: set filetype=mustache: */}}

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
{{- .Values.rabbitmq.port | default 6379 -}}
{{- end -}}
