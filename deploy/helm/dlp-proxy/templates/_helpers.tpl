{{- define "dlp-proxy.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "dlp-proxy.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dlp-proxy.labels" -}}
app.kubernetes.io/name: {{ include "dlp-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
