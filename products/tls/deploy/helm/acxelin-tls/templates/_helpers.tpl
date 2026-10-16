{{- define "acxelin-tls.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "acxelin-tls.labels" -}}
app.kubernetes.io/name: acxelin-tls
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "acxelin-tls.caHost" -}}
{{ .Release.Name }}-ca.{{ .Release.Namespace }}.svc
{{- end }}

{{- /* The issuing CA's passphrase; the root's is only ever given to the init container. */}}
{{- define "acxelin-tls.caEnv" -}}
- name: ACXELIN_TLS_CA_PASSPHRASE
  valueFrom:
    secretKeyRef:
      name: {{ .Values.ca.passphraseSecret | default (printf "%s-ca-passphrase" .Release.Name) }}
      key: passphrase
{{- end }}

{{- /* One folder of the data volume: services see only what they use, never the root CA. */}}
{{- define "acxelin-tls.dataMount" -}}
- {name: data, mountPath: /data/{{ .dir }}, subPath: {{ .dir }}{{ if .ro }}, readOnly: true{{ end }}}
{{- end }}
