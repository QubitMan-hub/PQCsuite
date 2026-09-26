{{- define "pqcsuite.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "pqcsuite.labels" -}}
app.kubernetes.io/name: pqcsuite
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "pqcsuite.caHost" -}}
{{ .Release.Name }}-ca.{{ .Release.Namespace }}.svc
{{- end }}

{{- define "pqcsuite.caEnv" -}}
{{- if .Values.ca.passphraseSecret }}
- name: PQCSUITE_CA_PASSPHRASE
  valueFrom:
    secretKeyRef:
      name: {{ .Values.ca.passphraseSecret }}
      key: passphrase
{{- end }}
{{- end }}
