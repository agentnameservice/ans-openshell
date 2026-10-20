{{- define "ans-openshell.image" -}}
{{ .spec.image.repository }}:{{ .spec.image.tag | default .root.Chart.AppVersion }}
{{- end -}}

{{- define "ans-openshell.service-config" -}}
{{- $config := deepCopy .spec.config -}}
{{- if .root.Values.gateway.jwksURL -}}
{{- $auth := merge (dict "jwks_url" .root.Values.gateway.jwksURL) (default (dict) $config.auth) -}}
{{- $config = merge (dict "auth" $auth) $config -}}
{{- end -}}
listen: ":{{ .spec.port }}"
health_listen: ":{{ .spec.healthPort }}"
tls:
  cert_file: /etc/ans-openshell/tls/tls.crt
  key_file: /etc/ans-openshell/tls/tls.key
{{ toYaml $config }}
{{- end -}}

{{/* One gRPC service: ConfigMap, Service, Deployment and PodDisruptionBudget. Called with a dict of root, name, spec. */}}
{{- define "ans-openshell.service" -}}
{{- $root := .root -}}
{{- $name := printf "%s-%s" $root.Release.Name .name -}}
{{- $serviceConfig := printf "%s\n" (include "ans-openshell.service-config" .) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ $name }}
data:
  config.yaml: |
{{ $serviceConfig | indent 4 }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $name }}
spec:
  selector:
    app: {{ $name }}
  ports:
    - name: grpc
      port: {{ .spec.port }}
      targetPort: grpc
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $name }}
spec:
  replicas: {{ .spec.replicas }}
  selector:
    matchLabels:
      app: {{ $name }}
  template:
    metadata:
      labels:
        app: {{ $name }}
      annotations:
        checksum/config: {{ $serviceConfig | sha256sum }}
    spec:
      terminationGracePeriodSeconds: {{ $root.Values.terminationGracePeriodSeconds }}
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: {{ $name }}
      containers:
        - name: {{ .name }}
          image: {{ include "ans-openshell.image" (dict "root" $root "spec" .spec) }}
          imagePullPolicy: {{ $root.Values.imagePullPolicy }}
          args: ["--config", "/etc/ans-openshell/config.yaml"]
          ports:
            - name: grpc
              containerPort: {{ .spec.port }}
            - name: health
              containerPort: {{ .spec.healthPort }}
          readinessProbe:
            httpGet: {path: /readyz, port: health}
            periodSeconds: 10
          livenessProbe:
            httpGet: {path: /healthz, port: health}
            periodSeconds: 20
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources: {{ toYaml $root.Values.resources | nindent 12 }}
          volumeMounts:
            - {name: config, mountPath: /etc/ans-openshell/config.yaml, subPath: config.yaml, readOnly: true}
            - {name: tls, mountPath: /etc/ans-openshell/tls, readOnly: true}
            - {name: trust, mountPath: /etc/ans-openshell/trust, readOnly: true}
{{- range $id, $secret := .spec.identitySecrets }}
            - {name: identity-{{ $id }}, mountPath: /var/run/secrets/ans-openshell/{{ $id }}, readOnly: true}
{{- end }}
      volumes:
        - name: config
          configMap: {name: {{ $name }}}
        - name: tls
          secret: {secretName: {{ $root.Values.tls.secretName }}}
        - name: trust
          configMap: {name: {{ $root.Values.trust.configMapName }}}
{{- range $id, $secret := .spec.identitySecrets }}
        - name: identity-{{ $id }}
          secret: {secretName: {{ $secret }}}
{{- end }}
{{- if and $root.Values.podDisruptionBudget.enabled (gt (int .spec.replicas) 1) }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ $name }}
spec:
  minAvailable: {{ $root.Values.podDisruptionBudget.minAvailable }}
  selector:
    matchLabels:
      app: {{ $name }}
{{- end }}
{{- end -}}
