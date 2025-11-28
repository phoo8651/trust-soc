# agent.yaml: 환경변수 기반 설정 분리

receivers:
  otlp:
    protocols:
      http:

exporters:
  otlphttp:
    endpoint: ${INGEST_ENDPOINT}
    headers:
      Authorization: "Bearer ${INGEST_TOKEN}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlphttp]
