sudo mkdir -p /etc/secure-log-agent/remote.d

sudo cp /home/last/Lastagent/text4shell-otel-config.yaml /etc/secure-log-agent/agent.yaml

sudo touch /etc/secure-log-agent/remote.d/remote.yaml  # 일단 빈 파일로

sudo chown -R otel-agent:otel-agent /etc/secure-log-agent

sudo chmod 750 /etc/secure-log-agent
