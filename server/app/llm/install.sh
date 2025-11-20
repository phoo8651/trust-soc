#!/bin/bash

echo "=============================="
echo "🛠  trust-soc LLM Install Script"
echo "📌 Ubuntu/Debian Linux Supported"
echo "=============================="
sleep 1

# ===============================
# 1) 기본 패키지 설치
# ===============================
echo "📦 Installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv build-essential git wget curl

# ===============================
# 2) Python venv 생성
# ===============================
echo "🐍 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# ===============================
# 3) PyPI requirements 설치
# ===============================
echo "📦 Installing Python packages..."
pip install --upgrade pip

# requirements.txt는 repo root (../)
pip install -r ../requirements.txt

# ===============================
# 4) llama-cpp 설치 (CPU 기본)
# ===============================
echo "🤖 Installing llama-cpp-python (CPU mode, GGUF runtime for Mistral)..."
pip install llama-cpp-python --verbose --force-reinstall --no-cache-dir

# ===============================
# 5) 모델 디렉토리 (llm/models/)
# ===============================
echo "📂 Preparing model directory..."
mkdir -p models
cd models

# ===============================
# 6) 모델 자동 다운로드
# ===============================
MODEL_URL="https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf"

if [ ! -f "mistral-7b-instruct-v0.2.Q4_K_M.gguf" ]; then
  echo "↓ Downloading model (≈ 4GB)..."
  wget $MODEL_URL
else
  echo "✔ Model already exists, skipping download."
fi

# 돌아가기 (llm/)
cd ..

# ===============================
# 7) 환경 변수 생성 (.env in llm/)
# ===============================
echo "🔧 Setting environment variables..."
cat <<EOF > .env
LLM_MODE=local
LOCAL_MODEL=./models/mistral-7b-instruct-v0.2.Q4_K_M.gguf
WEBHOOK_SECRET=change_me_please
EOF

echo "=============================="
echo "🎉 Installation Completed!"
echo "🚀 Run with:"
echo "👉  source venv/bin/activate && uvicorn llm.advisor_api:app --reload --port 10555"
echo "=============================="
