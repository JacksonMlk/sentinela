#!/usr/bin/env bash
set -euo pipefail

# ─── Config ────────────────────────────────────────────────────────────────
# Preencha com os valores da sua conta antes de executar
AWS_ACCOUNT="${AWS_ACCOUNT:-YOUR_AWS_ACCOUNT_ID}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"
ECR_REPO="sentinela"
IMAGE_TAG="${IMAGE_TAG:-latest}"
EKS_CLUSTER="${EKS_CLUSTER:-YOUR_EKS_CLUSTER_NAME}"
NAMESPACE="sentinela"

ECR_URI="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"

echo "==> Sentinela — Deploy"
echo "    Conta:    ${AWS_ACCOUNT}"
echo "    Região:   ${AWS_REGION}"
echo "    ECR:      ${ECR_URI}:${IMAGE_TAG}"
echo "    Cluster:  ${EKS_CLUSTER}"
echo ""

# ─── 1. Criar repositório ECR (idempotente) ─────────────────────────────────
echo "[1/5] ECR — criando repositório (se não existir)..."
aws ecr describe-repositories \
    --repository-names "${ECR_REPO}" \
    --region "${AWS_REGION}" \
    --profile "${AWS_PROFILE}" \
    --output text 2>/dev/null \
  || aws ecr create-repository \
       --repository-name "${ECR_REPO}" \
       --region "${AWS_REGION}" \
       --profile "${AWS_PROFILE}" \
       --image-scanning-configuration scanOnPush=true \
       --output text

# ─── 2. Autenticar Docker no ECR ────────────────────────────────────────────
echo "[2/5] Docker — autenticando no ECR..."
aws ecr get-login-password --region "${AWS_REGION}" --profile "${AWS_PROFILE}" \
  | docker login --username AWS --password-stdin "${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# ─── 3. Build + Push ────────────────────────────────────────────────────────
echo "[3/5] Docker — build..."
docker build \
  --platform linux/amd64 \
  -t "${ECR_URI}:${IMAGE_TAG}" \
  -f Dockerfile \
  .

echo "[3/5] Docker — push..."
docker push "${ECR_URI}:${IMAGE_TAG}"

# ─── 4. Configurar kubectl ──────────────────────────────────────────────────
echo "[4/5] kubectl — atualizando kubeconfig..."
aws eks update-kubeconfig \
  --name "${EKS_CLUSTER}" \
  --region "${AWS_REGION}" \
  --profile "${AWS_PROFILE}"

# ─── 5. Deploy no EKS ───────────────────────────────────────────────────────
echo "[5/5] Kubernetes — aplicando manifestos..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Força rollout com a nova imagem
kubectl rollout restart deployment/sentinela -n "${NAMESPACE}"
kubectl rollout status  deployment/sentinela -n "${NAMESPACE}" --timeout=120s

echo ""
echo "✅ Deploy concluído!"
echo "   Aguarde ~2 min para o ALB provisionar e DNS propagar."
echo "   URL: https://YOUR_DOMAIN"
