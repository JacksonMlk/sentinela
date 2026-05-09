# Sentinela — Guia de Setup

## O que é essa aplicação?

Plataforma multi-tenant de FinOps & Segurança AWS que:
- Recebe o **ARN da Role IAM** de cada cliente
- Conecta à conta AWS do cliente via **STS AssumeRole**
- Coleta dados de **custos, recursos e segurança** usando boto3
- Analisa tudo com **Claude AI** para gerar insights profundos
- Exibe dashboards de **FinOps** e **Segurança** separados
- Gera **Quick Wins** (ações rápidas) e **Projetos** (iniciativas estratégicas)
- Permite que clientes acessem seu relatório via **token único** (portal read-only)

---

## Estrutura do Projeto

```
sentinela/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Configurações via .env
│   ├── database.py          # SQLAlchemy + SQLite/PostgreSQL
│   ├── models.py            # Modelos Client e AnalysisReport
│   ├── aws_analyzer.py      # Coleta de dados AWS via boto3
│   ├── claude_analyzer.py   # Análise com Claude AI
│   ├── routers/
│   │   ├── admin.py         # Painel admin
│   │   ├── finops.py        # Dashboard FinOps
│   │   ├── security.py      # Dashboard Segurança
│   │   └── client.py        # Portal do cliente (token)
│   └── templates/           # HTML templates (Jinja2)
├── k8s/                     # Manifests Kubernetes
├── requirements.txt
├── .env.example
└── SETUP.md
```

---

## Passo a Passo para Rodar

### 1. Pré-requisitos

- Python 3.10+
- Conta AWS com credenciais configuradas
- Chave de API da Anthropic (Claude)

### 2. Clone e configure o ambiente

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
# ou: venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

### 3. Configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite o `.env` com seus valores (veja `.env.example` para referência).

### 4. Configurar credenciais AWS

A aplicação precisa de credenciais AWS da conta operadora para assumir as roles dos clientes.

**Opção A — AWS CLI configurado:**
```bash
aws configure
export AWS_PROFILE=meu-perfil
```

**Opção B — Variáveis de ambiente:**
```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AWS_DEFAULT_REGION=us-east-1
```

**Opção C (recomendado em produção):** IAM Role na instância EC2/EKS com permissão de `sts:AssumeRole`.

### 5. Iniciar a aplicação

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Acesse: **http://localhost:8000** → redireciona para `/admin`

---

## Configurar a Role na conta do cliente

Na conta AWS do cliente, criar uma role com a seguinte Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::SEU_ACCOUNT_ID_OPERADOR:root"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Policies a anexar:**
```bash
aws iam attach-role-policy \
  --role-name SentinelaAnalyzerRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

aws iam attach-role-policy \
  --role-name SentinelaAnalyzerRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

---

## URLs da Aplicação

| URL | Descrição |
|-----|-----------|
| `/admin` | Dashboard admin geral |
| `/admin/clients/new` | Criar novo cliente |
| `/admin/clients/{id}` | Detalhes do cliente |
| `/finops/{id}` | Dashboard FinOps |
| `/security/{id}` | Dashboard Segurança |
| `/portal/{token}` | Portal do cliente (read-only) |

---

## Produção

1. **PostgreSQL** em vez de SQLite: `DATABASE_URL=postgresql://user:pass@host/dbname`
2. **Gunicorn**: `gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker`
3. **HTTPS** com certificado SSL
4. **IAM Role** na instância (sem credenciais hardcoded)
