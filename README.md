# CriptoFile CLI

O **CriptoFile CLI** é um sistema de linha de comando (CLI) focado na segurança da informação, desenvolvido para garantir a confidencialidade, integridade, autenticação e rastreabilidade na gestão local de arquivos. 

A aplicação utiliza criptografia avançada (AES-256-GCM) e um modelo de *Envelope Encryption*, garantindo que apenas usuários autenticados e autorizados possam acessar ou modificar documentos sensíveis.

---

## Funcionalidades Principais

- **Autenticação e Controle de Acesso (RBAC):** Gestão de usuários com papéis definidos (`ADMIN` e `USER`), garantindo armazenamento seguro de credenciais com Argon2id.
- **Criptografia de Envelope (Envelope Encryption):** Utiliza chaves de dados (DEK) para os arquivos e chaves de criptografia (KEK) atreladas aos usuários, permitindo o compartilhamento seguro sem expor as chaves mestre.
- **Verificação de Integridade:** Cálculo e validação de hash (SHA-256) antes da cifragem e durante a descriptografia para evitar e detectar adulterações (*tampering*).
- **Auditoria e Detecção de Anomalias:** Registro detalhado de logs em formato JSON/CEF e bloqueio automático em casos de força bruta ou falha de integridade.

## Tecnologias Utilizadas

- **Linguagem:** Python 3.13
- **Banco de Dados:** PostgreSQL (via SQLAlchemy e psycopg2)
- **Migrações:** Alembic
- **Gerenciamento de Dependências:** [uv](https://github.com/astral-sh/uv)
- **Interface CLI:** argparse + [Rich](https://github.com/Textualize/rich)
- **Infraestrutura:** Docker & Docker Compose

## Pré-requisitos

Antes de começar, certifique-se de ter instalado em sua máquina:
- [Docker](https://www.docker.com/) e Docker Compose
- [Python 3.13+](https://www.python.org/downloads/) (Caso deseje rodar localmente sem Docker)
- [uv](https://github.com/astral-sh/uv) (Gerenciador de pacotes Python)

## Instalação e Configuração

### Usando Docker (Recomendado)

1. Clone o repositório:
   ```bash
   git clone <url-do-repositorio>
   cd criptofile
   ```

2. Configure as variáveis de ambiente:
   O projeto já inclui um arquivo `.env-EXAMPLE` de desenvolvimento, mas você pode customizá-lo:
   ```bash
   cp .env-EXAMPLE .env
   ```
   ```env
   POSTGRES_USER=ps_user
   POSTGRES_PASSWORD=senha_super_dificil
   POSTGRES_DB=criptofile_db
   DATABASE_URL=postgresql://POSTGRES_USER:POSTGRES_PASSWORD@db:5432/POSTGRES_DB
   ```

3. Suba os containers da aplicação e do banco de dados:
   ```bash
   docker-compose up -d --build
   ```

### Usando Ambiente Local (sem Docker)

1. Instale as dependências usando o `uv`:
   ```bash
   uv sync
   ```

2. Suba o banco de dados PostgreSQL.

3. Execute as migrações para criar as tabelas:
   ```bash
   uv run alembic upgrade head
   ```

## 💻 Como Usar

A interface de linha de comando possui os seguintes comandos e opções básicas:

```bash
# Executando a validação de um arquivo PDF
criptofile -p /caminho/para/seu/arquivo.pdf
# ou
criptofile --path /caminho/para/seu/arquivo.pdf
```

### Exemplo de Saída
```text
[+] Informações Iniciais do Arquivo [+]
Caminho recebido : /caminho/para/seu/arquivo.pdf
Nome do arquivo  : arquivo
Caminho absoluto : /home/usuario/caminho/para/seu/arquivo.pdf
----------------------------------------
```

*(Nota: Outros comandos de encriptação, decriptação e gerenciamento de usuários serão documentados conforme a evolução da CLI).*

## Arquitetura

O CriptoFile segue uma arquitetura em camadas (Layered Architecture):

1. **Interface CLI:** Ponto de entrada do usuário via terminal.
2. **Módulo IAM:** Responsável pelo RBAC e autenticação segura.
3. **Motor Criptográfico:** Lida com AES-256-GCM, SHA-256 e geração de DEKs/KEKs.
4. **Módulo de Auditoria:** Monitora anomalias e mantém a integridade dos logs.
5. **Armazenamento Seguro:** Banco relacional para guardar permissões, hashes e logs protegidos.

## Equipe de Desenvolvimento
- Adriana Raffaella
- Davi Aguiar
- Guilherme Moraes
- Henrique Furtado