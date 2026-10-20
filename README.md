# CriptoFile CLI

O **CriptoFile CLI** é um sistema de linha de comando (CLI) focado na segurança da informação, desenvolvido para garantir a confidencialidade, integridade, autenticação e rastreabilidade na gestão local de arquivos.

A aplicação utiliza criptografia avançada (AES-256-GCM) e um modelo de *Envelope Encryption*, garantindo que apenas usuários autenticados e autorizados possam acessar ou modificar documentos sensíveis.

---

## Funcionalidades Principais

- **Autenticação e Controle de Acesso (RBAC):** Gestão de usuários com papéis definidos (`ADMIN` e `USER`), com senhas protegidas por Argon2id (RFC 9106). Uma única derivação gera tanto o hash de verificação quanto a KEK do usuário, que nunca é armazenada. Excesso de falhas de login (4ª falha em uma janela de 60s) bloqueia a conta temporariamente e emite um `SECURITY_ALERT`. Migrações são aplicadas automaticamente pelo Alembic a cada comando.
- **Criptografia de Envelope (Envelope Encryption):** Utiliza chaves de dados (DEK) para os arquivos e chaves de criptografia (KEK) atreladas aos usuários, permitindo o compartilhamento seguro sem expor as chaves mestre. No compartilhamento a DEK é envolvida com RSA-OAEP (SHA-256) e, na **revogação, a DEK é trocada** (o arquivo é re-cifrado): quem perdeu o acesso não abre versões seguintes, mesmo que tenha guardado a DEK antiga.
- **Proteção da Chave Privada:** A `private.pem` gerada pelo usuário é gravada cifrada com a KEK da sessão (`chmod 600`) e a pública fica vinculada ao perfil no banco. Sem login válido, a chave privada é ilegível.
- **Verificação de Integridade:** Cálculo e validação de hash (SHA-256) antes da cifragem e durante a descriptografia para evitar e detectar adulterações (*tampering*). O comando `verify` confere tag AES-GCM e hash SHA-256 sem descriptografar o arquivo.
- **Auditoria e Detecção de Anomalias:** Registro detalhado de eventos (login, alterações de papel, operações com arquivos, `INTEGRITY_VIOLATION`, `SECURITY_ALERT` etc.), cada log assinado com HMAC-SHA256; o relatório valida as assinaturas antes de exibir e sinaliza registros adulterados, com exportação em JSON e CEF. Tentativas de acesso sem permissão também são auditadas. Os eventos formam uma **cadeia assinada** (cada um assina também o anterior) e a ponta da cadeia fica registrada fora do banco: tanto a remoção de um evento do meio quanto a dos eventos mais recentes são detectadas.
- **Robustez:** arquivos são processados em blocos (memória constante para qualquer tamanho); gravações são atômicas (temporário + troca) e nunca sobrescrevem arquivos existentes; arquivos criados pelo sistema têm permissão `0600`; o texto claro original é sobrescrito antes de ser apagado; operações simultâneas sobre o mesmo arquivo são serializadas por versão (*compare-and-swap*); uma gravação interrompida por queda do processo é concluída automaticamente no acesso seguinte.

## Tecnologias Utilizadas

- **Linguagem:** Python 3.13
- **Criptografia:** [pycryptodome](https://github.com/Legrandin/pycryptodome) (AES-256-GCM, RSA-OAEP, SHA-256) e [argon2-cffi](https://github.com/hynek/argon2-cffi) (Argon2id)
- **Banco de Dados:** PostgreSQL (via SQLAlchemy e psycopg2)
- **Migrações:** Alembic
- **Testes:** pytest
- **Gerenciamento de Dependências:** [uv](https://github.com/astral-sh/uv)
- **Interface CLI:** argparse + [Rich](https://github.com/Textualize/rich) (+ [rich-argparse](https://github.com/hamdanal/rich-argparse))
- **Infraestrutura:** Docker Compose

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
   POSTGRES_PORT=5432
   DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}

   # Chave (hex, 32 bytes) do HMAC que assina o log de auditoria. Se omitida,
   # o sistema gera uma e a guarda em .audit_key (chmod 600) no diretório de dados.
   AUDIT_HMAC_KEY=

   # Diretório de dados locais (workspace/ com as chaves privadas, .audit_key,
   # .audit_key.head e app.log). Padrão: a raiz do projeto. No Docker é /data.
   CRIPTOFILE_HOME=
   ```
   O `.env` e o diretório de dados são localizados a partir da raiz do projeto: o resultado é o mesmo qualquer que seja a pasta de onde o comando é executado.
   O `DATABASE_URL` acima aponta para o serviço `db` do Compose. Para rodar comandos fora do Docker, troque `@db` por `@localhost`. Se já houver um PostgreSQL instalado na máquina usando a porta 5432, troque `POSTGRES_PORT` e a porta do `DATABASE_URL` para outra (ex.: 5433).

3. Suba os containers:
   ```bash
   docker-compose up -d --build
   ```
   O Compose sobe o banco (`db`), aplica as migrações automaticamente (`migrate`) e o serviço da aplicação (`app`). Os comandos rodam dentro do container; use `-it`, pois as senhas são pedidas de forma interativa:
   ```bash
   docker compose run --rm -it app --help
   docker compose run --rm -it app admin-init -u admin
   docker compose run --rm -it app encrypt -p /arquivos/doc.pdf -u admin
   ```
   - Arquivos a cifrar ficam em `./arquivos` do projeto, visível no container como `/arquivos`.
   - As chaves privadas, a chave HMAC e os logs ficam no volume `criptofile_data` (`/data`), preservado entre execuções. `docker compose down -v` apaga esse volume **e as chaves privadas** junto: os arquivos cifrados deixam de abrir.
   - Recomenda-se definir `AUDIT_HMAC_KEY` no `.env` (o Compose a repassa ao container), mantendo a chave do log fora do volume de dados.
   - A imagem não inclui `workspace/`, `.audit_key` nem `arquivos/` do host (veja `.dockerignore`).
   Opcionalmente há um cliente web para o banco (`dbgate`) em `http://localhost:3005`.

### Usando Ambiente Local (sem Docker)

1. Instale as dependências usando o `uv`:
   ```bash
   uv sync
   ```

   Os exemplos desta documentação chamam o comando `criptofile` diretamente.
   Como o executável é criado dentro do ambiente virtual, execute a CLI com
   `uv run` ou ative o venv antes:
   ```bash
   uv run criptofile --help    # sem ativar o venv
   # ou
   source .venv/bin/activate   # a partir daí, `criptofile` direto
   ```
   Para ter o comando disponível em qualquer terminal:
   ```bash
   uv tool install --editable .
   ```

2. Suba o banco de dados PostgreSQL e aponte o `DATABASE_URL` para ele.

3. As migrações são aplicadas automaticamente na primeira execução de qualquer comando; para aplicá-las manualmente:
   ```bash
   uv run alembic upgrade head
   ```

4. Executar os testes:
   ```bash
   uv run pytest
   ```
   Os testes usam SQLite em memória. Para validar também as migrações num PostgreSQL real, aponte `CRIPTOFILE_TEST_POSTGRES_URL` para um banco **descartável** (o teste apaga as tabelas):
   ```bash
   CRIPTOFILE_TEST_POSTGRES_URL=postgresql+psycopg2://user:senha@localhost:5432/criptofile_test uv run pytest tests/test_migrations.py
   ```

## 💻 Como Usar

A interface de linha de comando possui os seguintes comandos:

### Gestão de Usuários (Módulo IAM)

As senhas são sempre solicitadas de forma interativa (sem eco no terminal) e nunca passadas como argumento.

```bash
# Cria o primeiro ADMIN (só funciona com o banco vazio)
criptofile admin-init -u admin

# Valida as credenciais de um usuário
criptofile login -u alice

# Operações exclusivas de ADMIN (o --as indica quem executa)
criptofile user-add  --as admin -u alice -r USER
criptofile user-role --as admin -u alice -r ADMIN
criptofile user-list --as admin
```

### Motor Criptográfico

A cifragem usa Envelope Encryption: cada arquivo recebe uma DEK AES-256 única, envolvida com a KEK do autor (e com a chave pública RSA do alvo, na partilha), guardada em `file_permissions`. O hash SHA-256 do original é registrado em `files` e validado a cada descriptografia e a cada `verify` — divergência aborta a operação com um evento `INTEGRITY_VIOLATION`.

A chave privada do usuário (`workspace/alice/private.pem`, no diretório de dados) é gravada cifrada com a KEK da sessão: qualquer comando criptográfico exige login e a pasta do usuário tem permissão restrita (`chmod 700`).

Após a criptografia/descriptografia o sistema salva por padrão o arquivo escolhido na pasta do usuário dono do arquivo; use `-o` para indicar outro destino.

```bash
#  Gera o par de chaves RSA (private.pem cifrada com a KEK; pública vai ao banco)
criptofile genkeys -u alice

#  Substituir um par existente exige --force: arquivos recebidos de outros
#  usuários (encrypt -t / share) ficam ilegíveis. Use só se a chave foi perdida.
criptofile genkeys -u alice --force
```
```bash
#  Criptografa um arquivo para você mesmo (workspace/alice/doc.pdf.enc)
criptofile encrypt -p ./doc.pdf -u alice
```

```bash
#  Criptografa para outro usuário ler (bob) (workspace/bob/doc.pdf.enc)
criptofile encrypt -p ./doc.pdf -u alice -t bob
```

```bash
#  Descriptografa um arquivo em que você tem permissão (workspace/alice/doc.pdf)
criptofile decrypt -p ./doc.enc -u alice
```

```bash
#  Confere a integridade de um arquivo .enc sem descriptografá-lo:
#  valida a tag AES-GCM e o hash SHA-256 registrado
criptofile verify -p ./doc.pdf.enc -u alice
```

```bash
#  Lista os arquivos acessíveis pelo usuário (próprios e compartilhados)
criptofile file-list -u alice
```

```bash
#  Concede a bob acesso a um arquivo .enc (nível "read" ou "modify"; padrão: read)
criptofile share -p ./doc.pdf.enc -u alice -t bob --permission read
```

```bash
#  Substitui o conteúdo de um arquivo .enc existente (exige MODIFY; o hash
#  registrado em `files` passa a corresponder ao novo conteúdo)
criptofile update -p ./doc.pdf.enc -c ./doc-atualizado.pdf -u alice
```

```bash
#  Revoga o acesso de bob (apenas o dono do arquivo). A DEK do arquivo é
#  trocada e reenvolvida para quem continua autorizado.
criptofile revoke -p ./doc.pdf.enc -u alice -t bob
```

_Todo tipo de arquivo pode ser criptografado — apenas o autor e os usuários autorizados conseguem descriptografar. Para cifrar/partilhar para outro usuário (`-t`), ele precisa ter gerado suas chaves antes com_ `genkeys`_. Divergência de tag AES-GCM ou de hash em qualquer operação registra_ `INTEGRITY_VIOLATION` _e aborta._

_No compartilhamento (04.2), a DEK do arquivo é reenvolvida com a chave pública RSA do receptor: só usuários com_ `MODIFY` _podem repassar o acesso, e a revogação é exclusiva do dono._

_Na modificação (04.1), quem tem_ `READ` _só decifra: substituir o conteúdo do `.enc` exige_ `MODIFY` _, e a DEK é preservada para que os demais autorizados continuem com acesso._

### Relatório de Auditoria (apenas ADMIN)

Antes de exibir qualquer relatório, o sistema verifica a assinatura HMAC de cada log: registros adulterados são sinalizados em quadro de alerta independentemente do formato escolhido.

```bash
#  Relatório completo em tabela (verifica antes a assinatura HMAC de cada log)
criptofile audit-report --as admin
```

```bash
#  Relatório filtrado por usuário e por ação
criptofile audit-report --as admin -u bob -a FILE_ENCRYPT
```

```bash
#  Exportar o relatório em JSON ou CEF para um arquivo (ou stdout sem -o)
criptofile audit-report --as admin --export cef -o logs/auditoria.cef
```

_Somente usuários com papel_ `ADMIN` _conseguem ler o relatório — tentativas de outros papéis são bloqueadas e registradas como_ `AUDIT_REPORT (FAIL)`._ O próprio acesso ao relatório também é auditado._

_Se os eventos mais recentes forem removidos do banco, o relatório passa a exibir um alerta persistente (a ponta registrada em_ `.audit_key.head` _não existe mais no banco). Novos eventos não apagam essa evidência. Depois de investigar (por exemplo, se o banco foi recriado de propósito), remova o arquivo_ `.audit_key.head` _do diretório de dados para reiniciar o registro da ponta._

## Arquitetura

O CriptoFile segue uma arquitetura em camadas (Layered Architecture):

1. **Interface CLI:** Ponto de entrada do usuário via terminal.
2. **Módulo IAM:** Responsável pelo RBAC e autenticação segura.
3. **Motor Criptográfico:** Lida com AES-256-GCM, SHA-256 e geração de DEKs/KEKs.
4. **Módulo de Auditoria:** Monitora anomalias, assina e valida a integridade dos logs via HMAC.
5. **Armazenamento Seguro:** Banco relacional para guardar permissões, hashes e logs protegidos.

## Estrutura do Projeto

```
app/
├── cli/            # Subcomandos (IAM, criptografia e auditoria)
├── core/           # Configuração, conexão com o banco e sessões
├── exceptions/     # Exceções de cada módulo
├── model/          # Modelos SQLAlchemy (users, files, file_permissions, audit_log)
├── service/        # Regras de negócio (IAM, criptografia, auditoria)
└── utils/          # Utilitários (validação, primitivas criptográficas)
migrations/         # Migrações Alembic
tests/              # Testes (pytest)
```

## Equipe de Desenvolvimento
- Adriana Raffaella
- Davi Aguiar
- Guilherme Moraes
- Henrique Furtado