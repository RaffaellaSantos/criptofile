# Projeto I de Redes de Computadores II

_Equipe_: Adriana Raffaella, Davi Aguiar, Guilherme Moraes, Henrique Furtado

## Critérios Obrigatórios

- [ ] Criptografia ou proteção de dados

- [ ] Autenticação e/ou controle de acesso

- [ ] Um mecanismo de análise, detecção ou proteção (Ex: Firewall, IDS, IPS, Análise de logs, anélise de tráfego, detector de comportamento suspeito)

- [ ] Um tema de segurança estudado de escolha própria

## Proposta do Projeto

Este documento proprõe a implementação de um sistema de arquivos criptografas com verificação de integridade de arquivos. Porrtanto, o projeto se compromete com a elaoração de uma aplicação para proteger arquivos e verificar se foram modificados. O sistema por meio de uma CLI será responsável por autenticar e autorizar um usuário previamente cadastrado a criptografar/descriptografar arquivos de sua escolha, manter um armazenamento seguro das chaves e realizar um cálculo de hash a fim de manter a integridade dos arquivos.

O projeto aborda conhecimentos acerca de criptografia, padrão de criptografia avançada (AES), confidencialidade, integridade, funções hash e autenticação.

## Requisitos de Projeto a serem atendidos

Código do Requisito | Requisito de Alto Nível | Requisito de Baixo Nível | Descrição
:----------:|:-------------:|:-----------:|:----------:
   01.1   |   Autenticação de Usuário    | Armazenamento Seguro | O sistema deve garantir o armazenamento seguro das credenciais do usuário
   01.2   |   Autenticação de Usuário    | Validação de Login | O sistema deve verificar se as informações de login são válidas antes de autorizar o acesso
   02.1   |   Gestão de Acessos         | Cadastrar novo Usuário | O sistema deve garantir que apenas usuários ADMIN podem cadastrar novos usuários
   02.2   |   Gestão de Acessos         | Gerencia de Acesso  | O sistema deve garantir que apenas usuários ADMIN podem gerenciar o nível de acesso dos usuários
   03.1   |   Criptografia de Arquivos  | Criptografar/Descriptografar Arquivos | O sistema deve garantir que todo usuário autenticado possa utilizar a criptografia e descriptografia de arquivos próprios
   03.2   |   Criptografia de Arquivos  | Acesso a Arquivos Criptografados | O sistema deve garantir que todo usuário autenticado possa ter acesso aos arquivos criptografados aos quais tem permissão
   04.1   |   Integridade de Arquivos  | Modificar Arquivos | O sistema deve garantir que apenas usuários autorizados possam modificar arquivos e que estes podem apenas modificar arquivos dos quais tem acesso.
   04.2   |   Integridade de Arquivos  | Compartilhamento | O sistema deve garantir que todo usuário possa dar permissão a outro usuário para modificar o arquivo
   04.3   |   Integridade de Arquivos  | Garantir a Integridade | O sistema deve garantir a integridade dos arquivos
   05.1   |   Auditoria do Sistema | Registro de Acessos | O sistema deve manter um registro dos acessos feitos ao sistema
   05.2   |   Auditoria do Sistema | Histórico de Alterações | O sistema deve manter o histório de arquivos que foram criptografados, modificados e consultados
   05.3   |   Auditoria do Sistema | Relatório de Logs | O sistema deve disponibilizar o relatório completo de usuários e alterações feitas apenas para o usuário ADMIN

## Arquitetura do Projeto

A arquitetura do CriptoFile CLI é baseada numa estrutura em camadas (Layered Architecture) modular, concebida para garantir a confidencialidade, integridade, autenticação e rastreabilidade na gestão local de ficheiros cifrados.

### Visão Geral da Arquitetura em Camadas

```
+-----------------------------------------------------------------+
|                      Interface CLI (Command Line)               |
+-----------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------+
|                  Módulo IAM (Autenticação & RBAC)               |
+-----------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------+
|            Motor Criptográfico & Integridade (Crypto & KMS)     |
+-----------------------------------------------------------------+
          |                                       |
          v                                       v
+-----------------------+               +-------------------------+
| Armazenamento Seguro  |               | Módulo de Auditoria &   |
| (Metadados & Ficheiros|               | Deteção de Anomalias    |
+-----------------------+               +-------------------------+
```

### Detalhes Técnicos dos Componentes

#### Módulo de Autenticação e Gestão de Acessos (IAM)

Atendimento dos Requisitos: 01.1, 01.2, 02.1, 02.2

Armazenamento Seguro de Credenciais:

   - As palavras-passe nunca são armazenadas em texto claro.

   - Utilização do algoritmo de derivação de chave Argon2id (com salt de 16 bytes gerado aleatoriamente por utilizador) para gerar a hash da palavra-passe e a chave mestre de utilizador.

Controlo de Acesso Baseado em Funções (RBAC):

   - Papeis (Roles): ADMIN e USER.

   - Sessão Local: Após autenticação com sucesso, é gerado um token temporário mantido apenas em memória durante a execução dos comandos na CLI.

#### 2.2 Motor Criptográfico e Gestão de Chaves (Crypto & KMS)

- Atendimento dos Requisitos: 03.1, 03.2, 04.1, 04.2, 04.3

- Tema de Segurança Escolhido: Criptografia de Envelope (Envelope Encryption) com AES-256-GCM e Troca de Chaves Cifradas.

- Mecanismo de Cifragem:

   - AES-256-GCM (Galois/Counter Mode): Utilizado para cifrar o conteúdo do ficheiro. Garante confidencialidade e autenticação dos dados cifrados via tag de autenticação GMAC.

- Estratégia de Gestão de Chaves (Envelope Encryption):

   1. Cada ficheiro cifrado tem uma chave simétrica única designada DEK (Data Encryption Key - AES-256).

   2. A DEK do ficheiro é cifrada com a KEK (Key Encryption Key) do proprietário/utilizador autorizado e guardada na tabela de metadados de permissões.

   3. Para partilhar o ficheiro com outro utilizador (Requisito 04.2), o sistema decifra a DEK do ficheiro e volta a cifrá-la utilizando a KEK do utilizador recetor, concedendo-lhe acesso à leitura/modificação.

- Verificação de Integridade:

   - É calculado o SHA-256 do ficheiro original antes de ser cifrado, e guardado no registo de metadados.

   - Antes de qualquer operação de leitura ou descriptografia, o sistema calcula a hash SHA-256 do ficheiro e valida se coincide com o registo original. Se houver discrepância, a operação é abortada e uma alerta de violação de integridade é acionado.

#### 2.3 Módulo de Auditoria e Deteção de Anomalias (Logging & Proteção)

- Atendimento dos Requisitos: 05.1, 05.2, 05.3

- Mecanismo de Análise e Deteção (Critério Obrigatório): Deteção de Comportamento Suspeito e Análise de Logs.

- Estrutura dos Logs:

   - Registos formatados em JSON/CEF guardados numa base de dados protegida ou ficheiro append-only com verificação de HMAC (evita adulteração dos próprios logs).

   - Atributos do Log: timestamp, user_id, action_type, resource_id, status (SUCCESS/FAIL), ip_address/hostname, signature_hmac.

- Regras do Detetor de Comportamento Suspeito:

   - Regra de Força Bruta: Múltiplas falhas consecutivas de login num curto intervalo (ex.: > 3 falhas em 60s) bloqueiam temporariamente a conta do utilizador e registam um evento SECURITY_ALERT.

   - Regra de Adulteração/Tampering: Qualquer falha na validação do hash SHA-256 durante a descriptografia gera um alerta imediato de INTEGRITY_VIOLATION.

#### 3. Modelo de Dados e Armazenamento

A persistência de metadados e permissões pode ser implementada utilizando uma base de dados relacional leve e cifrada (como SQLite com SQLCipher).

```
-- Tabela de Utilizadores
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT CHECK(role IN ('ADMIN', 'USER')) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Metadados dos Ficheiros
CREATE TABLE files (
    file_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
);

-- Tabela de Controlo de Acesso e Chaves Cifradas (Envelope Encryption)
CREATE TABLE file_permissions (
    permission_id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    encrypted_dek TEXT NOT NULL, -- DEK do ficheiro cifrada com a KEK deste utilizador
    can_modify BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (file_id) REFERENCES files(file_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Tabela de Logs de Auditoria
CREATE TABLE audit_logs (
    log_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id TEXT,
    action TEXT NOT NULL, -- LOGIN, ENCRYPT, DECRYPT, MODIFY, SHARE, INTEGRITY_FAIL
    resource_id TEXT,
    status TEXT NOT NULL, -- SUCCESS, FAIL, ALERT
    details TEXT,
    log_hmac TEXT NOT NULL -- HMAC para garantir a integridade do próprio registo de log
);
```

4. Matriz de Atendimento aos Critérios Obrigatórios

Critério Obrigatório |	Componente da Arquitetura | Implementação Técnica
:-------------------:|:--------------------------:|:---------------------
Criptografia ou Proteção de Dados | Motor Criptográfico | Cifragem AES-256-GCM para ficheiros e Argon2id para derivação de credenciais.
Autenticação / Controlo de Acesso | Módulo IAM (RBAC) | Autenticação por palavra-passe com controlo de permissões ADMIN vs USER.
Mecanismo de Análise / Deteção | Motor de Deteção de Anomalias em Logs | Monitorização em tempo real de tentativas de brute-force e alertas de violação de integridade (tampering).
Tema de Segurança Escolhido | Gestão Avançada de Chaves | Criptografia Envelope (Envelope Encryption) com chaves de dados (DEK) e chaves de utilizador (KEK).

#### 5. Fluxos Principais de Execução
Fluxo de Cifragem de Ficheiro pelo Utilizador

   1. O utilizador executa: securefs encrypt --file documento.pdf

   2. O Módulo IAM valida a sessão ativa do utilizador.

   3. O Motor Criptográfico:

      - Calcula o hash SHA-256 do documento.pdf.

      - Gera uma DEK (AES-256) aleatória para o ficheiro.

      - Cifra o ficheiro gerando o conteúdo cifrado + tag AES-GCM.

      - Cifra a DEK usando a KEK do utilizador.

   4. Os metadados e a DEK cifrada são guardados na base de dados (files e file_permissions).

    5. O Módulo de Auditoria regista o evento FILE_ENCRYPT com sucesso.

Fluxo de Verificação de Integridade e Descriptografia

   1. O utilizador executa: securefs decrypt --file documento.pdf.enc

   2. O sistema verifica se o utilizador possui registo em file_permissions.

   3. O Motor Criptográfico decifra a DEK e procede à descriptografia do conteúdo cifrado com AES-GCM.

   4. É calculado o hash SHA-256 do ficheiro resultante e comparado com o hash original presente na tabela files.

   5. Se os hashes coincidirem: O ficheiro em texto claro é entregue ao utilizador e regista-se FILE_DECRYPT (SUCCESS).

   6. Se houver divergência: O ficheiro é apagado temporariamente, a operação é bloqueada e o evento SECURITY_ALERT (INTEGRITY_VIOLATION) é gerado no log de auditoria.