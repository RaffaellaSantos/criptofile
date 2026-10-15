# Pasta `arquivos/`

Montada como volume no container `app` (ver `docker-compose.yml`) em `/arquivos`.

Coloque aqui os PDFs de teste e use a CLI apontando para o caminho do container:

```bash
docker compose run --rm app -p /arquivos/seu-arquivo.pdf
```

Os arquivos desta pasta **não são versionados no git** — apenas este `README.md` é.