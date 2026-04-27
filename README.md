# License Server (Render)

Server licenze minimale per CECCA, pronto deploy su Render.

## 1) Deploy su Render (consigliato)

1. Push di questa cartella in un repository Git.
2. In Render: `New` -> `Blueprint`.
3. Seleziona il repo e conferma il file `render.yaml`.
4. Render creerà automaticamente:
   - web service `cecca-license-server`
   - database Postgres `cecca-license-db`
5. Imposta la env `ADMIN_PASSWORD` (obbligatoria) prima del primo deploy.

## 2) Variabili ambiente Render

Le principali sono già in `render.yaml`. Verifica nel servizio web:

- `DATABASE_URL` = connection string Postgres Render
- `LICENSE_API_SECRET` = secret lungo casuale
- `ADMIN_USERNAME` = username pannello (es. `admin`)
- `ADMIN_PASSWORD` = password forte pannello

## 3) Endpoints

- `GET /health`
- `POST /api/validate` (Bearer required)
- `GET /admin` (Basic Auth)

Header:

`Authorization: Bearer <LICENSE_API_SECRET>`

Body supportati:

### Validazione con codice

```json
{ "code": "ABC-123" }
```

### Validazione zero-input con installazione

```json
{
  "installation_id": "uuid-macchina",
  "app_id": "zvanein",
  "request_mode": "auto_activate"
}
```

## 4) Dati iniziali

La tabella `licenses` viene creata automaticamente. Inserisci una licenza full:

```sql
insert into licenses (code, edition, active, max_installations)
values ('FULL-CLIENTE-001', 'full', true, 1);
```

Per zero-input puoi collegare l'installazione dal pannello `/admin`
(sezione "Collega Installazione"), senza SQL manuale.

## 5) Config CECCA client

Nel backend CECCA:

- `LICENSE_REMOTE_URL=https://<tuo-servizio>.onrender.com/api/validate`
- `LICENSE_REMOTE_SECRET=<LICENSE_API_SECRET>`
- `LICENSE_APP_ID=zvanein`

Poi puoi usare anche dominio custom Render (`license.tuodominio.it`).
