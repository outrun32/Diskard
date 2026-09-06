# Zero-configuration local console

The Docker console creates its PostgreSQL schema and a default `investment-local`
target profile automatically. The profile uses the bundled local investment stand,
the standard Keycloak test users (`client1001` through `client1004`), and the local
Mongo and invest-server endpoints.

Start Diskard from the repository root:

```bash
docker compose up --build -d
```

Open <http://localhost:8700/> and select `investment-local`. When a run starts,
Diskard obtains short-lived access tokens and API keys for the test users through
the local Keycloak realm. No target credential variables or target profile file are
needed for this local mode.

The target stand must be running and reachable from Docker at:

- `http://host.docker.internal:8600` — agent API;
- `http://host.docker.internal:8180` — Keycloak;
- `http://host.docker.internal:8200` — invest-server;
- `mongodb://host.docker.internal:27017` — evidence store.

The stand's model provider credentials are owned by the stand and must remain in
its local environment. They are not copied into Diskard or committed to Git.

For a non-local target, create `config/targets.yaml` from
`config/targets.example.yaml` and provide the referenced credentials through `.env`
or mounted secret files as before.
