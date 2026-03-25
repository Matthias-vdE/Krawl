# Deployment Modes

Krawl supports two deployment modes: **standalone** and **scalable**. The mode is controlled by the `mode` setting in `config.yaml` or the `KRAWL_MODE` environment variable.

## Standalone Mode (default)

The original single-instance deployment using SQLite and an in-memory cache.

| Component | Technology |
|-----------|------------|
| Database | SQLite (WAL mode) |
| Cache | In-memory Python dict |
| Replicas | 1 (single instance only) |

**When to use**: single-node deployments, development, low-traffic honeypots, or when you want the simplest possible setup with no external dependencies.

### Configuration

No extra configuration needed — standalone is the default.

```yaml
# config.yaml
mode: standalone

database:
  path: "data/krawl.db"
```

Or via environment variable:

```bash
KRAWL_MODE=standalone
```

## Scalable Mode

Multi-instance deployment backed by MariaDB and Redis, allowing horizontal scaling.

| Component | Technology |
|-----------|------------|
| Database | MariaDB |
| Cache | Redis |
| Replicas | 1+ (horizontal scaling) |

**When to use**: production deployments that need high availability, multiple replicas behind a load balancer, or when you expect high request volumes.

### Configuration

```yaml
# config.yaml
mode: scalable

mariadb:
  host: "localhost"
  port: 3306
  user: "krawl"
  password: "krawl"
  database: "krawl"

redis:
  host: "localhost"
  port: 6379
  db: 0
  password: null
```

Or via environment variables:

```bash
KRAWL_MODE=scalable

KRAWL_MARIADB_HOST=localhost
KRAWL_MARIADB_PORT=3306
KRAWL_MARIADB_USER=krawl
KRAWL_MARIADB_PASSWORD=krawl
KRAWL_MARIADB_DATABASE=krawl

KRAWL_REDIS_HOST=localhost
KRAWL_REDIS_PORT=6379
KRAWL_REDIS_DB=0
KRAWL_REDIS_PASSWORD=
```

### What changes between modes

| Concern | Standalone | Scalable |
|---------|-----------|----------|
| Data storage | SQLite file on disk | MariaDB server |
| Dashboard cache | Thread-locked Python dict | Redis with key prefix and 10-minute TTL |
| Rate limiting / bans | SQLite queries | MariaDB with row-level locking |
| Deployment strategy (K8s) | `Recreate` (SQLite file lock) | `RollingUpdate` (shared DB) |
| SQLite PVC (K8s) | Required | Not used |
| Multiple replicas | Not supported | Fully supported |
| External dependencies | None | MariaDB + Redis |

---

## Running Scalable Mode

### Docker Compose

A dedicated compose file is provided with MariaDB and Redis pre-configured:

```bash
docker compose -f docker-compose.scalable.yaml up -d
```

This starts three services:
- **krawl-mariadb**: MariaDB 11 with a persistent volume
- **krawl-redis**: Redis 7 Alpine with a persistent volume
- **krawl-server**: Krawl in scalable mode, waits for healthy DB/cache before starting

To stop:

```bash
docker compose -f docker-compose.scalable.yaml down
```

The standalone compose file (`docker-compose.yaml`) remains unchanged for standalone mode.

### Kubernetes (Helm)

Set the mode in your Helm values:

```yaml
# values.yaml
mode: scalable

mariadb:
  host: "mariadb"
  port: 3306
  user: "krawl"
  password: "krawl"
  database: "krawl"

redis:
  host: "redis"
  port: 6379
  db: 0
  password: ""
```

Or via `--set` flags:

```bash
helm upgrade krawl ./helm \
  --set mode=scalable \
  --set mariadb.host=mariadb \
  --set mariadb.password=krawl \
  --set redis.host=redis
```

When `mode=scalable`:
- The SQLite PVC is **not created**
- The deployment strategy switches to `RollingUpdate`
- MariaDB and Redis credentials are injected via Kubernetes Secrets
- `replicaCount` can be safely increased above 1

> **Note**: You are responsible for deploying MariaDB and Redis separately (e.g., via their official Helm charts or managed services). The Krawl chart only configures the connection to them.

### Docker Run

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_MODE=scalable \
  -e KRAWL_MARIADB_HOST=your-mariadb-host \
  -e KRAWL_MARIADB_PORT=3306 \
  -e KRAWL_MARIADB_USER=krawl \
  -e KRAWL_MARIADB_PASSWORD=krawl \
  -e KRAWL_MARIADB_DATABASE=krawl \
  -e KRAWL_REDIS_HOST=your-redis-host \
  -e KRAWL_REDIS_PORT=6379 \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

### Uvicorn (Python)

Set the environment variables before starting:

```bash
export KRAWL_MODE=scalable
export KRAWL_MARIADB_HOST=localhost
export KRAWL_MARIADB_PORT=3306
export KRAWL_MARIADB_USER=krawl
export KRAWL_MARIADB_PASSWORD=krawl
export KRAWL_MARIADB_DATABASE=krawl
export KRAWL_REDIS_HOST=localhost
export KRAWL_REDIS_PORT=6379

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --app-dir src
```

---

## Migrating Data from Standalone to Scalable

When switching from standalone to scalable mode, you can transfer existing data from SQLite to MariaDB using the included migration script.

### Prerequisites

- MariaDB must be running and reachable
- The target database must exist (the script creates tables automatically)
- Krawl should be **stopped** during migration to avoid SQLite write locks

### Migration Script

The migration script is located at `scripts/migrate_sqlite_to_mariadb.py`. It:
1. Reads all tables from the SQLite database
2. Creates the schema in MariaDB
3. Copies rows in configurable batches (default: 1000)
4. Falls back to row-by-row insert on batch errors
5. Prints a verification summary comparing source and destination row counts

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sqlite-path` | (required) | Path to the SQLite database file |
| `--mariadb-host` | `localhost` | MariaDB hostname |
| `--mariadb-port` | `3306` | MariaDB port |
| `--mariadb-user` | `krawl` | MariaDB username |
| `--mariadb-password` | `krawl` | MariaDB password |
| `--mariadb-database` | `krawl` | MariaDB database name |
| `--batch-size` | `1000` | Rows per INSERT batch |
| `--drop-existing` | `false` | Drop existing MariaDB tables before migrating |

### Local / Docker Host

```bash
# 1. Stop Krawl
docker compose down
# or: kill the uvicorn process

# 2. Start MariaDB (if not already running)
docker run -d --name krawl-mariadb \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=krawl \
  -e MYSQL_USER=krawl \
  -e MYSQL_PASSWORD=krawl \
  -p 3306:3306 \
  mariadb:11

# 3. Run the migration
python scripts/migrate_sqlite_to_mariadb.py \
  --sqlite-path data/krawl.db \
  --mariadb-host localhost \
  --mariadb-port 3306 \
  --mariadb-user krawl \
  --mariadb-password krawl \
  --mariadb-database krawl

# 4. Start Krawl in scalable mode
docker compose -f docker-compose.scalable.yaml up -d
```

### Docker Compose

If you're already using the standalone `docker-compose.yaml`:

```bash
# 1. Stop the standalone stack
docker compose down

# 2. Start only MariaDB and Redis from the scalable stack
docker compose -f docker-compose.scalable.yaml up -d mariadb redis

# 3. Run migration from the host (SQLite data is in ./data/)
python scripts/migrate_sqlite_to_mariadb.py \
  --sqlite-path data/krawl.db \
  --mariadb-host localhost \
  --mariadb-port 3306 \
  --mariadb-user krawl \
  --mariadb-password krawl \
  --mariadb-database krawl

# 4. Start the full scalable stack
docker compose -f docker-compose.scalable.yaml up -d
```

Alternatively, run the migration inside a container with access to both volumes:

```bash
docker compose -f docker-compose.scalable.yaml run --rm \
  -v ./data:/app/data:ro \
  krawl python /app/scripts/migrate_sqlite_to_mariadb.py \
    --sqlite-path /app/data/krawl.db \
    --mariadb-host mariadb \
    --mariadb-user krawl \
    --mariadb-password krawl \
    --mariadb-database krawl
```

### Kubernetes (Helm)

In Kubernetes, the SQLite data lives on a PersistentVolumeClaim. The Helm chart includes a migration Job that mounts the existing PVC and writes to MariaDB.

```bash
# 1. Scale down Krawl to release the SQLite PVC and avoid locks
kubectl scale deployment <release>-krawl --replicas=0

# 2. Ensure MariaDB is deployed and reachable in the same namespace

# 3. Run the migration Job
helm upgrade <release> ./helm \
  --set migration.enabled=true \
  --set mariadb.host=mariadb \
  --set mariadb.password=<mariadb-password>

# 4. Wait for the Job to complete and verify
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s
kubectl logs job/<release>-krawl-migrate

# 5. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set mariadb.host=mariadb \
  --set mariadb.password=<mariadb-password> \
  --set redis.host=redis \
  --set replicaCount=2
```

#### Helm migration values

| Value | Default | Description |
|-------|---------|-------------|
| `migration.enabled` | `false` | Create the migration Job |
| `migration.sqliteFilename` | `krawl.db` | SQLite filename inside the PVC |
| `migration.batchSize` | `1000` | Rows per INSERT batch |
| `migration.dropExisting` | `false` | Drop MariaDB tables before migrating |
| `migration.existingClaim` | auto | Override the source PVC name (defaults to `<release>-krawl-db`) |
| `migration.backoffLimit` | `3` | Job retry attempts |
| `migration.ttlSecondsAfterFinished` | `3600` | Auto-cleanup the completed Job after this many seconds |

> **Important**: After confirming the migration succeeded, you can safely delete the old SQLite PVC to reclaim storage. The PVC is not automatically deleted when switching to scalable mode.
