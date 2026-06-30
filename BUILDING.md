# Building `dh-p2p` Correctly

This project should be built so that `run.sh` and manual runs both execute the same binary:

- Expected runtime binary path: `./target/release/dh-p2p`
- `run.sh` executes that exact path.

## Canonical Release Build

Always build with `CARGO_TARGET_DIR=target`:

```bash
CARGO_TARGET_DIR=target cargo build --release
```

This guarantees Cargo writes artifacts to `./target/...` inside the repository.

## Verify You Built the Right Binary

After building, validate the executable and available flags:

```bash
./target/release/dh-p2p --help
```

If you recently added CLI options, confirm they appear in this output before running `./run.sh`.

## Why This Matters

If `CARGO_TARGET_DIR` points somewhere else (for example, a temporary cache directory), `cargo build` can succeed while `./target/release/dh-p2p` remains stale. In that case:

- `./run.sh` may run an old binary
- new CLI flags may fail with `unexpected argument`

## Recommended Local Workflow

```bash
# 1) Create your local secret config once
cp .env.example .env
$EDITOR .env

# 2) Build
CARGO_TARGET_DIR=target cargo build --release

# 3) Optional quick check
./target/release/dh-p2p --help

# 4) Run with project defaults
./run.sh
```

`run.sh` is safe to commit because it reads the camera serial from `.env`.
The `.env` file is ignored by Git so local device secrets stay on your machine.

