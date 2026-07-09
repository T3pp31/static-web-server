# GitHub Security Advisory Draft

## Advisory Details

### Title

Path traversal in markdown content negotiation may allow remote attackers to probe files outside the document root

### Description

#### Summary

Static Web Server (SWS) does not sanitize the URI path in its markdown content negotiation pre-processor before invoking filesystem `metadata()` operations. When the server is started with `--accept-markdown` (or `accept_markdown = true`), an unauthenticated remote attacker can send a request with `Accept: text/markdown` and a path containing `../` to cause the server to call `std::fs::metadata` on files outside the configured document root. File contents are not returned to the client because the static file handler later sanitizes the path and returns 404, but the metadata system call is still issued, leaking the existence of arbitrary files and creating a timing side channel.

#### Details

The `markdown::pre_process` function in `src/markdown.rs` received the raw URI path and built a `PathBuf` by pushing it onto `base_path` without calling `sanitize_path`:

- `src/markdown.rs:34-39` — `markdown::pre_process` (vulnerable code, now fixed)
- `src/fs/meta.rs:112-139` — `try_markdown_variant`, which calls `try_metadata` / `std::fs::metadata`
- `src/handler.rs:314-318` — call site: `pre_process` is invoked only when `accept_markdown` is enabled

The vulnerable code was:

```rust
// src/markdown.rs:34-39
let mut file_path = base_path.to_path_buf();
let sanitized_path = uri_path.trim_start_matches('/');
if !sanitized_path.is_empty() {
    file_path.push(sanitized_path);
}
```

This only removed a leading slash. It did not percent-decode the path, strip `..`/`./` segments, or block Windows drive prefixes. `try_markdown_variant` then appends `.md`, `.html.md`, or `index.html.md` and calls `std::fs::metadata`. Because `set_file_name` does not normalize `..` components, the OS resolves `<root>/../etc/passwd.md` to `/etc/passwd.md` during the `metadata()` call.

The existing path sanitization helper `sanitize_path` is used in `src/static_files/mod.rs:57` but was **not** called in `markdown::pre_process` (`src/fs/path.rs:84-112`).

The later `md_path.strip_prefix(base_path)` did not prevent this leak: it returned a relative path still containing `..` (e.g., `../etc/passwd.md`), which was then formatted into `/../etc/passwd.md` and passed to `static_files::handle`. That handler sanitizes the URI and returns 404, but the unauthorized `metadata()` call has already occurred.

This is only reachable when `accept_markdown` is enabled. The `RequestHandlerOpts` default sets `accept_markdown: false` (`src/handler.rs:192`), so deployments must opt-in via `--accept-markdown` or TOML config.

#### Fix

The fix reuses the existing `sanitize_path` helper in `markdown::pre_process` before any filesystem metadata call is made:

```rust
// src/markdown.rs:35-36
let file_path = sanitize_path(base_path, uri_path).ok()?;
```

This strips `..`, `.`, and Windows drive prefix components, percent-decodes the URI path, and ensures the resolved path stays under `base_path`. A regression test (`test_markdown_pre_process_rejects_traversal`) was added to `src/markdown.rs` to verify that `../` segments cannot probe files outside the document root.

Fix commit: `9690e05` (`fix(markdown): prevent path traversal in markdown content negotiation`).

#### PoC

1. Temporary unit test (now committed as `test_markdown_pre_process_rejects_traversal` in `src/markdown.rs`):

```rust
#[test]
fn markdown_traversal_poc() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let base_dir = tmp_dir.path().join("base");
    std::fs::create_dir(&base_dir).unwrap();

    // Create a markdown file outside the base directory
    let outside_md = tmp_dir.path().join("outside.md");
    std::fs::write(&outside_md, "outside").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("http://localhost/../outside")
        .header("Accept", "text/markdown")
        .body(crate::body::empty())
        .unwrap();

    let result = crate::markdown::pre_process(&req, &base_dir, "/../outside");
    // Vulnerable: pre_process returns Some("/../outside.md")
    assert!(result.as_deref().unwrap_or_default().contains(".."));
}
```

2. Runtime request against a server started with `--accept-markdown`:

```http
GET /../etc/passwd HTTP/1.1
Host: localhost
Accept: text/markdown
```

Observed with `strace`/`dtruss`, the server performs `stat`/`lstat` on `<root>/../etc/passwd.md`, `<root>/../etc/passwd.html.md`, and `<root>/../etc/passwd/index.html.md`, resolving outside the configured root directory.

#### Impact

A remote, unauthenticated attacker can cause the server to probe the existence of arbitrary files on the host filesystem outside the configured document root. This leaks file existence through timing differences and error behavior, and causes unauthorized filesystem access. File contents are not returned to the attacker, so the confidentiality impact is limited to file existence. Integrity and availability are not affected.

## Affected products

### Ecosystem

`cargo` (Rust / crates.io)

### Package name

`static-web-server`

### Affected versions

- `>= 2.40.0, < 2.43.1` (all 2.x releases from the feature introduction up to `2.43.0`)
- `master` branch before `9690e05`

### Patched versions

- `2.43.1` (or next release after `2.43.0`) — pending release
- `master` branch `9690e05` and later

_Note: If the next release is versioned `2.44.0` instead of `2.43.1`, update the affected range to `>= 2.40.0, < 2.44.0`._

## Severity

### Severity rating

Medium (5.3)

### CVSS v3.1 vector string

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

### CVSS rationale

- **AV:N** — The attack can be sent over the network.
- **AC:L** — No special conditions are required beyond the feature being enabled.
- **PR:N** — No authentication or privileges are required.
- **UI:N** — No user interaction is required.
- **S:U** — The vulnerable and impacted component are the same SWS process; the filesystem access is still performed by the server process.
- **C:L** — Only file existence is leaked, not file contents.
- **I:N** — No integrity impact.
- **A:N** — No availability impact.

## Weaknesses

- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Evidence

- Repository: `https://github.com/static-web-server/static-web-server`
- Package registry: `https://crates.io/crates/static-web-server`
- Feature introduced in commit: `2c25d82` (`feat: content negotiation for markdown files via Accept header (#577)`)
- First tagged release containing the vulnerable code: `v2.40.0`
- Vulnerable code:
  - `src/markdown.rs:22-53` — `pre_process`
  - `src/fs/meta.rs:112-139` — `try_markdown_variant`
  - `src/handler.rs:314-318` — call site gated by `accept_markdown`
- Existing sanitization not reused: `src/fs/path.rs:84-112` (`sanitize_path` is used in `src/static_files/mod.rs:57` but not in `src/markdown.rs` until the fix)
- Fix commit: `9690e05` (`fix(markdown): prevent path traversal in markdown content negotiation`)
- Regression test: `test_markdown_pre_process_rejects_traversal` in `src/markdown.rs`
- PoC result: The regression test fails before `9690e05` (`pre_process` returns `Some("/../outside.md")` and reaches outside the base directory) and passes after the fix.

## References

- `https://github.com/static-web-server/static-web-server/commit/9690e05`
- `https://github.com/static-web-server/static-web-server/security/advisories` (pending)
