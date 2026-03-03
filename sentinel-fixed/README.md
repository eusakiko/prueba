# WP Sentinel Security
Plugin avanzado de seguridad para WordPress — Detección, análisis y gestión de vulnerabilidades.

## Security Hardening (v1.0.1)

The following defensive improvements were applied in this release:

- **REST API**: Added `enum`/`minimum`/`maximum` constraints and `sanitize_callback` to all route argument schemas; callbacks now perform explicit allowlist checks for `scan_type`, vulnerability `status`, and filter parameters. Pagination is bounded (1–100 per page). Invalid `id` values now return HTTP 400 before any database query.
- **AJAX handlers**: All existing AJAX entry points already enforce `check_ajax_referer` and `current_user_can( 'manage_options' )` per action (no changes required).
- **Environment fingerprint**: The full list of loaded PHP extensions is no longer included in fingerprint output (only the count is returned). The raw server IP address is also omitted; only the boolean `is_local` flag is retained.
- **Uninstall cleanup**: `uninstall.php` now canonicalises the backup directory path with `realpath()` and verifies that it lies within `WP_CONTENT_DIR` before deletion. Symlinks are unlinked rather than recursed into, and a `is_writable()` guard is added.
