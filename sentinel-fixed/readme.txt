=== WP Sentinel Security ===
Contributors: wpsentinelsecurity
Tags: security, vulnerability, malware, hardening, scanner
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced security plugin for WordPress — Detection, analysis and vulnerability management.

== Description ==

WP Sentinel Security is a comprehensive security solution for WordPress sites. It provides:

* **Vulnerability Scanner** — Scans core, plugins, and themes for known vulnerabilities using the WPScan vulnerability database.
* **File Integrity Monitoring** — Detects unauthorized changes to WordPress core files and plugin/theme files.
* **Malware Detection** — Scans PHP files for known malware patterns, backdoors, and suspicious code.
* **Configuration Analyzer** — Reviews your WordPress and PHP configuration for security misconfigurations.
* **Permission Checker** — Verifies file and directory permissions are set correctly.
* **User Audit** — Identifies security issues with WordPress user accounts.
* **Security Scoring** — Provides an overall security score based on CVSS v3 methodology.
* **Activity Log** — Tracks all security-relevant events on your site.
* **REST API** — Full REST API for integration with external systems.

= Features =

* Multi-site compatible
* Async scanning support
* Configurable alert notifications (email, Slack, Telegram)
* Detailed vulnerability reports
* Scheduled automatic scans
* CVSS v3 scoring methodology

== Installation ==

1. Upload the `wp-sentinel-security` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Sentinel Security** in the admin menu.
4. Configure your settings and run your first scan.

For enhanced vulnerability detection, add your WPScan API key in **Settings → API Keys**.

== Frequently Asked Questions ==

= Is a WPScan API key required? =

No. The plugin works without an API key, but adding one significantly improves vulnerability detection accuracy and provides access to more vulnerability data.

= How long does a scan take? =

Scan times vary by type:
* Quick Scan: 1–2 minutes
* Full Scan: 5–10 minutes
* Configuration Check: ~30 seconds

= Does this plugin slow down my site? =

No. Scans run in the background and are designed to have minimal impact on site performance. The async scanning option (enabled by default) ensures scans do not affect front-end performance.

= Is this plugin compatible with WordPress Multisite? =

Yes. WP Sentinel Security is fully compatible with WordPress Multisite installations and can be network-activated.

== Screenshots ==

1. Security Dashboard with overall score and vulnerability summary
2. Vulnerability Scanner with scan type selection
3. Scanner results with severity filtering
4. Settings page

== Changelog ==

= 2.0.0 =
* Phase 3 — Hardening Engine: 24 hardening checks across 6 categories (file security, wp-config, server, user, database, API)
* Phase 3 — File Hardening: disable file editing, block PHP in uploads, protect wp-config and .htaccess, add security headers
* Phase 3 — WP-Config Hardening: force SSL admin, disable debug in production, limit revisions, disable file editor
* Phase 3 — User Hardening: block user enumeration, enforce strong passwords, limit login attempts, hide WP version
* Phase 3 — Database Hardening: audit table prefix, database privileges, and password strength
* Phase 3 — API Hardening: disable XML-RPC, restrict REST API, disable oEmbed, disable pingbacks
* Phase 4 — Backup System: full/database/files backup with ZIP and SQL export, SHA-256 checksums, restore and delete
* Phase 4 — Backup Engine: progress tracking via transients, AJAX polling, backup history management
* Phase 5 — Report Engine: technical, executive, and compliance reports in HTML, JSON, and CSV formats
* Phase 5 — Report HTML Renderer: standalone HTML reports with inline CSS, print-ready styling, and branding support
* Phase 5 — Alert Engine: email, Slack, and Telegram alert channels with 1-hour throttling and 7 event types
* Phase 5 — Activity Logger: logs 12 security-relevant WordPress events to the activity log
* Phase 5 — New admin views: Hardening, Backups, Reports, Alerts, Activity Log
* Version bump to 2.0.0

= 1.0.0 =
* Initial release
* Vulnerability scanner (core, plugins, themes)
* File integrity monitoring
* Malware detection
* Configuration analyzer
* Permission checker
* User audit
* Security scoring
* Activity logging
* REST API
* Admin dashboard with charts

== Upgrade Notice ==

= 1.0.0 =
Initial release of WP Sentinel Security.
