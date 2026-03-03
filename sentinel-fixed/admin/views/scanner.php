<?php
/**
 * Scanner view.
 *
 * @package WP_Sentinel_Security
 * @var array $scan_history Recent scan history.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-search sentinel-header-icon"></span>
			<h1><?php esc_html_e( 'Security Scanner', 'wp-sentinel-security' ); ?></h1>
		</div>
	</div>

	<!-- Scan Type Cards -->
	<h2><?php esc_html_e( 'Select Scan Type', 'wp-sentinel-security' ); ?></h2>
	<div class="sentinel-grid sentinel-scan-types">

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-search sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Full Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Comprehensive scan of all components (5–10 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="full">
				<?php esc_html_e( 'Start Full Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-performance sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Quick Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Fast scan: core, plugins, and config (1–2 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="quick">
				<?php esc_html_e( 'Start Quick Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-wordpress sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Core Integrity', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Verify WordPress core file integrity (1 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="core">
				<?php esc_html_e( 'Scan Core', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-plugins-checked sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Plugins', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check installed plugins for vulnerabilities (2–3 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="plugins">
				<?php esc_html_e( 'Scan Plugins', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-art sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Themes', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check installed themes for vulnerabilities (1–2 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="themes">
				<?php esc_html_e( 'Scan Themes', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-media-document sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'File Monitor', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Detect unauthorized file changes and malware (3–5 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="files">
				<?php esc_html_e( 'Scan Files', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-admin-settings sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Configuration', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Analyze WordPress and PHP configuration (~30 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="config">
				<?php esc_html_e( 'Scan Config', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-shield sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Malware Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Deep scan for malware, backdoors and obfuscated code (3–8 min).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="malware">
				<?php esc_html_e( 'Scan for Malware', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-admin-users sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'User Audit', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Audit user accounts, roles, and password policies (~15 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="user_audit">
				<?php esc_html_e( 'Audit Users', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-lock sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'SSL / TLS', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check SSL certificate expiry and HTTPS configuration (~10 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="ssl">
				<?php esc_html_e( 'Check SSL', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-networking sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'HTTP Headers', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Verify security response headers (CSP, HSTS, X-Frame, etc.) (~10 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="headers">
				<?php esc_html_e( 'Check Headers', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-list-view sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Compliance', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check OWASP Top 10, PCI-DSS and GDPR compliance (~30 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="compliance">
				<?php esc_html_e( 'Check Compliance', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-scan-type-card">
			<span class="dashicons dashicons-database sentinel-scan-icon"></span>
			<h3><?php esc_html_e( 'Database', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Check for DB prefixes, user privileges and SQL injection risks (~15 s).', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-start-scan" data-scan-type="database">
				<?php esc_html_e( 'Scan Database', 'wp-sentinel-security' ); ?>
			</button>
		</div>

	</div>

	<!-- Scan Progress (hidden by default) -->
	<div id="sentinel-scan-progress" class="sentinel-card" style="display:none;">
		<h2><?php esc_html_e( 'Scan in Progress', 'wp-sentinel-security' ); ?></h2>
		<div class="sentinel-progress-bar-wrap">
			<div class="sentinel-progress-bar">
				<div class="sentinel-progress-fill" id="sentinelProgressFill" style="width:0%"></div>
			</div>
			<span id="sentinelProgressText">0%</span>
		</div>
		<p id="sentinelProgressStatus"><?php esc_html_e( 'Initializing scan...', 'wp-sentinel-security' ); ?></p>
		<button class="button button-secondary" id="sentinelCancelScan">
			<?php esc_html_e( 'Cancel Scan', 'wp-sentinel-security' ); ?>
		</button>
	</div>

	<!-- Results Section (hidden by default) -->
	<div id="sentinel-scan-results" class="sentinel-card" style="display:none;">
		<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
			<h2 style="margin:0;"><?php esc_html_e( 'Scan Results', 'wp-sentinel-security' ); ?></h2>
			<button class="button button-secondary" onclick="document.getElementById('sentinel-scan-results').style.display='none';">
				<?php esc_html_e( 'Close', 'wp-sentinel-security' ); ?>
			</button>
		</div>
		<p id="sentinel-results-scan-info" style="color:#64748b;font-size:12px;margin-bottom:12px;display:none;"></p>

		<!-- Severity filter tabs -->
		<div class="sentinel-filter-tabs">
			<button class="sentinel-tab active" data-filter="all"><?php esc_html_e( 'All', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-critical" data-filter="critical"><?php esc_html_e( 'Critical (Do today)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-high" data-filter="high"><?php esc_html_e( 'High (Within 48h)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-medium" data-filter="medium"><?php esc_html_e( 'Medium (This week)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-low" data-filter="low"><?php esc_html_e( 'Low (Monitor)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-info" data-filter="info"><?php esc_html_e( 'Info', 'wp-sentinel-security' ); ?></button>
		</div>

		<!-- Bulk actions toolbar -->
		<div class="sentinel-bulk-toolbar" style="display:flex;align-items:center;gap:8px;margin-bottom:12px;padding:10px 14px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">
			<label style="display:flex;align-items:center;gap:6px;font-size:13px;color:#64748b;margin:0;">
				<input type="checkbox" id="sentinel-select-all">
				<?php esc_html_e( 'Select all', 'wp-sentinel-security' ); ?>
			</label>
			<select id="sentinel-bulk-action" style="font-size:13px;">
				<option value=""><?php esc_html_e( '— Bulk action —', 'wp-sentinel-security' ); ?></option>
				<option value="ignored"><?php esc_html_e( 'Mark as ignored', 'wp-sentinel-security' ); ?></option>
				<option value="false_positive"><?php esc_html_e( 'Mark as false positive', 'wp-sentinel-security' ); ?></option>
				<option value="fixed"><?php esc_html_e( 'Mark as fixed', 'wp-sentinel-security' ); ?></option>
				<option value="open"><?php esc_html_e( 'Reopen', 'wp-sentinel-security' ); ?></option>
			</select>
			<button id="sentinel-bulk-apply" class="button button-secondary" style="font-size:13px;">
				<?php esc_html_e( 'Apply', 'wp-sentinel-security' ); ?>
			</button>

			<!-- Export button — separated visually from bulk actions -->
			<span style="margin-left:auto;display:flex;align-items:center;gap:8px;">
				<select id="sentinel-export-status" style="font-size:13px;">
					<option value="open"><?php esc_html_e( 'Open', 'wp-sentinel-security' ); ?></option>
					<option value="all"><?php esc_html_e( 'All statuses', 'wp-sentinel-security' ); ?></option>
					<option value="fixed"><?php esc_html_e( 'Fixed', 'wp-sentinel-security' ); ?></option>
					<option value="ignored"><?php esc_html_e( 'Ignored', 'wp-sentinel-security' ); ?></option>
				</select>
				<button id="sentinel-export-vuln-btn" class="button button-secondary" style="font-size:13px;">
					⬇ <?php esc_html_e( 'Export CSV', 'wp-sentinel-security' ); ?>
				</button>
			</span>
		</div>

		<table class="sentinel-table" id="sentinelResultsTable">
			<thead>
				<tr>
					<th style="width:32px;"></th>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Title / CVE', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody id="sentinelResultsBody">
				<tr>
					<td colspan="6"><?php esc_html_e( 'No results yet.', 'wp-sentinel-security' ); ?></td>
				</tr>
			</tbody>
		</table>
	</div>

	<!-- Open Vulnerabilities panel (all scans, de-duplicated) -->
	<div class="sentinel-card" style="margin-bottom:24px;">
		<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
			<div>
				<h2 style="margin:0 0 2px;"><?php esc_html_e( 'Open Issues', 'wp-sentinel-security' ); ?></h2>
				<p style="margin:0;font-size:12px;color:#64748b;">
					<?php esc_html_e( 'All unresolved vulnerabilities across every scan — de-duplicated by component.', 'wp-sentinel-security' ); ?>
				</p>
			</div>
			<div style="display:flex;gap:8px;align-items:center;">
				<span id="sentinel-open-count-badge" style="display:none;background:#fee2e2;color:#dc2626;font-weight:700;padding:4px 12px;border-radius:99px;font-size:13px;"></span>
				<button id="sentinel-load-open-issues" class="button button-primary">
					<?php esc_html_e( '⚠ View Open Issues', 'wp-sentinel-security' ); ?>
				</button>
			</div>
		</div>

		<div id="sentinel-open-issues-panel" style="display:none;">
			<!-- Severity filter tabs reuse existing JS handler -->
			<div class="sentinel-filter-tabs" id="sentinel-open-filter-tabs">
				<button class="sentinel-tab active" data-filter="all"><?php esc_html_e( 'All', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab sentinel-tab-critical" data-filter="critical"><?php esc_html_e( 'Critical', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab sentinel-tab-high" data-filter="high"><?php esc_html_e( 'High', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab sentinel-tab-medium" data-filter="medium"><?php esc_html_e( 'Medium', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab sentinel-tab-low" data-filter="low"><?php esc_html_e( 'Low', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab sentinel-tab-info" data-filter="info"><?php esc_html_e( 'Info', 'wp-sentinel-security' ); ?></button>
			</div>
			<table class="sentinel-table" id="sentinel-open-issues-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Issue', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Detected', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
					</tr>
				</thead>
				<tbody id="sentinel-open-issues-body">
					<tr><td colspan="6" style="text-align:center;color:#94a3b8;"><?php esc_html_e( 'Loading…', 'wp-sentinel-security' ); ?></td></tr>
				</tbody>
			</table>
		</div>
	</div>

	<!-- Scan Differential panel -->
	<div class="sentinel-card" style="margin-bottom:24px;">
		<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
			<div>
				<h2 style="margin:0 0 2px;"><?php esc_html_e( 'Scan Comparison', 'wp-sentinel-security' ); ?></h2>
				<p style="margin:0;font-size:12px;color:#64748b;">
					<?php esc_html_e( 'What changed between your last two completed scans.', 'wp-sentinel-security' ); ?>
				</p>
			</div>
			<button id="sentinel-load-differential" class="button button-secondary">
				<?php esc_html_e( '📊 Compare Last Two Scans', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div id="sentinel-diff-panel" style="display:none;">
			<!-- Summary bar injected by JS -->
			<div id="sentinel-diff-summary"></div>

			<div class="sentinel-filter-tabs" style="margin-top:16px;" id="sentinel-diff-tabs">
				<button class="sentinel-tab active" data-diff="new"><?php esc_html_e( '🆕 New Issues', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab" data-diff="resolved"><?php esc_html_e( '✅ Resolved', 'wp-sentinel-security' ); ?></button>
				<button class="sentinel-tab" data-diff="persisting"><?php esc_html_e( '⚠ Still Open', 'wp-sentinel-security' ); ?></button>
			</div>

			<table class="sentinel-table" style="margin-top:12px;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Issue', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
					</tr>
				</thead>
				<tbody id="sentinel-diff-body">
					<tr><td colspan="4" style="text-align:center;color:#94a3b8;"><?php esc_html_e( 'Loading…', 'wp-sentinel-security' ); ?></td></tr>
				</tbody>
			</table>
		</div>
	</div>

	<!-- Scan History -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Scan History', 'wp-sentinel-security' ); ?></h2>
		<table class="sentinel-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Started', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Duration', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Issues', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Score', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Results', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $scan_history ) ) : ?>
					<?php foreach ( $scan_history as $scan ) : ?>
						<?php
						$duration = '';
						if ( $scan->completed_at && $scan->started_at ) {
							$secs     = strtotime( $scan->completed_at ) - strtotime( $scan->started_at );
							$duration = $secs >= 60
								? floor( $secs / 60 ) . 'm ' . ( $secs % 60 ) . 's'
								: $secs . 's';
						}
						?>
						<tr>
							<td><?php echo esc_html( ucfirst( $scan->scan_type ) ); ?></td>
							<td>
								<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $scan->status ); ?>">
									<?php echo esc_html( ucfirst( $scan->status ) ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $scan->started_at ); ?></td>
							<td><?php echo esc_html( $duration ); ?></td>
							<td><strong><?php echo esc_html( $scan->vulnerabilities_found ); ?></strong></td>
							<td><?php echo esc_html( $scan->risk_score ); ?></td>
							<td>
								<?php if ( 'completed' === $scan->status ) : ?>
									<button class="button button-small sentinel-load-scan"
									        data-id="<?php echo esc_attr( $scan->id ); ?>">
										<?php esc_html_e( 'View Results', 'wp-sentinel-security' ); ?>
									</button>
								<?php else : ?>
									<span style="color:#94a3b8;">—</span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="7"><?php esc_html_e( 'No scans have been run yet.', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

</div>
