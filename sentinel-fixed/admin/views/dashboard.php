<?php
/**
 * Dashboard view — improved.
 *
 * @package WP_Sentinel_Security
 * @var array  $score     Security score data from Scoring_Engine::calculate_site_score().
 * @var array  $alerts    Recent alerts.
 * @var object $last_scan Last completed scan object (or null).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$risk_level      = Scoring_Engine::get_risk_level( $score['score'] );
$recommendations = Scoring_Engine::get_top_recommendations( $score, ! empty( $last_scan ) );

$urgency_labels = array(
	'critical' => __( 'Critical (Do today)', 'wp-sentinel-security' ),
	'high'     => __( 'High (Within 48h)', 'wp-sentinel-security' ),
	'medium'   => __( 'Medium (This week)', 'wp-sentinel-security' ),
	'low'      => __( 'Low (Monitor)', 'wp-sentinel-security' ),
	'info'     => __( 'Info', 'wp-sentinel-security' ),
);

$risk_hints = array(
	'critical' => __( 'Your site has active critical vulnerabilities. Immediate action is required.', 'wp-sentinel-security' ),
	'high'     => __( 'Your site has high-severity issues that need urgent attention within 48 hours.', 'wp-sentinel-security' ),
	'medium'   => __( 'Your site has moderate risks that should be addressed this week.', 'wp-sentinel-security' ),
	'low'      => __( 'Your site is mostly secure. Continue monitoring for new issues.', 'wp-sentinel-security' ),
);

$risk_colors = array(
	'critical' => '#dc2626',
	'high'     => '#ea580c',
	'medium'   => '#ca8a04',
	'low'      => '#16a34a',
);
$risk_color = $risk_colors[ $risk_level['level'] ] ?? '#4f46e5';
?>

<div class="wrap sentinel-wrap">

	<!-- Page Header -->
	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-shield-alt sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'WP Sentinel Security', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-version-badge">v<?php echo esc_html( SENTINEL_VERSION ); ?></span>
			</div>
		</div>
		<div class="sentinel-header-right">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-scanner' ) ); ?>" class="button button-primary sentinel-btn-scan">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Run Scan', 'wp-sentinel-security' ); ?>
			</a>
		</div>
	</div>

	<!-- ===== TOP KPI ROW ===== -->
	<div class="sentinel-stats-grid sentinel-grid-4" style="margin-bottom:24px;">

		<!-- Security Score -->
		<div class="sentinel-card sentinel-score-card" style="text-align:center;padding:24px 16px;">
			<div class="sentinel-score-circle" style="--score-color:<?php
				$color = $score['grade_color'];
				if ( ! preg_match( '/^#[0-9a-fA-F]{6}$/', $color ) ) { $color = '#6c757d'; }
				echo esc_attr( $color );
			?>;">
				<span class="sentinel-score-value"><?php echo esc_html( $score['score'] ); ?></span>
				<span class="sentinel-score-grade"><?php echo esc_html( $score['grade'] ); ?></span>
			</div>
			<p class="sentinel-score-label" style="margin:8px 0 2px;"><?php echo esc_html( $score['grade_label'] ); ?></p>
			<small style="color:#94a3b8;"><?php esc_html_e( 'Security Score', 'wp-sentinel-security' ); ?></small>
		</div>

		<!-- Critical -->
		<div class="sentinel-card sentinel-stat-card sentinel-stat-critical">
			<div class="sentinel-stat-icon"><span class="dashicons dashicons-warning"></span></div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['by_severity']['critical'] ); ?></span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'Critical', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

		<!-- High -->
		<div class="sentinel-card sentinel-stat-card sentinel-stat-high">
			<div class="sentinel-stat-icon"><span class="dashicons dashicons-flag"></span></div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['by_severity']['high'] ); ?></span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'High', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

		<!-- Hardened -->
		<div class="sentinel-card sentinel-stat-card sentinel-stat-hardening">
			<div class="sentinel-stat-icon"><span class="dashicons dashicons-shield"></span></div>
			<div class="sentinel-stat-content">
				<span class="sentinel-stat-value"><?php echo esc_html( $score['hardening_percentage'] ); ?>%</span>
				<span class="sentinel-stat-label"><?php esc_html_e( 'Hardened', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>

	</div>

	<!-- ===== RISK BANNER ===== -->
	<div class="sentinel-card" style="border-left:5px solid <?php echo esc_attr( $risk_color ); ?>;padding:20px 24px;margin-bottom:24px;">
		<div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;">
			<div style="flex:1;min-width:220px;">
				<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
					<small style="color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">
						<?php esc_html_e( 'Overall Risk Level', 'wp-sentinel-security' ); ?>
					</small>
					<span class="sentinel-risk-badge sentinel-risk-<?php echo esc_attr( $risk_level['level'] ); ?>"
					      style="background:<?php echo esc_attr( $risk_color ); ?>20;color:<?php echo esc_attr( $risk_color ); ?>;border:1px solid <?php echo esc_attr( $risk_color ); ?>40;padding:3px 12px;border-radius:99px;font-size:13px;font-weight:700;">
						<?php echo esc_html( $risk_level['label'] ); ?>
					</span>
				</div>
				<p style="color:#475569;font-size:13px;margin:0;">
					<strong><?php esc_html_e( 'What this means:', 'wp-sentinel-security' ); ?></strong>
					<?php echo esc_html( $risk_hints[ $risk_level['level'] ] ?? '' ); ?>
				</p>
			</div>
			<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;">
				<?php foreach ( $urgency_labels as $sev => $urgency_label ) : ?>
					<?php if ( isset( $score['by_severity'][ $sev ] ) && $score['by_severity'][ $sev ] > 0 ) : ?>
						<div style="text-align:center;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 16px;min-width:90px;">
							<div style="font-size:22px;font-weight:700;color:<?php echo esc_attr( $risk_colors[ $sev ] ?? '#64748b' ); ?>;">
								<?php echo esc_html( $score['by_severity'][ $sev ] ); ?>
							</div>
							<div style="font-size:11px;color:#64748b;margin-top:2px;">
								<?php echo esc_html( $urgency_label ); ?>
							</div>
						</div>
					<?php endif; ?>
				<?php endforeach; ?>
			</div>
		</div>
	</div>

	<!-- ===== RECOMMENDATIONS + CHARTS ROW ===== -->
	<div class="sentinel-grid sentinel-grid-2" style="margin-bottom:24px;">

		<!-- Recommended Actions -->
		<div class="sentinel-card">
			<h2 style="margin-bottom:16px;"><?php esc_html_e( 'Top Recommended Actions', 'wp-sentinel-security' ); ?></h2>
			<ol style="margin:0;padding-left:20px;">
				<?php foreach ( $recommendations as $i => $rec ) : ?>
					<li style="margin-bottom:14px;padding-bottom:14px;<?php echo $i < count( $recommendations ) - 1 ? 'border-bottom:1px solid #f1f5f9;' : ''; ?>">
						<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
							<span style="color:#334155;font-size:13px;line-height:1.5;"><?php echo esc_html( $rec['text'] ); ?></span>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $rec['page'] ) ); ?>"
							   class="button button-primary button-small" style="white-space:nowrap;flex-shrink:0;">
								<?php echo esc_html( $rec['cta'] ); ?>
							</a>
						</div>
					</li>
				<?php endforeach; ?>
			</ol>
		</div>

		<!-- Vulnerability Distribution -->
		<div class="sentinel-card">
			<h2 style="margin-bottom:16px;"><?php esc_html_e( 'Vulnerability Distribution', 'wp-sentinel-security' ); ?></h2>
			<div class="sentinel-chart-container" style="position:relative;max-height:220px;">
				<canvas id="sentinelVulnChart"></canvas>
			</div>
			<div class="sentinel-vuln-legend" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
				<?php
				$vuln_colors = array( 'critical' => '#dc2626', 'high' => '#ea580c', 'medium' => '#ca8a04', 'low' => '#16a34a', 'info' => '#2563eb' );
				foreach ( $score['by_severity'] as $sev => $count ) :
				?>
					<span style="display:flex;align-items:center;gap:5px;font-size:12px;color:#475569;">
						<span style="width:10px;height:10px;border-radius:50%;background:<?php echo esc_attr( $vuln_colors[ $sev ] ?? '#6b7280' ); ?>;flex-shrink:0;"></span>
						<?php echo esc_html( ucfirst( $sev ) ); ?>: <strong><?php echo esc_html( $count ); ?></strong>
					</span>
				<?php endforeach; ?>
			</div>
		</div>

	</div>

	<!-- ===== SCORE EVOLUTION ===== -->
	<div class="sentinel-card" style="margin-bottom:24px;">
		<h2 style="margin-bottom:16px;"><?php esc_html_e( 'Security Evolution', 'wp-sentinel-security' ); ?></h2>
		<div class="sentinel-chart-container" style="max-height:200px;">
			<canvas id="sentinelScoreChart"></canvas>
		</div>
	</div>

	<!-- ===== QUICK ACTIONS ===== -->
	<div class="sentinel-grid sentinel-grid-3" style="margin-bottom:24px;">

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-search sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Quick Scan', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Run a quick security scan covering core, plugins and configuration.', 'wp-sentinel-security' ); ?></p>
			<button class="button button-primary sentinel-start-scan" data-scan-type="quick">
				<?php esc_html_e( 'Start Quick Scan', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-backup sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Create a full database backup before applying security changes.', 'wp-sentinel-security' ); ?></p>
			<button class="button button-secondary sentinel-create-backup">
				<?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<div class="sentinel-card sentinel-action-card">
			<span class="dashicons dashicons-media-document sentinel-action-icon"></span>
			<h3><?php esc_html_e( 'Generate Report', 'wp-sentinel-security' ); ?></h3>
			<p><?php esc_html_e( 'Generate a detailed security report with findings and recommendations.', 'wp-sentinel-security' ); ?></p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-reports' ) ); ?>" class="button button-secondary">
				<?php esc_html_e( 'View Reports', 'wp-sentinel-security' ); ?>
			</a>
		</div>

	</div>

	<!-- ===== LAST SCAN + RECENT ALERTS ===== -->
	<div class="sentinel-grid sentinel-grid-2">

		<!-- Last Scan -->
		<div class="sentinel-card">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
				<h2 style="margin:0;"><?php esc_html_e( 'Last Scan', 'wp-sentinel-security' ); ?></h2>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-scanner' ) ); ?>" class="button button-small button-secondary">
					<?php esc_html_e( 'All Scans', 'wp-sentinel-security' ); ?>
				</a>
			</div>
			<?php if ( $last_scan ) : ?>
				<table class="sentinel-table" style="margin:0;">
					<tbody>
						<tr>
							<td style="color:#64748b;width:40%;"><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></td>
							<td><strong><?php echo esc_html( ucfirst( $last_scan->scan_type ) ); ?></strong></td>
						</tr>
						<tr>
							<td style="color:#64748b;"><?php esc_html_e( 'Completed', 'wp-sentinel-security' ); ?></td>
							<td><?php echo esc_html( $last_scan->completed_at ); ?></td>
						</tr>
						<tr>
							<td style="color:#64748b;"><?php esc_html_e( 'Issues Found', 'wp-sentinel-security' ); ?></td>
							<td>
								<strong style="color:<?php echo $last_scan->vulnerabilities_found > 0 ? '#dc2626' : '#16a34a'; ?>">
									<?php echo esc_html( $last_scan->vulnerabilities_found ); ?>
								</strong>
							</td>
						</tr>
						<tr>
							<td style="color:#64748b;"><?php esc_html_e( 'Risk Score', 'wp-sentinel-security' ); ?></td>
							<td><?php echo esc_html( $last_scan->risk_score ); ?></td>
						</tr>
					</tbody>
				</table>
				<div style="margin-top:14px;">
					<button class="button button-primary sentinel-load-scan" data-id="<?php echo esc_attr( $last_scan->id ); ?>">
						<?php esc_html_e( 'View Results', 'wp-sentinel-security' ); ?>
					</button>
				</div>
			<?php else : ?>
				<p style="color:#64748b;"><?php esc_html_e( 'No scan has been run yet. Run your first scan to get started.', 'wp-sentinel-security' ); ?></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-scanner' ) ); ?>" class="button button-primary" style="margin-top:8px;">
					<?php esc_html_e( 'Run First Scan', 'wp-sentinel-security' ); ?>
				</a>
			<?php endif; ?>
		</div>

		<!-- Recent Alerts -->
		<div class="sentinel-card">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
				<h2 style="margin:0;"><?php esc_html_e( 'Recent Alerts', 'wp-sentinel-security' ); ?></h2>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-alerts' ) ); ?>" class="button button-small button-secondary">
					<?php esc_html_e( 'All Alerts', 'wp-sentinel-security' ); ?>
				</a>
			</div>
			<?php if ( ! empty( $alerts ) ) : ?>
				<table class="sentinel-table" style="margin:0;">
					<tbody>
						<?php foreach ( array_slice( $alerts, 0, 5 ) as $alert ) : ?>
							<tr>
								<td style="width:90px;">
									<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $alert->severity ); ?>">
										<?php echo esc_html( ucfirst( $alert->severity ) ); ?>
									</span>
								</td>
								<td style="font-size:12px;color:#334155;"><?php echo esc_html( $alert->description ); ?></td>
								<td style="font-size:11px;color:#94a3b8;white-space:nowrap;">
									<?php echo esc_html(
										human_time_diff(
											strtotime( $alert->created_at ),
											current_time( 'timestamp' ) // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested
										) . ' ' . __( 'ago', 'wp-sentinel-security' )
									); ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<div style="text-align:center;padding:24px;color:#94a3b8;">
					<span class="dashicons dashicons-yes-alt" style="font-size:32px;width:32px;height:32px;color:#16a34a;margin-bottom:8px;display:block;"></span>
					<?php esc_html_e( 'No alerts found. Your site looks clean!', 'wp-sentinel-security' ); ?>
				</div>
			<?php endif; ?>
		</div>

	</div>

	<!-- Results panel (injected by JS when "View Results" is clicked) -->
	<div id="sentinel-scan-results" class="sentinel-card" style="display:none;margin-top:24px;">
		<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
			<h2 style="margin:0;"><?php esc_html_e( 'Scan Results', 'wp-sentinel-security' ); ?></h2>
			<button class="button button-secondary" onclick="document.getElementById('sentinel-scan-results').style.display='none';">
				<?php esc_html_e( 'Close', 'wp-sentinel-security' ); ?>
			</button>
		</div>
		<p id="sentinel-results-scan-info" style="color:#64748b;font-size:12px;margin-bottom:12px;display:none;"></p>
		<div class="sentinel-filter-tabs">
			<button class="sentinel-tab active" data-filter="all"><?php esc_html_e( 'All', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-critical" data-filter="critical"><?php esc_html_e( 'Critical (Do today)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-high" data-filter="high"><?php esc_html_e( 'High (Within 48h)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-medium" data-filter="medium"><?php esc_html_e( 'Medium (This week)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-low" data-filter="low"><?php esc_html_e( 'Low (Monitor)', 'wp-sentinel-security' ); ?></button>
			<button class="sentinel-tab sentinel-tab-info" data-filter="info"><?php esc_html_e( 'Info', 'wp-sentinel-security' ); ?></button>
		</div>
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
				<tr><td colspan="6"><?php esc_html_e( 'No results yet.', 'wp-sentinel-security' ); ?></td></tr>
			</tbody>
		</table>
	</div>

</div>

<style>
.sentinel-cve-link { font-size:11px; font-weight:700; padding:2px 7px; background:#eff6ff; color:#2563eb; border-radius:4px; text-decoration:none; }
.sentinel-cve-link:hover { background:#dbeafe; }
.sentinel-modal-overlay { position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:99999;display:flex;align-items:center;justify-content:center; }
.sentinel-modal { background:#fff;border-radius:10px;padding:28px 32px;max-width:500px;width:90%;position:relative; }
.sentinel-modal-close { position:absolute;top:12px;right:16px;background:none;border:none;font-size:20px;cursor:pointer;color:#64748b; }
</style>
