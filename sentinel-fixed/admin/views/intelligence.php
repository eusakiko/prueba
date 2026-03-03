<?php
/**
 * Intelligence view.
 *
 * Displays environment fingerprint, attack surface map, and risk context analysis.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

// Fetch cached intelligence data (if available).
$intelligence = get_transient( 'sentinel_intelligence_data' );
$env          = is_array( $intelligence ) ? ( $intelligence['environment'] ?? array() ) : array();
$surface      = is_array( $intelligence ) ? ( $intelligence['attack_surface'] ?? array() ) : array();
$timestamp    = is_array( $intelligence ) ? ( $intelligence['timestamp'] ?? '' ) : '';

$sec_headers = $env['security_headers'] ?? array();

$header_labels = array(
	'Strict-Transport-Security' => __( 'HSTS', 'wp-sentinel-security' ),
	'Content-Security-Policy'   => __( 'CSP', 'wp-sentinel-security' ),
	'X-Frame-Options'           => __( 'X-Frame-Options', 'wp-sentinel-security' ),
	'X-Content-Type-Options'    => __( 'X-Content-Type-Options', 'wp-sentinel-security' ),
	'Referrer-Policy'           => __( 'Referrer-Policy', 'wp-sentinel-security' ),
	'Permissions-Policy'        => __( 'Permissions-Policy', 'wp-sentinel-security' ),
	'X-XSS-Protection'          => __( 'X-XSS-Protection', 'wp-sentinel-security' ),
);
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-chart-line sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Intelligence Layer', 'wp-sentinel-security' ); ?></h1>
				<?php if ( $timestamp ) : ?>
					<span class="sentinel-version-badge">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: datetime string */
								__( 'Last analysis: %s', 'wp-sentinel-security' ),
								$timestamp
							)
						);
						?>
					</span>
				<?php endif; ?>
			</div>
		</div>
		<div class="sentinel-header-right">
			<button id="sentinel-run-intelligence" class="button button-primary">
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( 'Run Fresh Analysis', 'wp-sentinel-security' ); ?>
			</button>
		</div>
	</div>

	<div id="sentinel-intelligence-notice" style="display:none;"></div>

	<?php
	$_sentinel_settings = get_option( 'sentinel_settings', array() );
	if ( empty( $_sentinel_settings['wpscan_api_key'] ) ) :
	?>
	<div class="notice notice-info" style="margin:0 0 16px;padding:12px 16px;border-left-color:#2563eb;">
		<p>
			<strong><?php esc_html_e( 'Intelligence Layer', 'wp-sentinel-security' ); ?></strong> &mdash;
			<?php
			printf(
				/* translators: %s: Settings page URL */
				esc_html__( 'All local checks run without an API key. For plugin/theme CVE data, add a free WPScan API key in %s.', 'wp-sentinel-security' ),
				'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-settings' ) ) . '">' . esc_html__( 'Settings', 'wp-sentinel-security' ) . '</a>'
			);
			?>
		</p>
	</div>
	<?php endif; ?>

	<!-- Environment Fingerprint -->
	<h2><?php esc_html_e( 'Environment Fingerprint', 'wp-sentinel-security' ); ?></h2>
	<div class="sentinel-grid sentinel-grid-3">

		<!-- Server -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e( 'Server', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['server'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Software', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['server']['software'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( ucfirst( $env['server']['type'] ?? '–' ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'OS', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['server']['os'] ?? '–' ); ?></td></tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- PHP -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-editor-code"></span> <?php esc_html_e( 'PHP', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['php'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr>
						<th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th>
						<td>
							<?php echo esc_html( $env['php']['version'] ?? '–' ); ?>
							<?php if ( ! empty( $env['php']['is_eol'] ) ) : ?>
								<span class="sentinel-badge sentinel-badge-critical"><?php esc_html_e( 'EOL', 'wp-sentinel-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr><th><?php esc_html_e( 'SAPI', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['php']['sapi'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Memory Limit', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['php']['memory'] ?? '–' ); ?></td></tr>
					<tr>
						<th><?php esc_html_e( 'OPcache', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['opcache'] ) ? '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'Enabled', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-medium">' . esc_html__( 'Disabled', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Redis', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['redis'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Memcached', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['php']['memcached'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td>
					</tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Database -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-database"></span> <?php esc_html_e( 'Database', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['database'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['type'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['version'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Charset', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['charset'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Table Prefix', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['database']['prefix'] ?? '–' ); ?></td></tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- WordPress -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-wordpress"></span> <?php esc_html_e( 'WordPress', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['wordpress'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr>
						<th><?php esc_html_e( 'Version', 'wp-sentinel-security' ); ?></th>
						<td>
							<?php echo esc_html( $env['wordpress']['version'] ?? '–' ); ?>
							<?php if ( empty( $env['wordpress']['is_latest'] ) ) : ?>
								<span class="sentinel-badge sentinel-badge-high"><?php esc_html_e( 'Update Available', 'wp-sentinel-security' ); ?></span>
							<?php else : ?>
								<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Latest', 'wp-sentinel-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr><th><?php esc_html_e( 'Multisite', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['wordpress']['multisite'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Active Plugins', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['wordpress']['plugins'] ?? 0 ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Active Theme', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['wordpress']['theme'] ?? '–' ); ?></td></tr>
					<tr>
						<th><?php esc_html_e( 'Debug Mode', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['wordpress']['debug'] ) ? '<span class="sentinel-badge sentinel-badge-high">' . esc_html__( 'ON', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'OFF', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'SSL', 'wp-sentinel-security' ); ?></th>
						<td><?php echo ! empty( $env['wordpress']['ssl'] ) ? '<span class="sentinel-badge sentinel-badge-low">' . esc_html__( 'Yes', 'wp-sentinel-security' ) . '</span>' : '<span class="sentinel-badge sentinel-badge-high">' . esc_html__( 'No', 'wp-sentinel-security' ) . '</span>'; ?></td>
					</tr>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Hosting -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-cloud"></span> <?php esc_html_e( 'Hosting', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $env['hosting'] ) ) : ?>
				<table class="sentinel-info-table">
					<tr><th><?php esc_html_e( 'Cloud Provider', 'wp-sentinel-security' ); ?></th><td><?php echo esc_html( $env['hosting']['cloud'] ?? '–' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'cPanel', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['cpanel'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Plesk', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['plesk'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Docker', 'wp-sentinel-security' ); ?></th><td><?php echo ! empty( $env['hosting']['docker'] ) ? esc_html__( 'Yes', 'wp-sentinel-security' ) : esc_html__( 'No', 'wp-sentinel-security' ); ?></td></tr>
					<?php if ( ! empty( $env['hosting']['waf'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'WAF', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php
								$active_wafs = array_keys( array_filter( $env['hosting']['waf'] ) );
								echo $active_wafs ? esc_html( implode( ', ', array_map( 'ucfirst', $active_wafs ) ) ) : esc_html__( 'None detected', 'wp-sentinel-security' );
								?>
							</td>
						</tr>
					<?php endif; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- Security Headers -->
		<div class="sentinel-card">
			<h3><span class="dashicons dashicons-lock"></span> <?php esc_html_e( 'Security Headers', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $sec_headers ) ) : ?>
				<table class="sentinel-info-table">
					<?php foreach ( $header_labels as $header => $label ) : ?>
						<tr>
							<th><?php echo esc_html( $label ); ?></th>
							<td>
								<?php if ( ! empty( $sec_headers[ $header ] ) ) : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Present', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Missing', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

	</div><!-- .sentinel-grid -->

	<!-- ── Blacklist Monitor ─────────────────────────────────────────────── -->
	<?php
	$blacklist_status = class_exists( 'Blacklist_Monitor' )
		? ( new Blacklist_Monitor( get_option( 'sentinel_settings', array() ) ) )->get_cached_status()
		: false;

	$service_labels = array(
		'google_safe_browsing' => array(
			'label' => __( 'Google Safe Browsing', 'wp-sentinel-security' ),
			'icon'  => 'dashicons-google',
		),
		'spamhaus_dbl' => array(
			'label' => __( 'SpamHaus DBL', 'wp-sentinel-security' ),
			'icon'  => 'dashicons-email-alt',
		),
		'phishtank' => array(
			'label' => __( 'PhishTank', 'wp-sentinel-security' ),
			'icon'  => 'dashicons-warning',
		),
	);
	?>
	<h2 style="display:flex;align-items:center;gap:12px;">
		<?php esc_html_e( 'Blacklist Monitor', 'wp-sentinel-security' ); ?>
		<?php if ( $blacklist_status ) :
			$any_listed = false;
			foreach ( $blacklist_status as $svc ) {
				if ( ! empty( $svc['listed'] ) ) { $any_listed = true; break; }
			}
		?>
			<span class="sentinel-badge sentinel-badge-<?php echo $any_listed ? 'critical' : 'low'; ?>" style="font-size:12px;font-weight:700;padding:3px 10px;border-radius:99px;">
				<?php echo $any_listed
					? '&#x26a0; ' . esc_html__( 'LISTED', 'wp-sentinel-security' )
					: '&#x2714; ' . esc_html__( 'Clean', 'wp-sentinel-security' ); ?>
			</span>
		<?php endif; ?>
	</h2>

	<?php if ( ! $blacklist_status ) : ?>
		<div class="notice notice-info inline" style="margin:0 0 16px;">
			<p>
				<?php esc_html_e( 'No blacklist check has been run yet. Click "Run Fresh Analysis" to check all services.', 'wp-sentinel-security' ); ?>
			</p>
		</div>
	<?php endif; ?>

	<div class="sentinel-grid sentinel-grid-3" style="margin-bottom:24px;">
		<?php foreach ( $service_labels as $svc_key => $svc_meta ) :
			$svc_data = $blacklist_status ? ( $blacklist_status[ $svc_key ] ?? null ) : null;
			$is_listed = ! empty( $svc_data['listed'] );
			$reason    = $svc_data['reason'] ?? '—';
			$checked   = isset( $svc_data['checked_at'] ) ? human_time_diff( $svc_data['checked_at'] ) . ' ' . __( 'ago', 'wp-sentinel-security' ) : __( 'Not checked', 'wp-sentinel-security' );
			$color     = $is_listed ? '#dc2626' : ( $svc_data ? '#16a34a' : '#94a3b8' );
			$bg        = $is_listed ? '#fef2f2' : ( $svc_data ? '#f0fdf4' : '#f8fafc' );
		?>
			<div class="sentinel-card" style="background:<?php echo esc_attr( $bg ); ?>;border-left:4px solid <?php echo esc_attr( $color ); ?>;padding:20px;">
				<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
					<span class="dashicons <?php echo esc_attr( $svc_meta['icon'] ); ?>"
						style="color:<?php echo esc_attr( $color ); ?>;font-size:22px;width:22px;height:22px;"></span>
					<strong style="font-size:14px;"><?php echo esc_html( $svc_meta['label'] ); ?></strong>
				</div>

				<?php if ( $svc_data ) : ?>
					<p style="margin:0 0 6px;">
						<span class="sentinel-badge sentinel-badge-<?php echo $is_listed ? 'critical' : 'low'; ?>">
							<?php echo $is_listed
								? '&#x26a0; ' . esc_html__( 'Listed', 'wp-sentinel-security' )
								: '&#x2714; ' . esc_html__( 'Clean', 'wp-sentinel-security' ); ?>
						</span>
					</p>
					<p style="font-size:12px;color:#475569;margin:4px 0 0;">
						<?php echo esc_html( $reason ); ?>
					</p>
					<p style="font-size:11px;color:#94a3b8;margin:6px 0 0;">
						<?php esc_html_e( 'Checked:', 'wp-sentinel-security' ); ?>
						<?php echo esc_html( $checked ); ?>
					</p>
				<?php else : ?>
					<p style="font-size:13px;color:#94a3b8;margin:0;">
						<?php esc_html_e( 'Not yet checked — run an analysis to populate this.', 'wp-sentinel-security' ); ?>
					</p>
					<?php if ( 'google_safe_browsing' === $svc_key && empty( get_option( 'sentinel_settings', array() )['google_safe_browsing_key'] ) ) : ?>
						<p style="font-size:11px;color:#b45309;margin:8px 0 0;">
							<?php printf(
								esc_html__( 'Requires a Google Safe Browsing API key — add one in %s.', 'wp-sentinel-security' ),
								'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-settings' ) ) . '">' . esc_html__( 'Settings', 'wp-sentinel-security' ) . '</a>'
							); ?>
						</p>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		<?php endforeach; ?>
	</div>

	<p style="margin-bottom:24px;font-size:12px;color:#64748b;">
		<?php esc_html_e( 'Blacklist status is cached for 6 hours. Use "Run Fresh Analysis" to force an immediate check. Being listed on any service is a critical incident — your hosting provider and the listing service must be contacted immediately.', 'wp-sentinel-security' ); ?>
	</p>

	<!-- Attack Surface Map -->
	<h2><?php esc_html_e( 'Attack Surface Map', 'wp-sentinel-security' ); ?></h2>

	<div class="sentinel-grid sentinel-grid-2">

		<!-- Public Files -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Public Sensitive Files', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['public_files'] ) ) : ?>
				<table class="sentinel-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'File', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'HTTP Code', 'wp-sentinel-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $surface['public_files'] as $file => $info ) : ?>
							<tr>
								<td><code><?php echo esc_html( $file ); ?></code></td>
								<td>
									<?php if ( $info['accessible'] ) : ?>
										<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Accessible', 'wp-sentinel-security' ); ?></span>
									<?php else : ?>
										<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Protected', 'wp-sentinel-security' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( $info['http_code'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- User Enumeration & Login -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Login & User Enumeration', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['login_endpoints'] ) || ! empty( $surface['user_enumeration'] ) ) : ?>
				<table class="sentinel-info-table">
					<?php if ( ! empty( $surface['login_endpoints'] ) ) : ?>
						<tr><th><?php esc_html_e( 'Login URL', 'wp-sentinel-security' ); ?></th><td><code><?php echo esc_html( $surface['login_endpoints']['login_url'] ?? '–' ); ?></code></td></tr>
						<tr>
							<th><?php esc_html_e( 'Registration Open', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( ! empty( $surface['login_endpoints']['registration_open'] ) ) : ?>
									<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
					<?php if ( ! empty( $surface['user_enumeration'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'REST Users Exposed', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['user_enumeration']['rest_users_exposed'] ) : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Author Enumeration', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['user_enumeration']['author_enum_exposed'] ) : ?>
									<span class="sentinel-badge sentinel-badge-high">&#x2718; <?php esc_html_e( 'Exposed', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low">&#x2714; <?php esc_html_e( 'Protected', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
					<?php if ( ! empty( $surface['xmlrpc'] ) ) : ?>
						<tr>
							<th><?php esc_html_e( 'XML-RPC', 'wp-sentinel-security' ); ?></th>
							<td>
								<?php if ( $surface['xmlrpc']['enabled'] ) : ?>
									<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'Enabled', 'wp-sentinel-security' ); ?></span>
								<?php else : ?>
									<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Disabled', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endif; ?>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- REST Endpoints -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'REST API Endpoints', 'wp-sentinel-security' ); ?></h3>
			<?php if ( ! empty( $surface['rest_endpoints'] ) ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of endpoints */
							__( '%d endpoints registered.', 'wp-sentinel-security' ),
							count( $surface['rest_endpoints'] )
						)
					);
					?>
				</p>
				<table class="sentinel-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Route', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Methods', 'wp-sentinel-security' ); ?></th>
							<th><?php esc_html_e( 'Auth Required', 'wp-sentinel-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$endpoints_display = array_slice( $surface['rest_endpoints'], 0, 20 );
						foreach ( $endpoints_display as $endpoint ) :
							?>
							<tr>
								<td><code><?php echo esc_html( $endpoint['route'] ); ?></code></td>
								<td><?php echo esc_html( implode( ', ', $endpoint['methods'] ?? array() ) ); ?></td>
								<td>
									<?php if ( $endpoint['requires_auth'] ) : ?>
										<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Yes', 'wp-sentinel-security' ); ?></span>
									<?php else : ?>
										<span class="sentinel-badge sentinel-badge-medium"><?php esc_html_e( 'No', 'wp-sentinel-security' ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php if ( count( $surface['rest_endpoints'] ) > 20 ) : ?>
					<p class="description">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of additional endpoints not shown */
								__( '+ %d more endpoints not shown.', 'wp-sentinel-security' ),
								count( $surface['rest_endpoints'] ) - 20
							)
						);
						?>
					</p>
				<?php endif; ?>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

		<!-- AJAX Actions -->
		<div class="sentinel-card">
			<h3><?php esc_html_e( 'Unauthenticated AJAX Actions', 'wp-sentinel-security' ); ?></h3>
			<?php if ( isset( $surface['ajax_actions'] ) ) : ?>
				<?php if ( ! empty( $surface['ajax_actions'] ) ) : ?>
					<p>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of AJAX actions */
								__( '%d nopriv AJAX actions registered.', 'wp-sentinel-security' ),
								count( $surface['ajax_actions'] )
							)
						);
						?>
					</p>
					<ul class="sentinel-list">
						<?php foreach ( $surface['ajax_actions'] as $action ) : ?>
							<li><code><?php echo esc_html( $action ); ?></code></li>
						<?php endforeach; ?>
					</ul>
				<?php else : ?>
					<p><?php esc_html_e( 'No unauthenticated AJAX actions registered.', 'wp-sentinel-security' ); ?></p>
				<?php endif; ?>
			<?php else : ?>
				<p><?php esc_html_e( 'No data. Run an analysis first.', 'wp-sentinel-security' ); ?></p>
			<?php endif; ?>
		</div>

	</div><!-- .sentinel-grid -->

</div><!-- .sentinel-wrap -->

<script>
jQuery(function($) {
	$('#sentinel-run-intelligence').on('click', function() {
		var $btn = $(this);
		$btn.prop('disabled', true).text('<?php echo esc_js( __( 'Analyzing...', 'wp-sentinel-security' ) ); ?>');
		$('#sentinel-intelligence-notice').hide();

		$.post(sentinelData.ajaxUrl, {
			action : 'sentinel_run_intelligence',
			nonce  : sentinelData.nonces.intelligence
		}, function(response) {
			if (response.success) {
				$('#sentinel-intelligence-notice')
					.removeClass('notice-error')
					.addClass('notice notice-success')
					.html('<p><?php echo esc_js( __( 'Analysis complete! Reload the page to see updated data.', 'wp-sentinel-security' ) ); ?></p>')
					.show();
			} else {
				$('#sentinel-intelligence-notice')
					.removeClass('notice-success')
					.addClass('notice notice-error')
					.html('<p>' + (response.data.message || '<?php echo esc_js( __( 'Analysis failed. Please try again.', 'wp-sentinel-security' ) ); ?>') + '</p>')
					.show();
			}
		}).fail(function() {
			$('#sentinel-intelligence-notice')
				.removeClass('notice-success')
				.addClass('notice notice-error')
				.html('<p><?php echo esc_js( __( 'Analysis failed. Please try again.', 'wp-sentinel-security' ) ); ?></p>')
				.show();
		}).always(function() {
			$btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> <?php echo esc_js( __( 'Run Fresh Analysis', 'wp-sentinel-security' ) ); ?>');
		});
	});
});
</script>
