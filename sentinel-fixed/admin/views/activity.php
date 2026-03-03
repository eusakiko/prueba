<?php
/**
 * Activity log admin view.
 *
 * @package WP_Sentinel_Security
 * @var array $log_data Array with keys: items (array), total (int), pages (int).
 * @var int   $page     Current page number.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$items      = $log_data['items'] ?? array();
$total      = $log_data['total'] ?? 0;
$pages      = $log_data['pages'] ?? 1;

// Current filter values (sanitized, no nonce needed for read-only display).
$filter_date_from = isset( $_GET['date_from'] ) ? sanitize_text_field( wp_unslash( $_GET['date_from'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_date_to   = isset( $_GET['date_to'] ) ? sanitize_text_field( wp_unslash( $_GET['date_to'] ) ) : '';     // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_category  = isset( $_GET['category'] ) ? sanitize_text_field( wp_unslash( $_GET['category'] ) ) : '';   // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_severity  = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '';   // phpcs:ignore WordPress.Security.NonceVerification.Recommended

// WAF blocked-request stats for the summary row.
// Use WordPress-timezone-aware boundaries so "today" matches the configured
// site timezone rather than the DB server's system clock.
global $wpdb;
$tlog = $wpdb->prefix . 'sentinel_activity_log';

$today_start = gmdate( 'Y-m-d', current_time( 'timestamp' ) ) . ' 00:00:00';
$today_end   = gmdate( 'Y-m-d', current_time( 'timestamp' ) ) . ' 23:59:59';
$week_start  = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - 7 * DAY_IN_SECONDS );

$waf_today  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$tlog}` WHERE event_type=%s AND created_at BETWEEN %s AND %s", 'waf_blocked', $today_start, $today_end ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$waf_week   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$tlog}` WHERE event_type=%s AND created_at>=%s", 'waf_blocked', $week_start ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$waf_total  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$tlog}` WHERE event_type=%s", 'waf_blocked' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$auth_fails = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$tlog}` WHERE event_type=%s AND created_at>=%s", 'login_failed', $week_start ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$categories = array(
	''               => __( 'All Categories', 'wp-sentinel-security' ),
	'authentication' => __( 'Authentication', 'wp-sentinel-security' ),
	'user_management'=> __( 'User Management', 'wp-sentinel-security' ),
	'firewall'       => __( 'Firewall / WAF', 'wp-sentinel-security' ),
	'plugin'         => __( 'Plugin', 'wp-sentinel-security' ),
	'theme'          => __( 'Theme', 'wp-sentinel-security' ),
	'scanner'        => __( 'Scanner', 'wp-sentinel-security' ),
	'hardening'      => __( 'Hardening', 'wp-sentinel-security' ),
	'backup'         => __( 'Backup', 'wp-sentinel-security' ),
	'alert'          => __( 'Alert', 'wp-sentinel-security' ),
	'system'         => __( 'System', 'wp-sentinel-security' ),
);

$severities = array(
	''         => __( 'All Severities', 'wp-sentinel-security' ),
	'critical' => __( 'Critical', 'wp-sentinel-security' ),
	'high'     => __( 'High', 'wp-sentinel-security' ),
	'medium'   => __( 'Medium', 'wp-sentinel-security' ),
	'low'      => __( 'Low', 'wp-sentinel-security' ),
	'info'     => __( 'Info', 'wp-sentinel-security' ),
);
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-list-view sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Activity Log', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-subtitle">
					<?php
					printf(
						/* translators: %d: Total log entries */
						esc_html__( '%d entries recorded', 'wp-sentinel-security' ),
						esc_html( $total )
					);
					?>
				</span>
			</div>
		</div>
		<div class="sentinel-header-right" style="display:flex;gap:8px;">
			<button id="sentinel-export-log" class="button button-secondary">
				<span class="dashicons dashicons-download" style="vertical-align:middle;margin-right:4px;"></span>
				<?php esc_html_e( 'Export CSV', 'wp-sentinel-security' ); ?>
			</button>
			<button id="sentinel-clear-old-logs" class="button" style="color:#dc2626;border-color:#dc2626;">
				<span class="dashicons dashicons-trash" style="vertical-align:middle;margin-right:4px;"></span>
				<?php esc_html_e( 'Clear Old Logs', 'wp-sentinel-security' ); ?>
			</button>
		</div>
	</div>

	<!-- Security event KPI row -->
	<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;">
		<?php
		$kpis = array(
			array(
				'label'   => __( 'WAF Blocks Today',    'wp-sentinel-security' ),
				'value'   => $waf_today,
				'icon'    => 'dashicons-shield',
				'color'   => '#dc2626',
				'filter'  => 'waf_blocked',
			),
			array(
				'label'   => __( 'WAF Blocks (7 days)', 'wp-sentinel-security' ),
				'value'   => $waf_week,
				'icon'    => 'dashicons-shield-alt',
				'color'   => '#ea580c',
				'filter'  => 'waf_blocked',
			),
			array(
				'label'   => __( 'Total WAF Blocks',   'wp-sentinel-security' ),
				'value'   => $waf_total,
				'icon'    => 'dashicons-lock',
				'color'   => '#7c3aed',
				'filter'  => 'waf_blocked',
			),
			array(
				'label'   => __( 'Failed Logins (7d)', 'wp-sentinel-security' ),
				'value'   => $auth_fails,
				'icon'    => 'dashicons-admin-users',
				'color'   => '#b45309',
				'filter'  => 'login_failed',
			),
		);
		foreach ( $kpis as $kpi ) :
			$filter_url = add_query_arg( array(
				'page'     => 'sentinel-activity',
				'category' => 'waf_blocked' === $kpi['filter'] ? 'firewall' : 'authentication',
			), admin_url( 'admin.php' ) );
		?>
			<a href="<?php echo esc_url( $filter_url ); ?>" style="text-decoration:none;">
				<div class="sentinel-card" style="padding:18px 20px;display:flex;align-items:center;gap:14px;transition:box-shadow .15s;cursor:pointer;" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,.12)'" onmouseout="this.style.boxShadow=''">
					<span class="dashicons <?php echo esc_attr( $kpi['icon'] ); ?>"
						style="font-size:28px;width:28px;height:28px;color:<?php echo esc_attr( $kpi['color'] ); ?>;flex-shrink:0;"></span>
					<div>
						<div style="font-size:26px;font-weight:700;line-height:1;color:<?php echo esc_attr( $kpi['color'] ); ?>;">
							<?php echo esc_html( number_format_i18n( $kpi['value'] ) ); ?>
						</div>
						<div style="font-size:12px;color:#64748b;margin-top:3px;"><?php echo esc_html( $kpi['label'] ); ?></div>
					</div>
				</div>
			</a>
		<?php endforeach; ?>
	</div>

	<!-- Filters -->
	<div class="sentinel-card" style="padding:16px 24px;">
		<form method="get" action="" style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;">
			<input type="hidden" name="page" value="sentinel-activity">
			<div>
				<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#475569;">
					<?php esc_html_e( 'From', 'wp-sentinel-security' ); ?>
				</label>
				<input type="date" name="date_from" value="<?php echo esc_attr( $filter_date_from ); ?>" class="regular-text" style="width:140px;">
			</div>
			<div>
				<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#475569;">
					<?php esc_html_e( 'To', 'wp-sentinel-security' ); ?>
				</label>
				<input type="date" name="date_to" value="<?php echo esc_attr( $filter_date_to ); ?>" class="regular-text" style="width:140px;">
			</div>
			<div>
				<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#475569;">
					<?php esc_html_e( 'Category', 'wp-sentinel-security' ); ?>
				</label>
				<select name="category">
					<?php foreach ( $categories as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $filter_category, $val ); ?>>
							<?php echo esc_html( $label ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</div>
			<div>
				<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#475569;">
					<?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?>
				</label>
				<select name="severity">
					<?php foreach ( $severities as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $filter_severity, $val ); ?>>
							<?php echo esc_html( $label ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</div>
			<div>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Filter', 'wp-sentinel-security' ); ?></button>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-activity' ) ); ?>" class="button" style="margin-left:4px;">
					<?php esc_html_e( 'Reset', 'wp-sentinel-security' ); ?>
				</a>
			</div>
		</form>
	</div>

	<!-- Activity Log Table -->
	<div class="sentinel-card">
		<table class="sentinel-table widefat">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'User', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Event', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Category', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'IP Address', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Description', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $items ) ) : ?>
					<?php foreach ( $items as $entry ) :
						$user = $entry->user_id ? get_userdata( $entry->user_id ) : null;
						?>
						<tr>
							<td style="white-space:nowrap;"><?php echo esc_html( $entry->created_at ); ?></td>
							<td>
								<?php if ( $user ) : ?>
									<?php echo esc_html( $user->user_login ); ?>
								<?php else : ?>
									<span style="color:#94a3b8;"><?php esc_html_e( 'System', 'wp-sentinel-security' ); ?></span>
								<?php endif; ?>
							</td>
							<td><code style="font-size:11px;"><?php echo esc_html( $entry->event_type ); ?></code></td>
							<td><?php echo esc_html( $entry->event_category ); ?></td>
							<td>
								<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $entry->severity ); ?>">
									<?php echo esc_html( ucfirst( $entry->severity ) ); ?>
								</span>
							</td>
							<td><code style="font-size:11px;"><?php echo esc_html( $entry->ip_address ); ?></code></td>
							<td><?php echo esc_html( $entry->description ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="7"><?php esc_html_e( 'No activity recorded yet.', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>

		<!-- Pagination -->
		<?php if ( $pages > 1 ) : ?>
		<div class="sentinel-pagination" style="margin-top:16px;text-align:center;">
			<?php
			$base_url = add_query_arg(
				array(
					'page'      => 'sentinel-activity',
					'date_from' => $filter_date_from,
					'date_to'   => $filter_date_to,
					'category'  => $filter_category,
					'severity'  => $filter_severity,
				),
				admin_url( 'admin.php' )
			);

			echo paginate_links( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				array(
					'base'    => esc_url( $base_url ) . '%_%',
					'format'  => '&paged=%#%',
					'current' => $page,
					'total'   => $pages,
				)
			);
			?>
		</div>
		<?php endif; ?>
	</div>

</div>

<script>
jQuery( function( $ ) {
	var nonce = '<?php echo esc_js( wp_create_nonce( 'sentinel_nonce' ) ); ?>';

	// Export log as CSV.
	$( '#sentinel-export-log' ).on( 'click', function() {
		window.location.href = '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>?action=sentinel_export_activity_log&nonce=' + nonce;
	} );

	// Clear old logs.
	$( '#sentinel-clear-old-logs' ).on( 'click', function() {
		if ( ! confirm( '<?php echo esc_js( __( 'Are you sure? This will permanently delete logs older than the configured retention period.', 'wp-sentinel-security' ) ); ?>' ) ) {
			return;
		}

		var $btn = $( this );
		$btn.prop( 'disabled', true );

		$.post(
			'<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>',
			{
				action: 'sentinel_clear_old_logs',
				nonce:  nonce
			},
			function( response ) {
				if ( response.success ) {
					location.reload();
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : '<?php echo esc_js( __( 'Failed to clear logs.', 'wp-sentinel-security' ) ); ?>';
					alert( msg );
					$btn.prop( 'disabled', false );
				}
			}
		).fail( function() {
			alert( '<?php echo esc_js( __( 'Request failed. Please try again.', 'wp-sentinel-security' ) ); ?>' );
			$btn.prop( 'disabled', false );
		} );
	} );
} );
</script>
