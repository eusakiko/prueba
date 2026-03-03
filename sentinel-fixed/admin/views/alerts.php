<?php
/**
 * Alerts admin view.
 *
 * @package WP_Sentinel_Security
 * @var array $alerts   Array of recent alert log objects.
 * @var array $settings Plugin settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$enabled_channels = $settings['alert_channels'] ?? array( 'email' );

$channel_labels = array(
	'email'    => __( 'Email', 'wp-sentinel-security' ),
	'slack'    => __( 'Slack', 'wp-sentinel-security' ),
	'telegram' => __( 'Telegram', 'wp-sentinel-security' ),
	'discord'  => __( 'Discord', 'wp-sentinel-security' ),
	'webhook'  => __( 'Webhook', 'wp-sentinel-security' ),
);

$monitored_events = array(
	'critical_vulnerability' => array(
		'label'    => __( 'Critical Vulnerability', 'wp-sentinel-security' ),
		'severity' => 'critical',
	),
	'malware_detected'       => array(
		'label'    => __( 'Malware Detected', 'wp-sentinel-security' ),
		'severity' => 'critical',
	),
	'backup_failed'          => array(
		'label'    => __( 'Backup Failed', 'wp-sentinel-security' ),
		'severity' => 'high',
	),
	'login_failed_threshold' => array(
		'label'    => __( 'Brute Force Threshold', 'wp-sentinel-security' ),
		'severity' => 'high',
	),
	'file_changed'           => array(
		'label'    => __( 'File Modification', 'wp-sentinel-security' ),
		'severity' => 'medium',
	),
	'hardening_changed'      => array(
		'label'    => __( 'Hardening Changed', 'wp-sentinel-security' ),
		'severity' => 'medium',
	),
	'scan_complete'          => array(
		'label'    => __( 'Scan Complete', 'wp-sentinel-security' ),
		'severity' => 'info',
	),
);
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-bell sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Alerts', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-subtitle"><?php esc_html_e( 'Configure notification channels and view recent alerts.', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Alert Channels Configuration -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Alert Channels', 'wp-sentinel-security' ); ?></h2>
		<p style="color:#64748b;margin-bottom:16px;">
			<?php esc_html_e( 'Configure and test your notification channels in Settings. Use the buttons below to send a test alert.', 'wp-sentinel-security' ); ?>
		</p>

		<div class="sentinel-channels-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;">
			<?php foreach ( $channel_labels as $channel_key => $channel_label ) : ?>
				<?php $is_enabled = in_array( $channel_key, $enabled_channels, true ); ?>
				<div class="sentinel-card" style="padding:16px;border:1px solid <?php echo $is_enabled ? '#4f46e5' : '#e2e8f0'; ?>;">
					<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
						<strong><?php echo esc_html( $channel_label ); ?></strong>
						<?php if ( $is_enabled ) : ?>
							<span class="sentinel-badge sentinel-badge-low"><?php esc_html_e( 'Enabled', 'wp-sentinel-security' ); ?></span>
						<?php else : ?>
							<span class="sentinel-badge" style="background:#f1f5f9;color:#64748b;"><?php esc_html_e( 'Disabled', 'wp-sentinel-security' ); ?></span>
						<?php endif; ?>
					</div>
					<?php if ( $is_enabled ) : ?>
						<button class="button button-secondary sentinel-test-channel" style="width:100%;"
						        data-channel="<?php echo esc_attr( $channel_key ); ?>">
							<?php esc_html_e( 'Send Test', 'wp-sentinel-security' ); ?>
						</button>
						<p class="sentinel-test-result" id="sentinel-test-result-<?php echo esc_attr( $channel_key ); ?>" style="margin-top:8px;font-size:12px;display:none;"></p>
					<?php else : ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-settings' ) ); ?>" class="button button-secondary" style="width:100%;text-align:center;">
							<?php esc_html_e( 'Configure', 'wp-sentinel-security' ); ?>
						</a>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>
		</div>
	</div>

	<!-- Monitored Events -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Monitored Event Types', 'wp-sentinel-security' ); ?></h2>
		<table class="sentinel-table widefat">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Event', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Channels', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $monitored_events as $event_key => $event ) : ?>
					<tr>
						<td><?php echo esc_html( $event['label'] ); ?></td>
						<td>
							<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $event['severity'] ); ?>">
								<?php echo esc_html( ucfirst( $event['severity'] ) ); ?>
							</span>
						</td>
						<td>
							<?php
							foreach ( $enabled_channels as $ch ) {
								if ( isset( $channel_labels[ $ch ] ) ) {
									echo '<span class="sentinel-badge" style="background:#eff6ff;color:#2563eb;margin-right:4px;">' . esc_html( $channel_labels[ $ch ] ) . '</span>';
								}
							}
							?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>

	<!-- Recent Alerts -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Recent Alerts', 'wp-sentinel-security' ); ?></h2>
		<table class="sentinel-table widefat">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Event', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Message', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $alerts ) ) : ?>
					<?php foreach ( $alerts as $alert ) : ?>
						<tr id="sentinel-alert-row-<?php echo esc_attr( $alert->id ); ?>">
							<td><?php echo esc_html( $alert->created_at ); ?></td>
							<td><?php echo esc_html( $alert->event_type ); ?></td>
							<td>
								<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $alert->severity ); ?>">
									<?php echo esc_html( ucfirst( $alert->severity ) ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $alert->description ); ?></td>
							<td>
								<button class="button button-small sentinel-dismiss-alert"
								        data-id="<?php echo esc_attr( $alert->id ); ?>">
									<?php esc_html_e( 'Dismiss', 'wp-sentinel-security' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="5"><?php esc_html_e( 'No alerts recorded yet.', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

</div>

<script>
jQuery( function( $ ) {
	var nonce = '<?php echo esc_js( wp_create_nonce( 'sentinel_nonce' ) ); ?>';

	// Test alert channel.
	$( '.sentinel-test-channel' ).on( 'click', function() {
		var $btn     = $( this );
		var channel  = $btn.data( 'channel' );
		var $result  = $( '#sentinel-test-result-' + channel );

		$btn.prop( 'disabled', true ).text( '<?php echo esc_js( __( 'Sending…', 'wp-sentinel-security' ) ); ?>' );
		$result.hide();

		var ajaxUrl = window.sentinelData ? sentinelData.ajaxUrl : '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>';
		var ajaxNonce = window.sentinelData ? sentinelData.nonces.sentinel : nonce;
		$.post(
			ajaxUrl,
			{
				action:  'sentinel_test_alert',
				nonce:   ajaxNonce,
				channel: channel
			},
			function( response ) {
				if ( response.success ) {
					$result.html( '<span style="color:#16a34a">&#x2714; ' + response.data.message + '</span>' ).show();
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : '<?php echo esc_js( __( 'Send failed.', 'wp-sentinel-security' ) ); ?>';
					$result.html( '<span style="color:#dc2626">&#x2718; ' + msg + '</span>' ).show();
				}
				$btn.prop( 'disabled', false ).text( '<?php echo esc_js( __( 'Send Test', 'wp-sentinel-security' ) ); ?>' );
			}
		).fail( function( xhr ) {
			var errMsg;
			if ( xhr.status === 0 ) {
				errMsg = '<?php echo esc_js( __( 'No server response. Check network connectivity.', 'wp-sentinel-security' ) ); ?>';
			} else if ( xhr.status === 403 ) {
				errMsg = '<?php echo esc_js( __( 'Permission denied (403). Try refreshing the page.', 'wp-sentinel-security' ) ); ?>';
			} else {
				errMsg = '<?php echo esc_js( __( 'Request failed.', 'wp-sentinel-security' ) ); ?>' + ' (HTTP ' + xhr.status + ')';
			}
			$result.html( '<span style="color:#dc2626">&#x2718; ' + errMsg + '</span>' ).show();
			$btn.prop( 'disabled', false ).text( '<?php echo esc_js( __( 'Send Test', 'wp-sentinel-security' ) ); ?>' );
		} );
	} );

	// Dismiss alert.
	$( document ).on( 'click', '.sentinel-dismiss-alert', function() {
		var $btn     = $( this );
		var alertId  = $btn.data( 'id' );

		$btn.prop( 'disabled', true );

		$.post(
			'<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>',
			{
				action:   'sentinel_dismiss_alert',
				nonce:    nonce,
				alert_id: alertId
			},
			function( response ) {
				if ( response.success ) {
					$( '#sentinel-alert-row-' + alertId ).fadeOut( 300, function() { $( this ).remove(); } );
				} else {
					$btn.prop( 'disabled', false );
				}
			}
		).fail( function() {
			$btn.prop( 'disabled', false );
		} );
	} );
} );
</script>
