<?php
/**
 * Firewall admin view — IP block list, whitelist and WAF activity summary.
 *
 * @package WP_Sentinel_Security
 * @var array  $blocked_ips    Blocked IPs from IP_Manager::get_blocked_ips().
 * @var array  $whitelisted    Whitelisted IPs from IP_Manager::get_whitelisted_ips().
 * @var string $firewall_nonce Nonce for AJAX calls.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

// Pull WAF block stats from the activity log.
global $wpdb;
$table_log  = $wpdb->prefix . 'sentinel_activity_log';
$waf_total  = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->prepare(
		"SELECT COUNT(*) FROM `{$table_log}` WHERE event_type = %s",
		'waf_blocked'
	)
);
$waf_today  = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->prepare(
		"SELECT COUNT(*) FROM `{$table_log}` WHERE event_type = %s AND DATE(created_at) = CURDATE()",
		'waf_blocked'
	)
);
$waf_week   = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->prepare(
		"SELECT COUNT(*) FROM `{$table_log}` WHERE event_type = %s AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
		'waf_blocked'
	)
);

// Top 10 recently blocked IPs.
$recent_blocks = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->prepare(
		"SELECT ip_address, COUNT(*) AS hits, MAX(created_at) AS last_seen,
		        GROUP_CONCAT(DISTINCT object_id ORDER BY created_at DESC SEPARATOR ', ') AS rules_hit
		 FROM `{$table_log}`
		 WHERE event_type = %s AND ip_address != ''
		 GROUP BY ip_address
		 ORDER BY hits DESC
		 LIMIT 10",
		'waf_blocked'
	),
	ARRAY_A
);
?>

<div class="sentinel-page sentinel-firewall">

	<!-- Page header -->
	<div class="sentinel-page-header">
		<h1><?php esc_html_e( 'Firewall', 'wp-sentinel-security' ); ?></h1>
		<p class="sentinel-page-subtitle">
			<?php esc_html_e( 'Manage blocked and whitelisted IP addresses. The WAF runs on every request before WordPress loads.', 'wp-sentinel-security' ); ?>
		</p>
	</div>

	<!-- WAF stats row -->
	<div class="sentinel-stats-row" style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;">
		<div class="sentinel-stat-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:20px;text-align:center;">
			<div style="font-size:2rem;font-weight:700;color:#e53935;"><?php echo esc_html( number_format_i18n( $waf_total ) ); ?></div>
			<div style="color:#555;margin-top:4px;"><?php esc_html_e( 'Total Blocked Requests', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="sentinel-stat-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:20px;text-align:center;">
			<div style="font-size:2rem;font-weight:700;color:#e53935;"><?php echo esc_html( number_format_i18n( $waf_today ) ); ?></div>
			<div style="color:#555;margin-top:4px;"><?php esc_html_e( 'Blocked Today', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="sentinel-stat-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:20px;text-align:center;">
			<div style="font-size:2rem;font-weight:700;color:#f57c00;"><?php echo esc_html( number_format_i18n( $waf_week ) ); ?></div>
			<div style="color:#555;margin-top:4px;"><?php esc_html_e( 'Blocked (Last 7 Days)', 'wp-sentinel-security' ); ?></div>
		</div>
	</div>

	<!-- Feedback notice (hidden by default) -->
	<div id="sentinel-firewall-notice" style="display:none;margin-bottom:16px;" class="notice"></div>

	<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">

		<!-- ── Block an IP ── -->
		<div class="sentinel-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;">
			<h2 style="margin-top:0;"><?php esc_html_e( 'Block IP / CIDR', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table" style="margin:0;">
				<tr>
					<th><label for="block-ip"><?php esc_html_e( 'IP or CIDR', 'wp-sentinel-security' ); ?></label></th>
					<td><input id="block-ip" type="text" class="regular-text" placeholder="203.0.113.0 or 203.0.113.0/24"></td>
				</tr>
				<tr>
					<th><label for="block-reason"><?php esc_html_e( 'Reason', 'wp-sentinel-security' ); ?></label></th>
					<td><input id="block-reason" type="text" class="regular-text" placeholder="<?php esc_attr_e( 'Optional note', 'wp-sentinel-security' ); ?>"></td>
				</tr>
				<tr>
					<th><label for="block-expiry"><?php esc_html_e( 'Expiry (hours)', 'wp-sentinel-security' ); ?></label></th>
					<td>
						<input id="block-expiry" type="number" class="small-text" min="0" value="0">
						<p class="description"><?php esc_html_e( '0 = permanent', 'wp-sentinel-security' ); ?></p>
					</td>
				</tr>
			</table>
			<button id="btn-block-ip" class="button button-primary" style="margin-top:12px;">
				<?php esc_html_e( 'Block IP', 'wp-sentinel-security' ); ?>
			</button>
		</div>

		<!-- ── Whitelist an IP ── -->
		<div class="sentinel-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;">
			<h2 style="margin-top:0;"><?php esc_html_e( 'Whitelist IP / CIDR', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table" style="margin:0;">
				<tr>
					<th><label for="wl-ip"><?php esc_html_e( 'IP or CIDR', 'wp-sentinel-security' ); ?></label></th>
					<td><input id="wl-ip" type="text" class="regular-text" placeholder="198.51.100.5 or 198.51.100.0/24"></td>
				</tr>
				<tr>
					<th><label for="wl-label"><?php esc_html_e( 'Label', 'wp-sentinel-security' ); ?></label></th>
					<td><input id="wl-label" type="text" class="regular-text" placeholder="<?php esc_attr_e( 'e.g. Office network', 'wp-sentinel-security' ); ?>"></td>
				</tr>
			</table>
			<button id="btn-whitelist-ip" class="button button-secondary" style="margin-top:12px;">
				<?php esc_html_e( 'Whitelist IP', 'wp-sentinel-security' ); ?>
			</button>
		</div>

	</div><!-- /grid -->

	<!-- ── Top blocked IPs from WAF log ── -->
	<?php if ( ! empty( $recent_blocks ) ) : ?>
	<div class="sentinel-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;margin-top:24px;">
		<h2 style="margin-top:0;"><?php esc_html_e( 'Top Blocked IPs (WAF Log)', 'wp-sentinel-security' ); ?></h2>
		<table class="wp-list-table widefat fixed striped" style="margin-top:12px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'IP Address', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Hits', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Last Seen', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Rules Hit', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $recent_blocks as $row ) : ?>
				<tr>
					<td><code><?php echo esc_html( $row['ip_address'] ); ?></code></td>
					<td><?php echo esc_html( number_format_i18n( (int) $row['hits'] ) ); ?></td>
					<td><?php echo esc_html( $row['last_seen'] ); ?></td>
					<td style="font-size:0.85em;color:#666;"><?php echo esc_html( $row['rules_hit'] ); ?></td>
					<td>
						<button class="button button-small btn-quick-block"
							data-ip="<?php echo esc_attr( $row['ip_address'] ); ?>"
							style="color:#c62828;border-color:#c62828;">
							<?php esc_html_e( 'Block', 'wp-sentinel-security' ); ?>
						</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php endif; ?>

	<!-- ── Blocked IP list ── -->
	<div class="sentinel-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;margin-top:24px;">
		<h2 style="margin-top:0;">
			<?php esc_html_e( 'Blocked IPs', 'wp-sentinel-security' ); ?>
			<span class="sentinel-badge" style="background:#e53935;color:#fff;font-size:0.75rem;padding:2px 8px;border-radius:10px;margin-left:8px;vertical-align:middle;">
				<?php echo esc_html( count( $blocked_ips ) ); ?>
			</span>
		</h2>
		<?php if ( empty( $blocked_ips ) ) : ?>
			<p style="color:#777;"><?php esc_html_e( 'No IPs are currently blocked.', 'wp-sentinel-security' ); ?></p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped" id="sentinel-blocked-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP / CIDR', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Blocked At', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $blocked_ips as $ip => $meta ) : ?>
					<tr id="blocked-row-<?php echo esc_attr( md5( $ip ) ); ?>">
						<td><code><?php echo esc_html( $ip ); ?></code></td>
						<td><?php echo esc_html( $meta['reason'] ?? '' ); ?></td>
						<td><?php echo esc_html( ! empty( $meta['blocked_at'] ) ? gmdate( 'Y-m-d H:i', (int) $meta['blocked_at'] ) : '—' ); ?></td>
						<td>
							<?php
							if ( empty( $meta['expiry'] ) ) {
								esc_html_e( 'Permanent', 'wp-sentinel-security' );
							} else {
								echo esc_html( gmdate( 'Y-m-d H:i', (int) $meta['expiry'] ) );
							}
							?>
						</td>
						<td>
							<button class="button button-small btn-unblock"
								data-ip="<?php echo esc_attr( $ip ); ?>"
								data-row="<?php echo esc_attr( md5( $ip ) ); ?>">
								<?php esc_html_e( 'Unblock', 'wp-sentinel-security' ); ?>
							</button>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<!-- ── Whitelist ── -->
	<div class="sentinel-card" style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;margin-top:24px;">
		<h2 style="margin-top:0;">
			<?php esc_html_e( 'Whitelisted IPs', 'wp-sentinel-security' ); ?>
			<span class="sentinel-badge" style="background:#43a047;color:#fff;font-size:0.75rem;padding:2px 8px;border-radius:10px;margin-left:8px;vertical-align:middle;">
				<?php echo esc_html( count( $whitelisted ) ); ?>
			</span>
		</h2>
		<?php if ( empty( $whitelisted ) ) : ?>
			<p style="color:#777;"><?php esc_html_e( 'No IPs are currently whitelisted.', 'wp-sentinel-security' ); ?></p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped" id="sentinel-whitelist-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP / CIDR', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Label', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Added At', 'wp-sentinel-security' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $whitelisted as $ip => $meta ) : ?>
					<tr id="wl-row-<?php echo esc_attr( md5( $ip ) ); ?>">
						<td><code><?php echo esc_html( $ip ); ?></code></td>
						<td><?php echo esc_html( $meta['label'] ?? '' ); ?></td>
						<td><?php echo esc_html( ! empty( $meta['added_at'] ) ? gmdate( 'Y-m-d H:i', (int) $meta['added_at'] ) : '—' ); ?></td>
						<td>
							<button class="button button-small btn-unwhitelist"
								data-ip="<?php echo esc_attr( $ip ); ?>"
								data-row="<?php echo esc_attr( md5( $ip ) ); ?>">
								<?php esc_html_e( 'Remove', 'wp-sentinel-security' ); ?>
							</button>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

</div><!-- /.sentinel-firewall -->

<script>
(function($) {
	'use strict';

	var nonce   = '<?php echo esc_js( $firewall_nonce ); ?>';
	var ajaxUrl = '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>';

	function showNotice( msg, type ) {
		var $n = $('#sentinel-firewall-notice');
		$n.removeClass('notice-success notice-error').addClass( 'notice notice-' + type ).html('<p>' + msg + '</p>').show();
		setTimeout(function(){ $n.fadeOut(); }, 5000);
	}

	function post( action, data, onSuccess ) {
		data.action = action;
		data.nonce  = nonce;
		$.post( ajaxUrl, data, function( r ) {
			if ( r.success ) {
				showNotice( r.data.message, 'success' );
				if ( typeof onSuccess === 'function' ) onSuccess();
			} else {
				showNotice( r.data.message, 'error' );
			}
		} ).fail(function(){
			showNotice( '<?php echo esc_js( __( 'Request failed. Please try again.', 'wp-sentinel-security' ) ); ?>', 'error' );
		});
	}

	// Block IP form.
	$('#btn-block-ip').on('click', function() {
		var ip     = $.trim( $('#block-ip').val() );
		var reason = $.trim( $('#block-reason').val() );
		var hours  = parseInt( $('#block-expiry').val(), 10 ) || 0;
		var expiry = hours > 0 ? Math.floor( Date.now() / 1000 ) + ( hours * 3600 ) : 0;
		if ( ! ip ) { showNotice('<?php echo esc_js( __( 'Please enter an IP address.', 'wp-sentinel-security' ) ); ?>', 'error'); return; }
		post( 'sentinel_block_ip', { ip: ip, reason: reason, expiry: expiry }, function() {
			location.reload();
		});
	});

	// Whitelist IP form.
	$('#btn-whitelist-ip').on('click', function() {
		var ip    = $.trim( $('#wl-ip').val() );
		var label = $.trim( $('#wl-label').val() );
		if ( ! ip ) { showNotice('<?php echo esc_js( __( 'Please enter an IP address.', 'wp-sentinel-security' ) ); ?>', 'error'); return; }
		post( 'sentinel_whitelist_ip', { ip: ip, label: label }, function() {
			location.reload();
		});
	});

	// Unblock buttons.
	$(document).on('click', '.btn-unblock', function() {
		var ip  = $(this).data('ip');
		var row = $(this).data('row');
		post( 'sentinel_unblock_ip', { ip: ip }, function() {
			$('#blocked-row-' + row).fadeOut(300, function(){ $(this).remove(); });
		});
	});

	// Remove-from-whitelist buttons.
	$(document).on('click', '.btn-unwhitelist', function() {
		var ip  = $(this).data('ip');
		var row = $(this).data('row');
		post( 'sentinel_unwhitelist_ip', { ip: ip }, function() {
			$('#wl-row-' + row).fadeOut(300, function(){ $(this).remove(); });
		});
	});

	// One-click block from WAF log table.
	$(document).on('click', '.btn-quick-block', function() {
		var ip = $(this).data('ip');
		post( 'sentinel_block_ip', { ip: ip, reason: '<?php echo esc_js( __( 'Blocked from WAF log', 'wp-sentinel-security' ) ); ?>', expiry: 0 }, function() {
			location.reload();
		});
	});

})(jQuery);
</script>
