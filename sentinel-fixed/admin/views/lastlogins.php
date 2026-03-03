<?php
/**
 * Last Logins admin view.
 *
 * @package WP_Sentinel_Security
 * @var array $login_data  Array with keys: total (int), entries (array).
 * @var int   $page        Current page number.
 * @var array $stats       30-day stats: logins, failed, logouts.
 * @var array $active_users Currently logged-in users.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$entries      = $login_data['entries'] ?? array();
$total        = $login_data['total']   ?? 0;
$per_page     = 50;
$pages        = $total > 0 ? (int) ceil( $total / $per_page ) : 1;
$stats        = $stats        ?? array( 'logins' => 0, 'failed' => 0, 'logouts' => 0 );
$active_users = $active_users ?? array();

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_event = isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-admin-users sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Last Logins', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-subtitle">
					<?php printf( esc_html__( '%d events recorded', 'wp-sentinel-security' ), (int) $total ); ?>
				</span>
			</div>
		</div>
	</div>

	<!-- KPI cards -->
	<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px;">
		<?php
		$kpis = array(
			array( 'label' => __( 'Successful Logins (30d)', 'wp-sentinel-security' ), 'value' => $stats['logins'],  'icon' => 'dashicons-yes-alt', 'color' => '#16a34a', 'event' => 'login'  ),
			array( 'label' => __( 'Failed Logins (30d)',    'wp-sentinel-security' ), 'value' => $stats['failed'],  'icon' => 'dashicons-warning',  'color' => '#dc2626', 'event' => 'failed' ),
			array( 'label' => __( 'Logouts (30d)',          'wp-sentinel-security' ), 'value' => $stats['logouts'], 'icon' => 'dashicons-exit',     'color' => '#2563eb', 'event' => 'logout' ),
		);
		foreach ( $kpis as $kpi ) :
			$url = add_query_arg( array( 'page' => 'sentinel-lastlogins', 'event' => $kpi['event'] ), admin_url( 'admin.php' ) );
		?>
			<a href="<?php echo esc_url( $url ); ?>" style="text-decoration:none;">
				<div class="sentinel-card" style="padding:18px 20px;display:flex;align-items:center;gap:14px;">
					<span class="dashicons <?php echo esc_attr( $kpi['icon'] ); ?>"
						style="font-size:28px;width:28px;height:28px;color:<?php echo esc_attr( $kpi['color'] ); ?>;flex-shrink:0;"></span>
					<div>
						<div style="font-size:26px;font-weight:700;color:<?php echo esc_attr( $kpi['color'] ); ?>;">
							<?php echo esc_html( number_format_i18n( $kpi['value'] ) ); ?>
						</div>
						<div style="font-size:12px;color:#64748b;margin-top:3px;"><?php echo esc_html( $kpi['label'] ); ?></div>
					</div>
				</div>
			</a>
		<?php endforeach; ?>
	</div>

	<!-- Active sessions -->
	<?php if ( ! empty( $active_users ) ) : ?>
	<div class="sentinel-card" style="margin-bottom:20px;">
		<div style="padding:16px 24px;border-bottom:1px solid #e2e8f0;">
			<h3 style="margin:0;font-size:14px;font-weight:700;color:#1e293b;">
				<span class="dashicons dashicons-admin-users" style="color:#16a34a;vertical-align:middle;margin-right:6px;"></span>
				<?php printf( esc_html__( 'Active Sessions (%d)', 'wp-sentinel-security' ), count( $active_users ) ); ?>
			</h3>
		</div>
		<table class="sentinel-table widefat" style="border:none;">
			<thead><tr>
				<th><?php esc_html_e( 'User', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Login', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Roles', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Sessions', 'wp-sentinel-security' ); ?></th>
			</tr></thead>
			<tbody>
				<?php foreach ( $active_users as $u ) : ?>
				<tr>
					<td><?php echo esc_html( $u['display_name'] ?? $u['user_login'] ); ?></td>
					<td><code><?php echo esc_html( $u['user_login'] ); ?></code></td>
					<td><?php echo esc_html( $u['roles'] ?? '—' ); ?></td>
					<td><?php echo esc_html( $u['session_count'] ); ?></td>
				</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php endif; ?>

	<!-- Filters -->
	<div class="sentinel-card" style="padding:16px 24px;margin-bottom:16px;">
		<form method="get" action="" style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;">
			<input type="hidden" name="page" value="sentinel-lastlogins">
			<div>
				<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:#475569;"><?php esc_html_e( 'Event Type', 'wp-sentinel-security' ); ?></label>
				<select name="event">
					<option value=""      <?php selected( $filter_event, '' ); ?>><?php esc_html_e( 'All Events',       'wp-sentinel-security' ); ?></option>
					<option value="login"  <?php selected( $filter_event, 'login'  ); ?>><?php esc_html_e( 'Successful Login', 'wp-sentinel-security' ); ?></option>
					<option value="failed" <?php selected( $filter_event, 'failed' ); ?>><?php esc_html_e( 'Failed Login',     'wp-sentinel-security' ); ?></option>
					<option value="logout" <?php selected( $filter_event, 'logout' ); ?>><?php esc_html_e( 'Logout',           'wp-sentinel-security' ); ?></option>
				</select>
			</div>
			<div>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Filter', 'wp-sentinel-security' ); ?></button>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-lastlogins' ) ); ?>" class="button" style="margin-left:4px;">
					<?php esc_html_e( 'Reset', 'wp-sentinel-security' ); ?>
				</a>
			</div>
		</form>
	</div>

	<!-- Events table -->
	<div class="sentinel-card">
		<div style="padding:16px 24px;border-bottom:1px solid #e2e8f0;">
			<h3 style="margin:0;font-size:14px;font-weight:700;color:#1e293b;"><?php esc_html_e( 'Login Events', 'wp-sentinel-security' ); ?></h3>
		</div>

		<?php if ( empty( $entries ) ) : ?>
			<div style="padding:48px;text-align:center;color:#94a3b8;">
				<span class="dashicons dashicons-admin-users" style="font-size:48px;width:48px;height:48px;display:block;margin:0 auto 12px;"></span>
				<?php esc_html_e( 'No login events found.', 'wp-sentinel-security' ); ?>
			</div>
		<?php else : ?>
			<table class="sentinel-table widefat" style="border:none;">
				<thead><tr>
					<th><?php esc_html_e( 'Date / Time',  'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'User',         'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Event',        'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'IP Address',   'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'User Agent',   'wp-sentinel-security' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $entries as $row ) :
					$event = $row['event'] ?? '';
					$colors = array( 'login' => '#16a34a', 'failed' => '#dc2626', 'logout' => '#2563eb' );
					$labels = array(
						'login'  => __( 'Login',  'wp-sentinel-security' ),
						'failed' => __( 'Failed', 'wp-sentinel-security' ),
						'logout' => __( 'Logout', 'wp-sentinel-security' ),
					);
					$c = $colors[ $event ] ?? '#64748b';
					$l = $labels[ $event ] ?? ucfirst( $event );
					$uid = absint( $row['user_id'] ?? 0 );
				?>
					<tr>
						<td style="white-space:nowrap;"><?php echo esc_html( $row['created_at'] ?? '—' ); ?></td>
						<td>
							<?php if ( $uid ) : ?>
								<a href="<?php echo esc_url( get_edit_user_link( $uid ) ); ?>"><?php echo esc_html( $row['user_login'] ?? '' ); ?></a>
							<?php else : ?>
								<?php echo esc_html( $row['user_login'] ?? '—' ); ?>
							<?php endif; ?>
						</td>
						<td>
							<span style="display:inline-block;padding:2px 10px;border-radius:9999px;font-size:11px;font-weight:700;color:#fff;background:<?php echo esc_attr( $c ); ?>;">
								<?php echo esc_html( $l ); ?>
							</span>
						</td>
						<td><code><?php echo esc_html( $row['ip_address'] ?? '—' ); ?></code></td>
						<td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?php echo esc_attr( $row['user_agent'] ?? '' ); ?>">
							<?php echo esc_html( $row['user_agent'] ?? '—' ); ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
			<div style="padding:12px 24px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;">
				<span style="font-size:13px;color:#64748b;">
					<?php printf( esc_html__( 'Page %1$d of %2$d', 'wp-sentinel-security' ), (int) $page, (int) $pages ); ?>
				</span>
				<div style="display:flex;gap:4px;">
					<?php if ( $page > 1 ) : ?>
					<a href="<?php echo esc_url( add_query_arg( array( 'page' => 'sentinel-lastlogins', 'paged' => $page - 1, 'event' => $filter_event ), admin_url( 'admin.php' ) ) ); ?>" class="button button-small">
						&laquo; <?php esc_html_e( 'Previous', 'wp-sentinel-security' ); ?>
					</a>
					<?php endif; ?>
					<?php if ( $page < $pages ) : ?>
					<a href="<?php echo esc_url( add_query_arg( array( 'page' => 'sentinel-lastlogins', 'paged' => $page + 1, 'event' => $filter_event ), admin_url( 'admin.php' ) ) ); ?>" class="button button-small">
						<?php esc_html_e( 'Next', 'wp-sentinel-security' ); ?> &raquo;
					</a>
					<?php endif; ?>
				</div>
			</div>
			<?php endif; ?>
		<?php endif; ?>
	</div>

</div><!-- .wrap -->
