<?php
/**
 * Security Headers admin view.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

if ( ! class_exists( 'Sentinel_Security_Headers' ) ) {
	require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-security-headers.php';
}

// ── Handle save ───────────────────────────────────────────────────────────────
$saved_notice = '';
if ( isset( $_POST['sentinel_headers_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['sentinel_headers_nonce'] ) ), 'sentinel_save_headers' ) && current_user_can( 'manage_options' ) ) {
	Sentinel_Security_Headers::save_config( wp_unslash( $_POST['sentinel_headers'] ?? array() ) );
	$saved_notice = '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Security header settings saved.', 'wp-sentinel-security' ) . '</p></div>';
}

$cfg = Sentinel_Security_Headers::get_config();
$pp  = $cfg['permissions_policy'];

$xfo_options = array( 'SAMEORIGIN' => 'SAMEORIGIN', 'DENY' => 'DENY', 'disabled' => __( 'Disabled', 'wp-sentinel-security' ) );
$rp_options  = array(
	'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin (recommended)',
	'no-referrer'                     => 'no-referrer',
	'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade',
	'same-origin'                     => 'same-origin',
	'strict-origin'                   => 'strict-origin',
	'origin'                          => 'origin',
	'origin-when-cross-origin'        => 'origin-when-cross-origin',
	'unsafe-url'                      => 'unsafe-url',
);

$pp_features = array(
	'camera' => 'Camera', 'microphone' => 'Microphone', 'geolocation' => 'Geolocation',
	'payment' => 'Payment', 'usb' => 'USB', 'fullscreen' => 'Fullscreen',
	'accelerometer' => 'Accelerometer', 'gyroscope' => 'Gyroscope',
	'magnetometer' => 'Magnetometer', 'display-capture' => 'Display Capture',
);
$pp_values = array( 'none' => __( 'Block ()', 'wp-sentinel-security' ), 'self' => __( 'Self (self)', 'wp-sentinel-security' ), '*' => __( 'Allow (*)', 'wp-sentinel-security' ) );

$csp_modes  = array( 'disabled' => __( 'Disabled', 'wp-sentinel-security' ), 'report-only' => __( 'Report-Only', 'wp-sentinel-security' ), 'enforce' => __( 'Enforce', 'wp-sentinel-security' ) );
$csp_mode   = $cfg['csp_enabled'] ?: 'disabled';
?>

<div class="wrap sentinel-wrap">

<div class="sentinel-page-header">
	<div class="sentinel-header-left">
		<span class="dashicons dashicons-lock sentinel-header-icon"></span>
		<h1><?php esc_html_e( 'Security Headers', 'wp-sentinel-security' ); ?></h1>
	</div>
</div>

<?php echo $saved_notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

<form method="post" action="">
<?php wp_nonce_field( 'sentinel_save_headers', 'sentinel_headers_nonce' ); ?>

<!-- ── Simple Headers ───────────────────────────────────────────────────────── -->
<div class="sentinel-card">
	<h2><?php esc_html_e( 'Basic Security Headers', 'wp-sentinel-security' ); ?></h2>
	<table class="form-table">
		<tr>
			<th><?php esc_html_e( 'X-Content-Type-Options', 'wp-sentinel-security' ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="sentinel_headers[x_content_type_options]" value="1" <?php checked( $cfg['x_content_type_options'] ); ?>>
					<?php esc_html_e( 'Send "nosniff" — prevents browsers from MIME-sniffing responses', 'wp-sentinel-security' ); ?>
				</label>
			</td>
		</tr>
		<tr>
			<th><label for="sh-xfo"><?php esc_html_e( 'X-Frame-Options', 'wp-sentinel-security' ); ?></label></th>
			<td>
				<select name="sentinel_headers[x_frame_options]" id="sh-xfo">
					<?php foreach ( $xfo_options as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $cfg['x_frame_options'], $val ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
				<p class="description"><?php esc_html_e( 'Controls whether the site can be embedded in frames (clickjacking protection).', 'wp-sentinel-security' ); ?></p>
			</td>
		</tr>
		<tr>
			<th><label for="sh-rp"><?php esc_html_e( 'Referrer-Policy', 'wp-sentinel-security' ); ?></label></th>
			<td>
				<select name="sentinel_headers[referrer_policy]" id="sh-rp">
					<?php foreach ( $rp_options as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $cfg['referrer_policy'], $val ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
				<p class="description"><?php esc_html_e( 'Controls how much referrer information is sent with requests.', 'wp-sentinel-security' ); ?></p>
			</td>
		</tr>
	</table>
</div>

<!-- ── HSTS ─────────────────────────────────────────────────────────────────── -->
<div class="sentinel-card" style="margin-top:20px;">
	<h2><?php esc_html_e( 'HTTP Strict Transport Security (HSTS)', 'wp-sentinel-security' ); ?></h2>
	<p class="description" style="margin-bottom:16px;">
		<?php esc_html_e( 'HSTS tells browsers to always use HTTPS. Only enable if your site is fully served over HTTPS.', 'wp-sentinel-security' ); ?>
		<?php if ( ! is_ssl() ) : ?>
			<strong style="color:#e53935;"><?php esc_html_e( '⚠ Your site does not appear to be served over HTTPS — enabling HSTS may break access.', 'wp-sentinel-security' ); ?></strong>
		<?php endif; ?>
	</p>
	<table class="form-table">
		<tr>
			<th><?php esc_html_e( 'Enable HSTS', 'wp-sentinel-security' ); ?></th>
			<td><label><input type="checkbox" name="sentinel_headers[hsts_enabled]" value="1" <?php checked( $cfg['hsts_enabled'] ); ?>> <?php esc_html_e( 'Send Strict-Transport-Security header', 'wp-sentinel-security' ); ?></label></td>
		</tr>
		<tr>
			<th><label for="sh-hsts-age"><?php esc_html_e( 'Max-Age (seconds)', 'wp-sentinel-security' ); ?></label></th>
			<td><input type="number" id="sh-hsts-age" name="sentinel_headers[hsts_max_age]" value="<?php echo esc_attr( $cfg['hsts_max_age'] ); ?>" min="0" class="small-text"> <span style="color:#777;"><?php esc_html_e( '(31536000 = 1 year)', 'wp-sentinel-security' ); ?></span></td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'Include Sub-Domains', 'wp-sentinel-security' ); ?></th>
			<td><label><input type="checkbox" name="sentinel_headers[hsts_include_subdomains]" value="1" <?php checked( $cfg['hsts_include_subdomains'] ); ?>> includeSubDomains</label></td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'Preload', 'wp-sentinel-security' ); ?></th>
			<td>
				<label><input type="checkbox" name="sentinel_headers[hsts_preload]" value="1" <?php checked( $cfg['hsts_preload'] ); ?>> preload</label>
				<p class="description"><?php esc_html_e( 'Only enable if you intend to submit to the HSTS preload list. Requires includeSubDomains and max-age ≥ 31536000.', 'wp-sentinel-security' ); ?></p>
			</td>
		</tr>
	</table>
</div>

<!-- ── Permissions-Policy ───────────────────────────────────────────────────── -->
<div class="sentinel-card" style="margin-top:20px;">
	<h2><?php esc_html_e( 'Permissions-Policy', 'wp-sentinel-security' ); ?></h2>
	<p class="description" style="margin-bottom:16px;"><?php esc_html_e( 'Controls browser feature access. "Block" prevents any origin from using the feature.', 'wp-sentinel-security' ); ?></p>
	<table class="form-table">
		<?php foreach ( $pp_features as $feature => $label ) :
			$key = str_replace( '-', '_', $feature );
			$cur = $pp[ $key ] ?? ( $pp[ $feature ] ?? 'none' );
		?>
		<tr>
			<th><?php echo esc_html( $label ); ?></th>
			<td>
				<select name="sentinel_headers[permissions_policy][<?php echo esc_attr( $key ); ?>]">
					<?php foreach ( $pp_values as $v => $vl ) : ?>
						<option value="<?php echo esc_attr( $v ); ?>" <?php selected( $cur, $v ); ?>><?php echo esc_html( $vl ); ?></option>
					<?php endforeach; ?>
				</select>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
</div>

<!-- ── CSP ──────────────────────────────────────────────────────────────────── -->
<div class="sentinel-card" style="margin-top:20px;">
	<h2><?php esc_html_e( 'Content Security Policy (CSP)', 'wp-sentinel-security' ); ?></h2>
	<p class="description" style="margin-bottom:12px;">
		<?php esc_html_e( 'Use "Report-Only" first to test your policy without blocking anything, then switch to "Enforce" once validated.', 'wp-sentinel-security' ); ?>
	</p>
	<table class="form-table">
		<tr>
			<th><label for="sh-csp-mode"><?php esc_html_e( 'CSP Mode', 'wp-sentinel-security' ); ?></label></th>
			<td>
				<select name="sentinel_headers[csp_enabled]" id="sh-csp-mode">
					<?php foreach ( $csp_modes as $v => $l ) : ?>
						<option value="<?php echo esc_attr( $v ); ?>" <?php selected( $csp_mode, $v ); ?>><?php echo esc_html( $l ); ?></option>
					<?php endforeach; ?>
				</select>
			</td>
		</tr>
	</table>

	<table class="wp-list-table widefat fixed striped" style="margin-top:12px;">
		<thead><tr>
			<th style="width:40px;"><?php esc_html_e( 'On', 'wp-sentinel-security' ); ?></th>
			<th><?php esc_html_e( 'Directive', 'wp-sentinel-security' ); ?></th>
			<th><?php esc_html_e( 'Value', 'wp-sentinel-security' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $cfg['csp_directives'] as $directive => $opt ) : ?>
		<tr>
			<td><input type="checkbox" name="sentinel_headers[csp_directives][<?php echo esc_attr( $directive ); ?>][enabled]" value="1" <?php checked( ! empty( $opt['enabled'] ) ); ?>></td>
			<td><code><?php echo esc_html( $directive ); ?></code></td>
			<td>
				<?php if ( 'upgrade-insecure-requests' !== $directive ) : ?>
				<input type="text" name="sentinel_headers[csp_directives][<?php echo esc_attr( $directive ); ?>][value]"
					value="<?php echo esc_attr( $opt['value'] ); ?>"
					class="large-text code" style="font-size:0.85em;"
					placeholder="<?php echo esc_attr( $directive === 'report-uri' ? 'https://...' : "'self'" ); ?>">
				<?php else : ?>
				<em style="color:#888;"><?php esc_html_e( '(no value required)', 'wp-sentinel-security' ); ?></em>
				<input type="hidden" name="sentinel_headers[csp_directives][upgrade-insecure-requests][value]" value="">
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>

<!-- ── CORS ─────────────────────────────────────────────────────────────────── -->
<div class="sentinel-card" style="margin-top:20px;">
	<h2><?php esc_html_e( 'Cross-Origin Resource Sharing (CORS)', 'wp-sentinel-security' ); ?></h2>
	<p class="description" style="margin-bottom:12px;"><?php esc_html_e( 'Only configure CORS if your site serves an API accessed from other domains. Incorrect settings can expose your data.', 'wp-sentinel-security' ); ?></p>
	<table class="form-table">
		<tr>
			<th><?php esc_html_e( 'Enable CORS Headers', 'wp-sentinel-security' ); ?></th>
			<td><label><input type="checkbox" name="sentinel_headers[cors_enabled]" value="1" <?php checked( $cfg['cors_enabled'] ); ?>> <?php esc_html_e( 'Send CORS headers on all responses', 'wp-sentinel-security' ); ?></label></td>
		</tr>
	</table>

	<?php
	$cors_labels = array(
		'allow_origin'      => array( 'label' => 'Access-Control-Allow-Origin',      'placeholder' => '* or https://example.com' ),
		'allow_methods'     => array( 'label' => 'Access-Control-Allow-Methods',     'placeholder' => 'GET, POST, OPTIONS' ),
		'allow_headers'     => array( 'label' => 'Access-Control-Allow-Headers',     'placeholder' => 'Content-Type, Authorization' ),
		'allow_credentials' => array( 'label' => 'Access-Control-Allow-Credentials', 'placeholder' => 'true' ),
		'expose_headers'    => array( 'label' => 'Access-Control-Expose-Headers',    'placeholder' => 'X-Custom-Header' ),
		'max_age'           => array( 'label' => 'Access-Control-Max-Age',           'placeholder' => '3600' ),
	);
	?>
	<table class="wp-list-table widefat fixed striped" style="margin-top:12px;">
		<thead><tr>
			<th style="width:40px;"><?php esc_html_e( 'On', 'wp-sentinel-security' ); ?></th>
			<th><?php esc_html_e( 'Header', 'wp-sentinel-security' ); ?></th>
			<th><?php esc_html_e( 'Value', 'wp-sentinel-security' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $cors_labels as $key => $info ) :
			$opt = $cfg['cors_options'][ $key ] ?? array( 'enabled' => false, 'value' => '' );
		?>
		<tr>
			<td><input type="checkbox" name="sentinel_headers[cors_options][<?php echo esc_attr( $key ); ?>][enabled]" value="1" <?php checked( ! empty( $opt['enabled'] ) ); ?>></td>
			<td><code style="font-size:0.85em;"><?php echo esc_html( $info['label'] ); ?></code></td>
			<td>
				<input type="text" name="sentinel_headers[cors_options][<?php echo esc_attr( $key ); ?>][value]"
					value="<?php echo esc_attr( $opt['value'] ); ?>"
					class="regular-text code" style="font-size:0.85em;"
					placeholder="<?php echo esc_attr( $info['placeholder'] ); ?>">
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>

<?php submit_button( __( 'Save Header Settings', 'wp-sentinel-security' ) ); ?>
</form>
</div>
