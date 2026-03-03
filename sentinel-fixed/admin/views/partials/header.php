<?php
/**
 * Reusable admin navigation header partial.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : 'sentinel-security'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

$nav_items = array(
	'sentinel-security'      => __( 'Dashboard', 'wp-sentinel-security' ),
	'sentinel-scanner'       => __( 'Scanner', 'wp-sentinel-security' ),
	'sentinel-hardening'     => __( 'Hardening', 'wp-sentinel-security' ),
	'sentinel-backups'       => __( 'Backups', 'wp-sentinel-security' ),
	'sentinel-reports'       => __( 'Reports', 'wp-sentinel-security' ),
	'sentinel-alerts'        => __( 'Alerts', 'wp-sentinel-security' ),
	'sentinel-activity'      => __( 'Activity', 'wp-sentinel-security' ),
	'sentinel-intelligence'  => __( 'Intelligence', 'wp-sentinel-security' ),
	'sentinel-settings'      => __( 'Settings', 'wp-sentinel-security' ),
);

$available_languages = array(
	''      => __( 'English', 'wp-sentinel-security' ),
	'es_ES' => 'Español',
	'fr_FR' => 'Français',
	'de_DE' => 'Deutsch',
	'pt_BR' => 'Português',
	'it_IT' => 'Italiano',
);
$current_lang = get_option( 'sentinel_language', '' );
?>

<nav class="sentinel-nav-header">
	<div class="sentinel-nav-brand">
		<span class="dashicons dashicons-shield-alt"></span>
		<strong><?php esc_html_e( 'Sentinel', 'wp-sentinel-security' ); ?></strong>
	</div>
	<ul class="sentinel-nav-tabs">
		<?php foreach ( $nav_items as $slug => $label ) : ?>
			<li>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $slug ) ); ?>"
				   class="sentinel-nav-tab<?php echo $current_page === $slug ? ' sentinel-nav-tab-active' : ''; ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			</li>
		<?php endforeach; ?>
	</ul>
	<div class="sentinel-lang-switcher" title="<?php esc_attr_e( 'Switch language', 'wp-sentinel-security' ); ?>">
		<span class="dashicons dashicons-translation" style="vertical-align:middle;margin-right:4px;"></span>
		<select id="sentinel-lang-select" style="font-size:12px;padding:2px 4px;">
			<?php foreach ( $available_languages as $locale => $label ) : ?>
				<option value="<?php echo esc_attr( $locale ); ?>"<?php selected( $current_lang, $locale ); ?>>
					<?php echo esc_html( $label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</div>
</nav>
<script>
(function(){
	var sel = document.getElementById('sentinel-lang-select');
	if ( ! sel ) { return; }
	sel.addEventListener('change', function(){
		var locale = this.value;
		var data = new FormData();
		data.append( 'action', 'sentinel_switch_language' );
		data.append( 'nonce',  '<?php echo esc_js( wp_create_nonce( 'sentinel_nonce' ) ); ?>' );
		data.append( 'locale', locale );
		fetch( '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>', {
			method: 'POST',
			body: data,
			credentials: 'same-origin',
		})
		.then( function(r){ return r.json(); })
		.then( function(res){
			if ( res.success ) {
				window.location.reload();
			} else {
				alert( res.data && res.data.message ? res.data.message : 'Error switching language.' );
			}
		})
		.catch( function(){ alert( 'Network error.' ); });
	});
}());
</script>
