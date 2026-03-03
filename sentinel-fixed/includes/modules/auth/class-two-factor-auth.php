<?php
/**
 * Two-Factor Authentication (TOTP).
 *
 * Provides TOTP-based 2FA for WordPress users.
 *
 * Flow overview
 * ─────────────
 * 1. Admin enables the 2FA feature in Settings and optionally marks roles as
 *    "required". Users in required roles who have not yet configured 2FA see
 *    a mandatory-setup notice after they log in.
 *
 * 2. Users configure 2FA from their Profile page via an AJAX-driven wizard:
 *    a) Click "Set up 2FA" → AJAX returns a new secret + QR code URL.
 *    b) User scans QR / enters secret in their authenticator app.
 *    c) User types the live 6-digit code to confirm → AJAX validates and
 *       persists the secret, then returns one-time recovery codes.
 *    d) User copies recovery codes and dismisses the modal.
 *
 * 3. On subsequent logins WordPress fires wp_login → handle_login() clears the
 *    auth cookie, stores a short-lived transient keyed to the user, and
 *    redirects to the TOTP verification form.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0  (profile UI and TOTP core)
 * @since   2.3.0  (role enforcement, AJAX setup wizard, admin management)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Two_Factor_Auth {

	const META_SECRET   = 'sentinel_2fa_secret';
	const META_ENABLED  = 'sentinel_2fa_enabled';
	const META_RECOVERY = 'sentinel_2fa_recovery';

	const PERIOD       = 30;
	const DIGITS       = 6;
	const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/** @var array */
	private $settings;

	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function init() {
		// Profile UI always available.
		add_action( 'admin_init',            array( $this, 'register_user_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

		// AJAX endpoints for the setup wizard.
		add_action( 'wp_ajax_sentinel_2fa_get_setup',     array( $this, 'ajax_get_setup' ) );
		add_action( 'wp_ajax_sentinel_2fa_confirm_setup', array( $this, 'ajax_confirm_setup' ) );
		add_action( 'wp_ajax_sentinel_2fa_disable',       array( $this, 'ajax_disable' ) );

		// Login-time enforcement only when feature is globally on.
		if ( $this->is_feature_enabled() ) {
			add_action( 'wp_login', array( $this, 'handle_login' ), 10, 2 );
			add_action( 'login_form_sentinel_2fa',          array( $this, 'render_2fa_form' ) );
			add_action( 'login_form_sentinel_2fa_required', array( $this, 'render_required_notice' ) );
		}
	}

	// ── Settings helpers ──────────────────────────────────────────────────────

	public function is_feature_enabled() {
		return ! empty( $this->settings['2fa_enabled'] );
	}

	/**
	 * Whether 2FA is required for the given user based on their role.
	 *
	 * @param WP_User $user
	 * @return bool
	 */
	public function is_required_for_user( $user ) {
		if ( ! $this->is_feature_enabled() ) {
			return false;
		}
		$required_roles = $this->settings['2fa_required_roles'] ?? array();
		if ( empty( $required_roles ) || ! is_array( $required_roles ) ) {
			return false;
		}
		return (bool) array_intersect( (array) ( $user->roles ?? array() ), $required_roles );
	}

	// ── Per-user state ────────────────────────────────────────────────────────

	public function is_enabled_for_user( $user_id ) {
		return '1' === get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Persist a confirmed secret and generate recovery codes.
	 *
	 * @param int    $user_id
	 * @param string $secret Base32-encoded TOTP secret.
	 * @return string[] Plain-text recovery codes.
	 */
	/**
	 * Persist a confirmed secret and generate recovery codes.
	 *
	 * Recovery codes are stored as bcrypt hashes (password_hash) rather than
	 * wp_hash() (HMAC-MD5). This matches the same security bar as WordPress
	 * user passwords.
	 *
	 * @param int    $user_id
	 * @param string $secret Base32-encoded TOTP secret.
	 * @return string[] Plain-text recovery codes.
	 */
	public function enable_for_user( $user_id, $secret ) {
		$recovery_codes = $this->generate_recovery_codes();
		// Store bcrypt hashes — never plain-text.
		$hashed = array_map(
			function ( $code ) {
				return password_hash( $code, PASSWORD_DEFAULT );
			},
			$recovery_codes
		);

		update_user_meta( $user_id, self::META_SECRET,   $secret );
		update_user_meta( $user_id, self::META_ENABLED,  '1' );
		update_user_meta( $user_id, self::META_RECOVERY, wp_json_encode( $hashed ) );

		return $recovery_codes;
	}

	public function disable_for_user( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_RECOVERY );
	}

	// ── Login-time enforcement ─────────────────────────────────────────────────

	/**
	 * Intercept successful logins when 2FA is enabled or required.
	 *
	 * @param string   $user_login
	 * @param WP_User  $user
	 */
	public function handle_login( $user_login, $user ) {
		// ── Case 1: user has 2FA active → TOTP verification form.
		if ( $this->is_enabled_for_user( $user->ID ) ) {
			wp_clear_auth_cookie();

			$token = wp_hash( $user->ID . '|' . wp_rand() . '|' . time() );
			set_transient( 'sentinel_2fa_' . $token, $user->ID, 5 * MINUTE_IN_SECONDS );

			wp_safe_redirect( add_query_arg( array(
				'action'         => 'sentinel_2fa',
				'sentinel_token' => rawurlencode( $token ),
			), wp_login_url() ) );
			exit;
		}

		// ── Case 2: 2FA required for this role but not yet set up → setup notice.
		if ( $this->is_required_for_user( $user ) ) {
			wp_clear_auth_cookie();

			$token = wp_hash( $user->ID . '|setup|' . time() );
			set_transient( 'sentinel_2fa_setup_required_' . $token, $user->ID, 10 * MINUTE_IN_SECONDS );

			wp_safe_redirect( add_query_arg( array(
				'action'         => 'sentinel_2fa_required',
				'sentinel_token' => rawurlencode( $token ),
			), wp_login_url() ) );
			exit;
		}
	}

	/**
	 * Render the TOTP verification form (second login step).
	 */
	public function render_2fa_form() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token   = isset( $_REQUEST['sentinel_token'] )
			? sanitize_text_field( wp_unslash( $_REQUEST['sentinel_token'] ) )
			: '';
		$user_id = get_transient( 'sentinel_2fa_' . $token );

		if ( ! $user_id ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$error = '';

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'sentinel_2fa_verify' );

			$code   = sanitize_text_field( wp_unslash( $_POST['sentinel_2fa_code'] ?? '' ) );
			$secret = get_user_meta( (int) $user_id, self::META_SECRET, true );

			if ( $this->verify_code( $secret, $code, 1, (int) $user_id ) || $this->verify_recovery_code( (int) $user_id, $code ) ) {
				delete_transient( 'sentinel_2fa_' . $token );
				wp_set_auth_cookie( (int) $user_id, false );
				$user = get_user_by( 'id', (int) $user_id );
				/**
				 * Re-fire wp_login so audit loggers record the completed login,
				 * but temporarily unhook handle_login() first to prevent an
				 * infinite loop: handle_login checks is_enabled_for_user(), which
				 * now returns true, so without this guard it would immediately clear
				 * the auth cookie and redirect back to the 2FA form.
				 */
				remove_action( 'wp_login', array( $this, 'handle_login' ), 10 );
				do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.WP.HookMaturity.PrematureHookUsed
				add_action( 'wp_login', array( $this, 'handle_login' ), 10, 2 );
				wp_safe_redirect( admin_url() );
				exit;
			}

			$error = __( 'Invalid verification code. Please try again.', 'wp-sentinel-security' );
		}

		login_header( __( 'Two-Factor Authentication', 'wp-sentinel-security' ) );
		?>
		<form name="sentinel_2fa_form" id="sentinel_2fa_form" method="post" autocomplete="off">
			<?php wp_nonce_field( 'sentinel_2fa_verify' ); ?>
			<input type="hidden" name="sentinel_token" value="<?php echo esc_attr( $token ); ?>">
			<input type="hidden" name="action" value="sentinel_2fa">

			<?php if ( $error ) : ?>
				<div id="login_error"><strong><?php echo esc_html( $error ); ?></strong></div>
			<?php endif; ?>

			<p>
				<label for="sentinel_2fa_code">
					<?php esc_html_e( 'Authentication Code', 'wp-sentinel-security' ); ?>
				</label>
				<input type="text" name="sentinel_2fa_code" id="sentinel_2fa_code"
					class="input" size="20" autocomplete="one-time-code"
					autofocus="autofocus" inputmode="numeric" placeholder="000000"
					style="letter-spacing:4px;font-size:20px;text-align:center;">
			</p>
			<p style="color:#888;font-size:12px;margin-top:-8px;">
				<?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.', 'wp-sentinel-security' ); ?>
			</p>

			<p class="submit">
				<input type="submit" class="button button-primary button-large"
					value="<?php esc_attr_e( 'Verify & Log In', 'wp-sentinel-security' ); ?>">
			</p>
		</form>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Render a notice informing the user that 2FA is required and must be
	 * configured before they can access the dashboard.
	 */
	public function render_required_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token   = isset( $_REQUEST['sentinel_token'] )
			? sanitize_text_field( wp_unslash( $_REQUEST['sentinel_token'] ) )
			: '';
		$user_id = get_transient( 'sentinel_2fa_setup_required_' . $token );

		if ( ! $user_id ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Do NOT issue a full auth cookie here: that would allow the user to bypass
		// the mandatory 2FA setup by navigating directly to the dashboard.
		// Instead, keep them unauthenticated and redirect to the profile page with
		// a short-lived signed token that the setup wizard can verify.
		$setup_token = wp_hash( $user_id . '|sentinel_2fa_setup|' . time() );
		set_transient( 'sentinel_2fa_setup_token_' . $setup_token, (int) $user_id, 15 * MINUTE_IN_SECONDS );
		delete_transient( 'sentinel_2fa_setup_required_' . $token );

		$profile_url = add_query_arg(
			array(
				'sentinel_2fa_required' => '1',
				'sentinel_setup_token'  => rawurlencode( $setup_token ),
			),
			wp_login_url()
		);

		login_header( __( 'Two-Factor Authentication Required', 'wp-sentinel-security' ) );
		?>
		<div id="login_error" style="border-left-color:#e53935;">
			<strong><?php esc_html_e( 'Action required:', 'wp-sentinel-security' ); ?></strong>
			<?php esc_html_e( 'Two-factor authentication is mandatory for your role. Please set it up now.', 'wp-sentinel-security' ); ?>
		</div>
		<p style="text-align:center;margin-top:16px;">
			<a class="button button-primary button-large"
				href="<?php echo esc_url( $profile_url ); ?>">
				<?php esc_html_e( 'Set Up 2FA Now →', 'wp-sentinel-security' ); ?>
			</a>
		</p>
		<?php
		login_footer();
		exit;
	}

	// ── Profile UI ─────────────────────────────────────────────────────────────

	public function register_user_settings() {
		add_action( 'show_user_profile', array( $this, 'render_user_profile_field' ) );
		add_action( 'edit_user_profile', array( $this, 'render_user_profile_field' ) );
	}

	public function enqueue_profile_assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}

		wp_enqueue_script(
			'sentinel-2fa-profile',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-2fa-profile.js',
			array( 'jquery' ),
			SENTINEL_VERSION,
			true
		);

		wp_localize_script( 'sentinel-2fa-profile', 'sentinel2fa', array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'sentinel_2fa_profile' ),
			'i18n'    => array(
				'setupTitle'     => __( 'Configure your authenticator app', 'wp-sentinel-security' ),
				'scanQr'         => __( 'Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.):',  'wp-sentinel-security' ),
				'manualEntry'    => __( 'Or enter this code manually:', 'wp-sentinel-security' ),
				'enterCode'      => __( 'Then enter the 6-digit code your app shows to confirm setup:', 'wp-sentinel-security' ),
				'codeLabel'      => __( 'Verification code', 'wp-sentinel-security' ),
				'confirm'        => __( 'Confirm setup', 'wp-sentinel-security' ),
				'saving'         => __( 'Verifying…', 'wp-sentinel-security' ),
				'recoveryTitle'  => __( '🎉 2FA is now active!', 'wp-sentinel-security' ),
				'recoveryIntro'  => __( 'Save these recovery codes somewhere safe. Each code can only be used once if you lose access to your authenticator app.', 'wp-sentinel-security' ),
				'done'           => __( 'I have saved my recovery codes', 'wp-sentinel-security' ),
				'invalidCode'    => __( 'Incorrect code — please check your authenticator app and try again.', 'wp-sentinel-security' ),
				'sessionExpired' => __( 'Session expired. Please start setup again.', 'wp-sentinel-security' ),
				'disableConfirm' => __( 'Are you sure you want to disable two-factor authentication? This will make your account less secure.', 'wp-sentinel-security' ),
				'disabled'       => __( '2FA has been disabled.', 'wp-sentinel-security' ),
				'reload'         => __( 'Reloading…', 'wp-sentinel-security' ),
			),
		) );
	}

	/**
	 * Render the 2FA section on the user profile page.
	 *
	 * @param WP_User $user
	 */
	public function render_user_profile_field( $user ) {
		$is_own_profile  = get_current_user_id() === $user->ID;
		$can_manage      = current_user_can( 'manage_options' );
		$has_2fa         = $this->is_enabled_for_user( $user->ID );
		$is_required     = $this->is_required_for_user( $user );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$required_notice = $is_own_profile && isset( $_GET['sentinel_2fa_required'] );
		?>
		<div id="sentinel-2fa-section">
			<h2><?php esc_html_e( 'Two-Factor Authentication', 'wp-sentinel-security' ); ?></h2>

			<?php if ( $required_notice ) : ?>
				<div class="notice notice-error inline" style="margin:0 0 16px;">
					<p>
						<strong><?php esc_html_e( 'Your role requires two-factor authentication.', 'wp-sentinel-security' ); ?></strong>
						<?php esc_html_e( 'Please complete setup below before you can use the dashboard.', 'wp-sentinel-security' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( '2FA Status', 'wp-sentinel-security' ); ?></th>
					<td>
						<?php if ( $has_2fa ) : ?>
							<p>
								<span style="color:#2e7d32;font-weight:600;">
									&#10003; <?php esc_html_e( 'Enabled and active', 'wp-sentinel-security' ); ?>
								</span>
							</p>
							<?php if ( $is_own_profile || $can_manage ) : ?>
								<button type="button" id="sentinel-2fa-disable-btn"
									class="button button-secondary"
									data-user="<?php echo esc_attr( $user->ID ); ?>">
									<?php esc_html_e( 'Disable 2FA', 'wp-sentinel-security' ); ?>
								</button>
							<?php endif; ?>
						<?php else : ?>
							<p>
								<span style="color:#888;">
									<?php esc_html_e( 'Not configured.', 'wp-sentinel-security' ); ?>
								</span>
								<?php if ( $is_required ) : ?>
									<strong style="color:#c62828;">
										<?php esc_html_e( ' Required for your role.', 'wp-sentinel-security' ); ?>
									</strong>
								<?php endif; ?>
							</p>
							<?php if ( $is_own_profile ) : ?>
								<button type="button" id="sentinel-2fa-setup-btn"
									class="button button-primary"
									data-user="<?php echo esc_attr( $user->ID ); ?>">
									<?php esc_html_e( 'Set up 2FA', 'wp-sentinel-security' ); ?>
								</button>
							<?php elseif ( $can_manage ) : ?>
								<em style="color:#888;">
									<?php esc_html_e( 'The user must set up 2FA from their own profile.', 'wp-sentinel-security' ); ?>
								</em>
							<?php endif; ?>
						<?php endif; ?>

						<!-- Setup wizard injected here by sentinel-2fa-profile.js -->
						<div id="sentinel-2fa-wizard" style="display:none;margin-top:24px;max-width:480px;"></div>
					</td>
				</tr>
			</table>
		</div>
		<?php
	}

	// ── AJAX endpoints ─────────────────────────────────────────────────────────

	/**
	 * Generate a new pending secret and return the provisioning URI + QR URL.
	 * The secret is stored in a transient and NOT yet saved to user meta.
	 */
	public function ajax_get_setup() {
		check_ajax_referer( 'sentinel_2fa_profile', 'nonce' );

		$user_id = absint( $_POST['user_id'] ?? 0 );

		if ( ! $user_id || get_current_user_id() !== $user_id ) {
			wp_send_json_error( array( 'message' => __( 'You can only set up 2FA for your own account.', 'wp-sentinel-security' ) ) );
		}

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$user   = get_user_by( 'id', $user_id );
		$secret = $this->generate_secret();

		// Temporarily store the pending secret for up to 15 minutes.
		set_transient( 'sentinel_2fa_pending_' . $user_id, $secret, 15 * MINUTE_IN_SECONDS );

		$uri = $this->get_provisioning_uri( $secret, $user->user_email );

		// Generate QR code locally — no external service, no data leakage.
		if ( ! class_exists( 'Sentinel_QR' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-qr.php';
		}
		$qr_svg = Sentinel_QR::generate( $uri, 200 );

		wp_send_json_success( array(
			'secret'           => $secret,
			'provisioning_uri' => $uri,
			'qr_svg'           => $qr_svg, // Inline SVG — rendered directly in the wizard.
		) );
	}

	/**
	 * Verify the TOTP code against the pending secret.
	 * On success: persist the secret, return recovery codes.
	 */
	public function ajax_confirm_setup() {
		check_ajax_referer( 'sentinel_2fa_profile', 'nonce' );

		$user_id = absint( $_POST['user_id'] ?? 0 );
		$code    = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );

		if ( ! $user_id || get_current_user_id() !== $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$secret = get_transient( 'sentinel_2fa_pending_' . $user_id );
		if ( ! $secret ) {
			wp_send_json_error( array( 'message' => __( 'Setup session expired. Please start again.', 'wp-sentinel-security' ) ) );
		}

		if ( ! $this->verify_code( $secret, $code, 1, $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Incorrect code — please try again.', 'wp-sentinel-security' ) ) );
		}

		delete_transient( 'sentinel_2fa_pending_' . $user_id );
		$recovery_codes = $this->enable_for_user( $user_id, $secret );

		wp_send_json_success( array(
			'message'        => __( '2FA enabled successfully.', 'wp-sentinel-security' ),
			'recovery_codes' => $recovery_codes,
		) );
	}

	/**
	 * Disable 2FA for a user.
	 * Users can disable their own; admins can disable any user's.
	 */
	public function ajax_disable() {
		check_ajax_referer( 'sentinel_2fa_profile', 'nonce' );

		$user_id    = absint( $_POST['user_id'] ?? 0 );
		$current_id = get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'wp-sentinel-security' ) ) );
		}

		$is_own    = $current_id === $user_id;
		$can_admin = current_user_can( 'manage_options' );

		if ( ! $is_own && ! $can_admin ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$this->disable_for_user( $user_id );

		wp_send_json_success( array( 'message' => __( '2FA has been disabled.', 'wp-sentinel-security' ) ) );
	}

	// ── TOTP cryptography ──────────────────────────────────────────────────────

	public function generate_secret( $length = 32 ) { // RFC 6238 recommends 160-bit (32 Base32 chars) minimum
		$secret = '';
		$chars  = self::BASE32_CHARS;
		$max    = strlen( $chars ) - 1;
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= $chars[ random_int( 0, $max ) ];
		}
		return $secret;
	}

	public function get_code( $secret, $time = null ) {
		if ( null === $time ) {
			$time = time();
		}
		$time_step  = (int) floor( $time / self::PERIOD );
		$binary     = $this->base32_decode( $secret );
		$time_bytes = pack( 'N*', 0, $time_step );
		$hash       = hash_hmac( 'sha1', $time_bytes, $binary, true );
		$offset     = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$code = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % pow( 10, self::DIGITS );
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a TOTP code against the secret, with replay protection.
	 *
	 * A code that has been used once is stored in a transient for 2× the TOTP
	 * period (60 s) so it cannot be submitted again in the same time window.
	 *
	 * @param string   $secret  Base32-encoded TOTP secret.
	 * @param string   $code    6-digit code submitted by the user.
	 * @param int      $window  Number of time-steps to accept before/after now (default 1).
	 * @param int|null $user_id WordPress user ID for replay-protection keying (optional).
	 * @return bool
	 */
	public function verify_code( $secret, $code, $window = 1, $user_id = null ) {
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$now = time();

		// ── Replay protection ────────────────────────────────────────────────
		// Build a key that ties the code to the user (or to the secret itself
		// when no user_id is supplied, e.g. during unit tests).
		$replay_key = 'sentinel_2fa_used_' . ( $user_id ? (int) $user_id : md5( $secret ) );
		$last_code  = get_transient( $replay_key );
		if ( false !== $last_code && hash_equals( (string) $last_code, $code ) ) {
			// Same code within the replay-protection window — reject.
			return false;
		}

		// ── TOTP verification ────────────────────────────────────────────────
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( $this->get_code( $secret, $now + $i * self::PERIOD ), $code ) ) {
				// Mark this code as used for 2× the period so it cannot be
				// replayed before the next time-step begins.
				set_transient( $replay_key, $code, self::PERIOD * 2 );
				return true;
			}
		}

		return false;
	}

	public function generate_recovery_codes( $count = 8 ) {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = strtoupper( bin2hex( random_bytes( 4 ) ) );
		}
		return $codes;
	}

	private function verify_recovery_code( $user_id, $code ) {
		$stored = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( empty( $stored ) ) {
			return false;
		}
		$hashes = json_decode( $stored, true );
		if ( ! is_array( $hashes ) ) {
			return false;
		}
		$code_upper = strtoupper( trim( $code ) );
		foreach ( $hashes as $index => $hash ) {
			// password_verify handles bcrypt hashes (stored by enable_for_user).
			// hash_equals wrapper inside password_verify provides timing-safe comparison.
			if ( password_verify( $code_upper, $hash ) ) {
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_RECOVERY, wp_json_encode( array_values( $hashes ) ) );
				return true;
			}
		}
		return false;
	}

	public function get_provisioning_uri( $secret, $user_email ) {
		$issuer = rawurlencode( get_bloginfo( 'name' ) );
		$label  = rawurlencode( $user_email );
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$issuer, $label, $secret, $issuer, self::DIGITS, self::PERIOD
		);
	}

	private function base32_decode( $input ) {
		$input  = strtoupper( $input );
		$buffer = 0;
		$bits   = 0;
		$output = '';
		for ( $i = 0, $len = strlen( $input ); $i < $len; $i++ ) {
			$val = strpos( self::BASE32_CHARS, $input[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits   -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $output;
	}
}
