<?php
if ( ! defined( "ABSPATH" ) ) { exit; }
class Sentinel_Last_Logins {
    const PER_PAGE = 50;
    public static function register_hooks() {
        add_action( "wp_login",        array( __CLASS__, "on_login" ), 10, 2 );
        add_action( "wp_login_failed", array( __CLASS__, "on_login_failed" ), 10, 1 );
        add_action( "wp_logout",       array( __CLASS__, "on_logout" ), 10, 1 );
    }
    public static function on_login( $user_login, $user ) {
        self::insert( array( "user_id" => (int) $user->ID, "user_login" => $user_login, "event" => "login", "ip_address" => self::get_ip(), "user_agent" => self::get_ua() ) );
    }
    public static function on_login_failed( $username ) {
        $user = get_user_by( "login", $username );
        self::insert( array( "user_id" => $user ? (int) $user->ID : 0, "user_login" => sanitize_user( $username ), "event" => "failed", "ip_address" => self::get_ip(), "user_agent" => self::get_ua() ) );
    }
    public static function on_logout( $user_id ) {
        $user = get_userdata( $user_id );
        self::insert( array( "user_id" => (int) $user_id, "user_login" => $user ? $user->user_login : "", "event" => "logout", "ip_address" => self::get_ip(), "user_agent" => self::get_ua() ) );
    }
    public static function get_events( $args = array() ) {
        global $wpdb;
        $table = self::table();
        if ( ! $table ) { return array( "total" => 0, "entries" => array() ); }
        $event    = sanitize_key( $args["event"]    ?? "" );
        $user_id  = absint( $args["user_id"]  ?? 0 );
        $per_page = max( 1, min( 200, (int) ( $args["per_page"] ?? self::PER_PAGE ) ) );
        $page     = max( 1, (int) ( $args["page"] ?? 1 ) );
        $offset   = ( $page - 1 ) * $per_page;
        $where = array( "1=1" ); $params = array();
        if ( $event && in_array( $event, array( "login", "failed", "logout" ), true ) ) { $where[] = "event = %s"; $params[] = $event; }
        if ( $user_id ) { $where[] = "user_id = %d"; $params[] = $user_id; }
        $w = implode( " AND ", $where );
        if ( $params ) {
            $total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$table}` WHERE {$w}", ...$params ) );
            $rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE {$w} ORDER BY created_at DESC LIMIT %d OFFSET %d", ...array_merge( $params, array( $per_page, $offset ) ) ), ARRAY_A );
        } else {
            $total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
            $rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` ORDER BY created_at DESC LIMIT %d OFFSET %d", $per_page, $offset ), ARRAY_A );
        }
        return array( "total" => $total, "entries" => $rows ?: array() );
    }
    public static function get_logged_in_users() {
        global $wpdb;
        $ids = $wpdb->get_col( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'" );
        $result = array();
        foreach ( (array) $ids as $uid ) {
            $manager = WP_Session_Tokens::get_instance( (int) $uid );
            $sessions = $manager->get_all();
            if ( empty( $sessions ) ) { continue; }
            $user = get_userdata( (int) $uid );
            if ( ! $user ) { continue; }
            $result[] = array( "user_id" => (int) $uid, "user_login" => $user->user_login, "display_name" => $user->display_name, "roles" => implode( ", ", $user->roles ), "session_count" => count( $sessions ) );
        }
        return $result;
    }
    public static function get_stats() {
        global $wpdb;
        $table = self::table();
        if ( ! $table ) { return array( "logins" => 0, "failed" => 0, "logouts" => 0 ); }
        $rows = $wpdb->get_results( "SELECT event, COUNT(*) AS cnt FROM `{$table}` WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY event", ARRAY_A );
        $s = array( "logins" => 0, "failed" => 0, "logouts" => 0 );
        foreach ( (array) $rows as $r ) {
            if ( "login"  === $r["event"] ) { $s["logins"]  = (int) $r["cnt"]; }
            if ( "failed" === $r["event"] ) { $s["failed"]  = (int) $r["cnt"]; }
            if ( "logout" === $r["event"] ) { $s["logouts"] = (int) $r["cnt"]; }
        }
        return $s;
    }
    public static function prune( $days = 90 ) {
        global $wpdb; $table = self::table(); if ( ! $table ) { return false; }
        return $wpdb->query( $wpdb->prepare( "DELETE FROM `{$table}` WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)", (int) $days ) );
    }
    public static function create_table() {
        global $wpdb; $table = $wpdb->prefix . "sentinel_logins"; $charset = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS `{$table}` ( id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, user_id BIGINT UNSIGNED NOT NULL DEFAULT 0, user_login VARCHAR(60) NOT NULL DEFAULT \'\', event VARCHAR(10) NOT NULL DEFAULT \'login\', ip_address VARCHAR(45) NOT NULL DEFAULT \'\', user_agent VARCHAR(512) NOT NULL DEFAULT \'\', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY idx_user_id (user_id), KEY idx_event (event), KEY idx_created (created_at) ) {$charset};";
        require_once ABSPATH . "wp-admin/includes/upgrade.php";
        dbDelta( $sql );
    }
    private static function insert( $data ) {
        global $wpdb; $table = self::table(); if ( ! $table ) { return false; }
        return $wpdb->insert( $table, array( "user_id" => (int) ( $data["user_id"] ?? 0 ), "user_login" => sanitize_user( (string) ( $data["user_login"] ?? "" ) ), "event" => in_array( $data["event"] ?? "", array( "login", "failed", "logout" ), true ) ? $data["event"] : "login", "ip_address" => sanitize_text_field( (string) ( $data["ip_address"] ?? "" ) ), "user_agent" => substr( sanitize_text_field( (string) ( $data["user_agent"] ?? "" ) ), 0, 512 ) ), array( "%d", "%s", "%s", "%s", "%s" ) );
    }
    private static function table() {
        global $wpdb; static $exists = null; if ( null === $exists ) { $exists = (bool) $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->prefix . "sentinel_logins" ) ); }
        return $exists ? $wpdb->prefix . "sentinel_logins" : null;
    }
    private static function get_ip() {
        $s = get_option( "sentinel_settings", array() ); $t = (array) ( $s["trusted_proxy_ips"] ?? array() );
        $r = sanitize_text_field( $_SERVER["REMOTE_ADDR"] ?? "" ); $in_t = false;
        foreach ( $t as $c ) { if ( self::ip_in_cidr( $r, $c ) ) { $in_t = true; break; } }
        if ( $in_t ) { foreach ( array( "HTTP_CF_CONNECTING_IP", "HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP" ) as $h ) { if ( ! empty( $_SERVER[$h] ) ) { $ip = trim( explode( ",", $_SERVER[$h] )[0] ); if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) { return $ip; } } } }
        return filter_var( $r, FILTER_VALIDATE_IP ) ? $r : "";
    }
    private static function get_ua() { return isset( $_SERVER["HTTP_USER_AGENT"] ) ? substr( (string) $_SERVER["HTTP_USER_AGENT"], 0, 512 ) : ""; }
    private static function ip_in_cidr( $ip, $cidr ) {
        if ( false === strpos( $cidr, "/" ) ) { return $ip === $cidr; }
        list( $range, $prefix ) = explode( "/", $cidr, 2 ); $prefix = (int) $prefix;
        if ( filter_var( $range, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) { $il = ip2long( $ip ); $rl = ip2long( $range ); if ( false === $il || false === $rl ) { return false; } $mask = $prefix > 0 ? ( ~0 << ( 32 - $prefix ) ) : 0; return ( $il & $mask ) === ( $rl & $mask ); }
        return false;
    }
}
