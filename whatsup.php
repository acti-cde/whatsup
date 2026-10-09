<?php
/*
Plugin Name: WhatsUp MU
Description: Expose minimal site info (WP, PHP, plugins) at /whatsup and trigger updates, for allowed IPs only
Version: 1.1.0
*/
/**
 * WhatsUp MU - expose minimal site info at /whatsup and trigger updates
 *
 * Usage:
 * 1) Place this file in wp-content/mu-plugins/ (already in web/app/mu-plugins/ for Bedrock projects)
 * 2) Optional constants in wp-config.php / config/application.php:
 *      define('WHATSUP_MU_ALLOWED_IPS', '1.2.3.4, 5.6.7.8');   // replaces the default allowed IPs
 *      define('WHATSUP_MU_TRUSTED_PROXIES', '10.0.0.1');        // only then X-Forwarded-For is trusted
 *
 * Endpoint:
 *  - GET  https://example.tld/whatsup  (or /?whatsup=1)  => site info JSON
 *  - POST https://example.tld/whatsup  with update=<comma-separated targets> => runs updates
 *      targets: "self" (this mu-plugin, from GitHub main), "core" (WordPress minor only),
 *               or a plugin file as listed in the info JSON (e.g. "akismet/akismet.php")
 *      e.g. curl -X POST -d 'update=self,core,akismet/akismet.php' https://example.tld/whatsup
 *
 * Security notes:
 *  - Only allowed IPs can access the endpoint, any other IP gets a 404 with no body.
 *  - Updates bypass DISALLOW_FILE_MODS: on Bedrock sites they are reverted by the next composer deploy.
 *
 * Output (JSON):
 * {
 *   "timestamp": "2026-03-20T12:34:56Z",
 *   "whatsup": {"version": "1.1.0"},
 *   "wordpress": {"version": "6.x"},
 *   "php": {"version": "8.x"},
 *   "plugins": [ {"file":"akismet/akismet.php","name":"Akismet","version":"4.1","update":"4.2","status":"active"}, ... ]
 * }
 */

if ( ! defined( 'ABSPATH' ) ) {
    return;
}

define( 'WHATSUP_MU_VERSION', '1.1.0' );
define( 'WHATSUP_MU_SOURCE_URL', 'https://raw.githubusercontent.com/acti-cde/whatsup/main/whatsup.php' );

add_action( 'parse_request', 'whatsup_mu_handle_request', 0 );

function whatsup_mu_ip_list( $constant, $default = '' ) {
	$list = defined( $constant ) && constant( $constant ) ? constant( $constant ) : $default;

	return array_filter( preg_split( '/\s*,\s*/', trim( $list ) ) );
}

function whatsup_mu_client_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';

	// X-Forwarded-For is client-controlled: only trust it when the request comes from a known proxy
	if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && in_array( $ip, whatsup_mu_ip_list( 'WHATSUP_MU_TRUSTED_PROXIES' ), true ) ) {
		$forwarded = explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		$ip = trim( $forwarded[0] );
	}

	return $ip;
}

function whatsup_mu_ip_allowed() {
	$allowed = whatsup_mu_ip_list( 'WHATSUP_MU_ALLOWED_IPS', '89.227.241.142, 78.201.112.201, 31.193.54.209' );

	return in_array( whatsup_mu_client_ip(), $allowed, true );
}

function whatsup_mu_handle_request( $wp ) {
	$request_uri_path = '';
	if ( isset( $_SERVER['REQUEST_URI'] ) ) {
		$request_uri_path = parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH );
		$request_uri_path = trim( $request_uri_path, '/' );
	}

	$is_path_endpoint = ( strtolower( $request_uri_path ) === 'whatsup' );
	$is_query_endpoint = ( isset( $_GET['whatsup'] ) && (string) $_GET['whatsup'] );

	if ( ! $is_path_endpoint && ! $is_query_endpoint ) {
		return;
	}

	if ( ! whatsup_mu_ip_allowed() ) {
		status_header( 404 );
		nocache_headers();
		exit;
	}

	// --- CORS handling ---
	// Par défaut on autorise toutes les origines pour cet endpoint puisque l'accès est protégé
	// par IP. Si vous préférez restreindre, vous pouvez toujours
	// définir WHATSUP_MU_ALLOW_ORIGINS ou WHATSUP_MU_ALLOW_ORIGIN dans wp-config.php.
	$cors_allow_origin = '*';
	$origin = '';
	if ( ! empty( $_SERVER['HTTP_ORIGIN'] ) ) {
		$origin = trim( wp_unslash( (string) $_SERVER['HTTP_ORIGIN'] ) );
	}

	// If explicit constants exist, they override default '*' to allow finer control
	if ( defined( 'WHATSUP_MU_ALLOW_ORIGINS' ) && WHATSUP_MU_ALLOW_ORIGINS ) {
		$cors_allow_origin = false;
		$allowed_list = preg_split( '/\s*,\s*/', WHATSUP_MU_ALLOW_ORIGINS );
		foreach ( $allowed_list as $allowed ) {
			if ( $allowed === '*' ) {
				$cors_allow_origin = '*';
				break;
			}
			if ( strcasecmp( $allowed, $origin ) === 0 ) {
				$cors_allow_origin = $origin;
				break;
			}
		}
	} elseif ( defined( 'WHATSUP_MU_ALLOW_ORIGIN' ) && WHATSUP_MU_ALLOW_ORIGIN ) {
		// If single origin constant is provided, use it; otherwise keep default '*'
		if ( WHATSUP_MU_ALLOW_ORIGIN === '*' ) {
			$cors_allow_origin = '*';
		} elseif ( strcasecmp( WHATSUP_MU_ALLOW_ORIGIN, $origin ) === 0 ) {
			$cors_allow_origin = $origin;
		}
	}

	$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';

	// Handle preflight OPTIONS request: reply with allowed methods/headers if origin allowed
	if ( $method === 'OPTIONS' ) {
		if ( $cors_allow_origin ) {
			header( 'Access-Control-Allow-Origin: ' . $cors_allow_origin );
			header( 'Access-Control-Allow-Methods: GET, POST, OPTIONS' );
			header( 'Access-Control-Allow-Headers: Content-Type, X-Requested-With, Authorization' );
			header( 'Vary: Origin' );
		}
		status_header( 204 );
		nocache_headers();
		exit;
	}

	$cache_key = 'whatsup_mu_cache_' . get_current_blog_id();

	if ( $method === 'POST' && ! empty( $_POST['update'] ) ) {
		$targets = array_filter( preg_split( '/\s*,\s*/', trim( wp_unslash( (string) $_POST['update'] ) ) ) );
		$results = whatsup_mu_run_updates( $targets );
		delete_transient( $cache_key );
		whatsup_mu_send_json( array( 'timestamp' => gmdate( 'c' ), 'updates' => $results ), $cors_allow_origin );
	}

	$cached = get_transient( $cache_key );
	if ( ! $cached || ! is_string( $cached ) ) {
		$cached = whatsup_mu_encode( whatsup_mu_get_info() );
		set_transient( $cache_key, $cached, 300 );
	}

	whatsup_mu_send_json( $cached, $cors_allow_origin );
}

function whatsup_mu_get_info() {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	$updates = get_site_transient( 'update_plugins' );
	$active_plugins = (array) get_option( 'active_plugins', array() );
	$network_plugins = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();

	$plugins = array();
	foreach ( get_plugins() as $file => $meta ) {
		$status = 'inactive';
		if ( in_array( $file, $active_plugins, true ) ) {
			$status = 'active';
		}
		if ( in_array( $file, $network_plugins, true ) ) {
			$status = 'network-activated';
		}

		$plugins[] = array(
			'file'    => $file,
			'name'    => isset( $meta['Name'] ) ? $meta['Name'] : $file,
			'version' => isset( $meta['Version'] ) ? $meta['Version'] : '',
			'update'  => isset( $updates->response[ $file ]->new_version ) ? $updates->response[ $file ]->new_version : null,
			'status'  => $status,
		);
	}

	return array(
		'timestamp' => gmdate( 'c' ),
		'whatsup'   => array( 'version' => WHATSUP_MU_VERSION ),
		'wordpress' => array( 'version' => get_bloginfo( 'version' ) ),
		'php'       => array( 'version' => PHP_VERSION ),
		'plugins'   => $plugins,
	);
}

function whatsup_mu_run_updates( $targets ) {
	ignore_user_abort( true );
	set_time_limit( 0 );

	require_once ABSPATH . 'wp-admin/includes/admin.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

	$results = array();
	$plugins = array();
	foreach ( $targets as $target ) {
		if ( $target === 'self' ) {
			$results['self'] = whatsup_mu_try( 'whatsup_mu_update_self' );
		} elseif ( $target === 'core' ) {
			$results['core'] = whatsup_mu_try( 'whatsup_mu_update_core' );
		} else {
			$plugins[] = $target;
		}
	}

	if ( $plugins ) {
		$results['plugins'] = whatsup_mu_try( 'whatsup_mu_update_plugins', $plugins );
	}

	return $results;
}

function whatsup_mu_try( $callback, $arg = null ) {
	try {
		$result = call_user_func( $callback, $arg );
	} catch ( Throwable $e ) {
		$result = new WP_Error( 'exception', $e->getMessage() );
	}

	return is_wp_error( $result ) ? array( 'success' => false, 'error' => $result->get_error_message() ) : $result;
}

function whatsup_mu_update_self() {
	$response = wp_remote_get( WHATSUP_MU_SOURCE_URL, array( 'timeout' => 30 ) );
	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$code = wp_remote_retrieve_body( $response );
	if ( wp_remote_retrieve_response_code( $response ) !== 200 || strpos( $code, 'Plugin Name: WhatsUp MU' ) === false ) {
		return new WP_Error( 'download', 'Invalid download from ' . WHATSUP_MU_SOURCE_URL );
	}
	if ( ! preg_match( '/^Version:\s*(\S+)/m', $code, $version ) ) {
		return new WP_Error( 'version', 'No version header in downloaded file' );
	}
	if ( version_compare( $version[1], WHATSUP_MU_VERSION, '<=' ) ) {
		return array( 'success' => true, 'from' => WHATSUP_MU_VERSION, 'to' => WHATSUP_MU_VERSION, 'message' => 'Already up to date' );
	}

	// A syntax error in a mu-plugin takes the whole site down: refuse anything that doesn't parse
	try {
		token_get_all( $code, TOKEN_PARSE );
	} catch ( ParseError $e ) {
		return new WP_Error( 'parse', 'Downloaded file does not parse: ' . $e->getMessage() );
	}

	$tmp = __FILE__ . '.tmp';
	if ( file_put_contents( $tmp, $code ) === false || ! rename( $tmp, __FILE__ ) ) {
		@unlink( $tmp );

		return new WP_Error( 'write', 'Cannot write ' . __FILE__ );
	}
	if ( function_exists( 'opcache_invalidate' ) ) {
		opcache_invalidate( __FILE__, true );
	}

	return array( 'success' => true, 'from' => WHATSUP_MU_VERSION, 'to' => $version[1] );
}

function whatsup_mu_update_core() {
	$current = get_bloginfo( 'version' );
	$branch = implode( '.', array_slice( explode( '.', $current ), 0, 2 ) ) . '.';

	wp_version_check( array(), true );

	$offer = null;
	foreach ( (array) get_core_updates( array( 'dismissed' => true ) ) as $candidate ) {
		if ( strpos( $candidate->current, $branch ) === 0 && version_compare( $candidate->current, $offer ? $offer->current : $current, '>' ) ) {
			$offer = $candidate;
		}
	}
	if ( ! $offer ) {
		return array( 'success' => true, 'from' => $current, 'to' => $current, 'message' => 'No minor update available' );
	}

	$upgrader = new Core_Upgrader( new Automatic_Upgrader_Skin() );
	$result = $upgrader->upgrade( $offer );
	if ( is_wp_error( $result ) ) {
		return $result;
	}
	if ( ! $result ) {
		return new WP_Error( 'core', implode( ' ', $upgrader->skin->get_upgrade_messages() ) );
	}

	return array( 'success' => true, 'from' => $current, 'to' => $result );
}

function whatsup_mu_update_plugins( $files ) {
	wp_update_plugins();

	$before = get_plugins();
	$known = array_intersect( $files, array_keys( $before ) );

	// bulk_upgrade keeps plugins active (single upgrade() deactivates them and relies on the admin UI to reactivate)
	$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
	$results = $known ? $upgrader->bulk_upgrade( $known ) : array();
	if ( $results === false ) {
		return new WP_Error( 'filesystem', 'Cannot access filesystem' );
	}

	wp_clean_plugins_cache();
	$after = get_plugins();

	$out = array();
	foreach ( $files as $file ) {
		if ( ! isset( $before[ $file ] ) ) {
			$out[ $file ] = array( 'success' => false, 'error' => 'Unknown plugin' );
		} elseif ( is_wp_error( $results[ $file ] ) ) {
			$out[ $file ] = array( 'success' => false, 'error' => $results[ $file ]->get_error_message() );
		} else {
			$out[ $file ] = array(
				'success' => $results[ $file ] !== false,
				'from'    => $before[ $file ]['Version'],
				'to'      => isset( $after[ $file ] ) ? $after[ $file ]['Version'] : null,
			);
		}
	}

	return $out;
}

function whatsup_mu_encode( $data ) {
	$json_flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		$json_flags |= JSON_PRETTY_PRINT;
	}

	$json = json_encode( $data, $json_flags );

	return $json === false ? json_encode( array( 'timestamp' => gmdate( 'c' ) ) ) : $json;
}

function whatsup_mu_send_json( $data, $cors_allow_origin ) {
	if ( ! empty( $cors_allow_origin ) ) {
		header( 'Access-Control-Allow-Origin: ' . $cors_allow_origin );
		header( 'Vary: Origin' );
	}
	header( 'Content-Type: application/json; charset=utf-8' );
	status_header( 200 );
	nocache_headers();
	echo is_string( $data ) ? $data : whatsup_mu_encode( $data );
	exit;
}
