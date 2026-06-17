<?php
/**
 * WhatsUp MU - expose minimal site info at /whatsup?token=TOKEN
 *
 * Usage:
 * 1) Place this file in wp-content/mu-plugins/ (already in web/app/mu-plugins/ for Bedrock projects)
 * 2) Define a token in wp-config.php to harden access (recommended):
 *      define('WHATSUP_MU_TOKEN', 'your-very-long-secret-token');
 *    If you don't define it, a default token is used: 'bnFiYCm$14Dg' (NOT recommended for production).
 *    For now, we only support default token so don't define it
 *
 * Endpoint (examples):
 *  - https://example.tld/whatsup?token=bnFiYCm$14Dg
 *  - https://example.tld/?whatsup=1&token=...
 *
 * Security notes:
 *  - Token comparison uses hash_equals for timing-safe comparison.
 *  - Invalid or absent token yields a 404 response with no JSON body to avoid information leakage.
 *  - Minimal rate-limiter per IP is implemented via transients.
 *
 * Output (JSON):
 * {
 *   "timestamp": "2026-03-20T12:34:56Z",
 *   "wordpress": {"version": "6.x"},
 *   "php": {"version": "8.x"},
 *   "plugins": [ {"name":"Akismet","version":"4.1","status":"active"}, ... ]
 * }
 */

if ( ! defined( 'ABSPATH' ) ) {
    return;
}

add_action( 'parse_request', 'whatsup_mu_handle_request', 0 );

function whatsup_mu_get_expected_token() {
	if ( defined( 'WHATSUP_MU_TOKEN' ) && WHATSUP_MU_TOKEN ) {
		return WHATSUP_MU_TOKEN;
	}

	return 'bnFiYCm$14Dg';
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

	// --- CORS handling ---
	// Par défaut on autorise toutes les origines pour cet endpoint puisque l'accès est protégé
	// par token (fourni dans la query string). Si vous préférez restreindre, vous pouvez toujours
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

	// Handle preflight OPTIONS request: reply with allowed methods/headers if origin allowed
	if ( isset( $_SERVER['REQUEST_METHOD'] ) && strtoupper( $_SERVER['REQUEST_METHOD'] ) === 'OPTIONS' ) {
		if ( $cors_allow_origin ) {
			header( 'Access-Control-Allow-Origin: ' . ( $cors_allow_origin === '*' ? '*' : $cors_allow_origin ) );
			header( 'Access-Control-Allow-Methods: GET, OPTIONS' );
			header( 'Access-Control-Allow-Headers: Content-Type, X-Requested-With, Token, token, Authorization' );
			header( 'Vary: Origin' );
		}
		status_header( 204 );
		nocache_headers();
		exit;
	}

	$ip = '';
	if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$forwarded = explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		$ip = trim( $forwarded[0] );
	}
	if ( empty( $ip ) && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	if ( filter_var( $ip, FILTER_VALIDATE_IP ) === false ) {
		$ip = 'unknown';
	}

	$rate_key = 'whatsup_mu_rate_' . md5( $ip );
	$rate = (int) get_transient( $rate_key );
	$rate++;
	set_transient( $rate_key, $rate, 60 );
	if ( $rate > 60 ) {
		status_header( 429 );
		nocache_headers();
		exit;
	}

	$provided = '';
	if ( isset( $_GET['token'] ) ) {
		$provided = trim( wp_unslash( (string) $_GET['token'] ) );
	}

	$expected = whatsup_mu_get_expected_token();

	$token_ok = false;
	if ( is_string( $expected ) && $expected !== '' && is_string( $provided ) && $provided !== '' ) {
		if ( function_exists( 'hash_equals' ) ) {
			$token_ok = hash_equals( (string) $expected, (string) $provided );
		} else {
			$token_ok = ( (string) $expected === (string) $provided );
		}
	}

	if ( ! $token_ok ) {
		status_header( 404 );
		nocache_headers();
		exit;
	}

	$cache_key = 'whatsup_mu_cache_' . get_current_blog_id();
	$cached = get_transient( $cache_key );
	if ( $cached && is_string( $cached ) ) {
		if ( ! empty( $cors_allow_origin ) ) {
			header( 'Access-Control-Allow-Origin: ' . ( $cors_allow_origin === '*' ? '*' : $cors_allow_origin ) );
			header( 'Vary: Origin' );
		}
		header( 'Content-Type: application/json; charset=utf-8' );
		status_header( 200 );
		nocache_headers();
		echo $cached;
		exit;
	}

	$wp_version = '';
	if ( function_exists( 'get_bloginfo' ) ) {
		$wp_version = get_bloginfo( 'version' );
	} elseif ( isset( $GLOBALS['wp_version'] ) ) {
		$wp_version = $GLOBALS['wp_version'];
	}

	$php_version = PHP_VERSION;

	if ( ! function_exists( 'get_plugins' ) ) {
		if ( file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
	}

	$plugins = array();
	if ( function_exists( 'get_plugins' ) ) {
		$all_plugins = get_plugins(); // keyed by plugin file path
		$active_plugins = (array) get_option( 'active_plugins', array() );
		$network_plugins = array();
		if ( is_multisite() ) {
			$network_active = (array) get_site_option( 'active_sitewide_plugins', array() );
			$network_plugins = array_keys( $network_active );
		}

		foreach ( $all_plugins as $file => $meta ) {
			$status = 'inactive';
			if ( in_array( $file, $active_plugins, true ) ) {
				$status = 'active';
			}
			if ( in_array( $file, $network_plugins, true ) ) {
				$status = 'network-activated';
			}

			$plugins[] = array(
				'name'    => isset( $meta['Name'] ) ? $meta['Name'] : $file,
				'version' => isset( $meta['Version'] ) ? $meta['Version'] : '',
				'status'  => $status,
			);
		}
	}

	$data = array(
		'timestamp' => gmdate( 'c' ),
		'wordpress' => array( 'version' => $wp_version ),
		'php'       => array( 'version' => $php_version ),
		'plugins'   => $plugins,
	);

	$json_flags = 0;
	if ( defined( 'JSON_UNESCAPED_SLASHES' ) ) {
		$json_flags |= JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
	}
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		$json_flags |= JSON_PRETTY_PRINT;
	}

	$json = json_encode( $data, $json_flags );
	if ( $json === false ) {
		$json = json_encode( array( 'timestamp' => gmdate( 'c' ) ) );
	}

	set_transient( $cache_key, $json, 300 );

	if ( ! empty( $cors_allow_origin ) ) {
		header( 'Access-Control-Allow-Origin: ' . ( $cors_allow_origin === '*' ? '*' : $cors_allow_origin ) );
		header( 'Vary: Origin' );
	}
	header( 'Content-Type: application/json; charset=utf-8' );
	status_header( 200 );
	nocache_headers();
	echo $json;
	exit;
}
