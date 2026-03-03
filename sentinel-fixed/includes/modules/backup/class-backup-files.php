<?php
/**
 * File-system backup handler.
 *
 * Creates and extracts ZIP archives of the WordPress content directory
 * (or any specified source directory) while tracking progress via transients.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Backup_Files
 *
 * Uses PHP's ZipArchive extension to create and extract backup archives
 * of WordPress file-system content, with sensible exclusions and a
 * per-file size cap to avoid memory exhaustion on large sites.
 */
class Backup_Files {

	/**
	 * Maximum individual file size to include in the archive (50 MB).
	 *
	 * @var int
	 */
	const MAX_FILE_SIZE = 52428800;

	/**
	 * Directory/path fragment patterns to exclude from the archive.
	 *
	 * Each entry is matched against the file's real path using strpos().
	 *
	 * @var string[]
	 */
	private static $exclude_patterns = array(
		'sentinel-backups',
		'/cache/',
		'\\cache\\',
		'node_modules',
		'.git',
	);

	// -----------------------------------------------------------------------
	// Public API
	// -----------------------------------------------------------------------

	/**
	 * Create a ZIP archive of a directory.
	 *
	 * Progress (0-100) is stored in a transient named
	 * `sentinel_backup_progress` so that the admin UI can poll it.
	 *
	 * @param string      $destination_path Absolute path for the output .zip file.
	 * @param string|null $source_dir       Directory to archive. Defaults to WP_CONTENT_DIR.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function create_archive( $destination_path, $source_dir = null ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error(
				'backup_zip_unavailable',
				__( 'The ZipArchive PHP extension is not available on this server.', 'wp-sentinel-security' )
			);
		}

		if ( null === $source_dir ) {
			$source_dir = WP_CONTENT_DIR;
		}

		$source_dir = rtrim( $source_dir, '/\\' );

		if ( ! is_dir( $source_dir ) ) {
			return new WP_Error(
				'backup_source_missing',
				sprintf(
					/* translators: %s: directory path */
					__( 'Source directory does not exist: %s', 'wp-sentinel-security' ),
					$source_dir
				)
			);
		}

		$zip = new ZipArchive();
		$opened = $zip->open( $destination_path, ZipArchive::CREATE | ZipArchive::OVERWRITE );
		if ( true !== $opened ) {
			return new WP_Error(
				'backup_zip_open_failed',
				sprintf(
					/* translators: 1: file path, 2: error code */
					__( 'Cannot create ZIP archive at %1$s (error code: %2$d).', 'wp-sentinel-security' ),
					$destination_path,
					$opened
				)
			);
		}

		// Collect all files first so we can track accurate progress.
		$files = $this->collect_files( $source_dir );

		$total   = count( $files );
		$current = 0;

		set_transient( 'sentinel_backup_progress', 0, HOUR_IN_SECONDS );

		foreach ( $files as $file_path ) {
			$current++;

			$real_path = realpath( $file_path );
			if ( false === $real_path ) {
				continue;
			}

			// Build relative path for the archive entry.
			$relative = ltrim( str_replace( $source_dir, '', $real_path ), '/\\' );

			// Add to ZIP.
			$zip->addFile( $real_path, $relative ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_exists

			// Update progress transient roughly every 50 files.
			if ( 0 === $current % 50 || $current === $total ) {
				$percent = $total > 0 ? (int) round( ( $current / $total ) * 100 ) : 100;
				set_transient( 'sentinel_backup_progress', $percent, HOUR_IN_SECONDS );
			}
		}

		$closed = $zip->close();
		if ( ! $closed ) {
			return new WP_Error(
				'backup_zip_close_failed',
				__( 'Failed to finalise the ZIP archive.', 'wp-sentinel-security' )
			);
		}

		set_transient( 'sentinel_backup_progress', 100, HOUR_IN_SECONDS );

		return true;
	}

	/**
	 * Extract a ZIP archive to a destination directory.
	 *
	 * Each entry path is validated against the destination directory to prevent
	 * Zip Slip attacks (crafted entries like "../../wp-config.php" that would
	 * resolve outside the intended extraction directory).
	 *
	 * @param string      $archive_path Absolute path to the .zip file.
	 * @param string|null $destination  Target directory. Defaults to WP_CONTENT_DIR.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function extract_archive( $archive_path, $destination = null ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error(
				'backup_zip_unavailable',
				__( 'The ZipArchive PHP extension is not available on this server.', 'wp-sentinel-security' )
			);
		}

		if ( null === $destination ) {
			$destination = WP_CONTENT_DIR;
		}

		// Normalise destination to a real, canonical path.
		$destination      = rtrim( $destination, '/\\' );
		$real_destination = realpath( $destination );
		if ( false === $real_destination ) {
			wp_mkdir_p( $destination );
			$real_destination = realpath( $destination );
		}
		if ( false === $real_destination ) {
			return new WP_Error(
				'backup_destination_invalid',
				sprintf(
					/* translators: %s: destination path */
					__( 'Extraction destination is not accessible: %s', 'wp-sentinel-security' ),
					$destination
				)
			);
		}

		// Trailing separator prevents prefix-check bypass
		// (e.g. "/var/www/html-evil" falsely matching "/var/www/html").
		$safe_prefix = $real_destination . DIRECTORY_SEPARATOR;

		if ( ! file_exists( $archive_path ) ) {
			return new WP_Error(
				'backup_archive_missing',
				sprintf(
					/* translators: %s: archive path */
					__( 'Archive file not found: %s', 'wp-sentinel-security' ),
					$archive_path
				)
			);
		}

		$zip    = new ZipArchive();
		$opened = $zip->open( $archive_path );
		if ( true !== $opened ) {
			return new WP_Error(
				'backup_zip_open_failed',
				sprintf(
					/* translators: 1: archive path, 2: error code */
					__( 'Cannot open ZIP archive %1$s (error code: %2$d).', 'wp-sentinel-security' ),
					$archive_path,
					$opened
				)
			);
		}

		$skipped = array();

		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$entry_name = $zip->getNameIndex( $i );
			if ( false === $entry_name ) {
				continue;
			}

			// Strip null bytes defensively before path construction.
			$entry_name  = str_replace( "\0", '', $entry_name );
			$target_path = $real_destination . DIRECTORY_SEPARATOR . $entry_name;

			// Resolve the parent to check for path traversal.
			$parent_real = realpath( dirname( $target_path ) );
			if ( false !== $parent_real ) {
				$resolved_target = $parent_real . DIRECTORY_SEPARATOR . basename( $target_path );
			} else {
				// Parent doesn't exist yet: normalise /../ sequences manually.
				$norm = $target_path;
				do {
					$prev = $norm;
					$norm = preg_replace( '#[/\\\\][^/\\\\]+[/\\\\]\.\.[/\\\\]#', DIRECTORY_SEPARATOR, $norm );
					$norm = preg_replace( '#[/\\\\]\.[/\\\\]#', DIRECTORY_SEPARATOR, $norm );
				} while ( $norm !== $prev );
				$resolved_target = $norm;
			}

			// Security check: resolved target must reside inside $safe_prefix.
			if ( 0 !== strpos( $resolved_target, $safe_prefix ) ) {
				$skipped[] = $entry_name;
				continue;
			}

			// Directories: create and move on.
			if ( '/' === substr( $entry_name, -1 ) ) {
				wp_mkdir_p( $target_path );
				continue;
			}

			// Files: ensure parent exists, then write content.
			wp_mkdir_p( dirname( $target_path ) );
			$content = $zip->getFromIndex( $i ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( false !== $content ) {
				file_put_contents( $target_path, $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		$zip->close();

		if ( ! empty( $skipped ) ) {
			return new WP_Error(
				'backup_extract_unsafe_entries',
				sprintf(
					/* translators: %d: number of skipped entries */
					__( 'Extraction completed, but %d unsafe ZIP entries were skipped.', 'wp-sentinel-security' ),
					count( $skipped )
				)
			);
		}

		return true;
	}

	/**
	 * Recursively calculate the total size of a directory in bytes.
	 *
	 * @param string $dir Absolute path to the directory.
	 * @return int Total size in bytes (0 if the directory is unreadable).
	 */
	public function get_directory_size( $dir ) {
		$size = 0;

		if ( ! is_dir( $dir ) ) {
			return $size;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$size += $file->getSize();
				}
			}
		} catch ( Exception $e ) {
			// Return whatever we have accumulated so far.
			return $size;
		}

		return $size;
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Collect all eligible file paths from a source directory.
	 *
	 * Applies exclusion rules and the per-file size cap before returning
	 * the list so that the caller can track accurate progress.
	 *
	 * @param string $source_dir Root directory to scan.
	 * @return string[] Array of absolute file paths to include.
	 */
	private function collect_files( $source_dir ) {
		$files = array();

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $source_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				$real_path = $file->getRealPath();

				// Check exclusion patterns.
				if ( $this->is_excluded( $real_path ) ) {
					continue;
				}

				// Skip files exceeding the size cap.
				if ( $file->getSize() > self::MAX_FILE_SIZE ) {
					continue;
				}

				$files[] = $real_path;
			}
		} catch ( Exception $e ) {
			// Return whatever we collected before the error.
			return $files;
		}

		return $files;
	}

	/**
	 * Determine whether a file path should be excluded from the archive.
	 *
	 * @param string $path Absolute file path.
	 * @return bool True if the file should be excluded.
	 */
	private function is_excluded( $path ) {
		foreach ( self::$exclude_patterns as $pattern ) {
			if ( false !== strpos( $path, $pattern ) ) {
				return true;
			}
		}
		return false;
	}
}
