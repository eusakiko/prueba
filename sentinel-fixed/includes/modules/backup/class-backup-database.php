<?php
/**
 * Database backup handler.
 *
 * Exports and imports WordPress database tables as SQL dump files.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Backup_Database
 *
 * Handles MySQL database export (dump) and import (restore) operations
 * for all tables belonging to the current WordPress installation.
 */
class Backup_Database {

	/**
	 * Number of rows to export per INSERT batch.
	 *
	 * @var int
	 */
	const BATCH_SIZE = 500;

	/**
	 * Export all WordPress tables to a SQL dump file.
	 *
	 * Writes a complete, self-contained SQL file containing:
	 * - A header comment block with metadata.
	 * - DROP TABLE IF EXISTS + CREATE TABLE for every table.
	 * - Batched INSERT statements for all rows.
	 *
	 * @param string $file_path Absolute path to the destination .sql file.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function export( $file_path ) {
		global $wpdb;

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$handle = fopen( $file_path, 'wb' );
		if ( false === $handle ) {
			return new WP_Error(
				'backup_export_open_failed',
				sprintf(
					/* translators: %s: file path */
					__( 'Cannot open file for writing: %s', 'wp-sentinel-security' ),
					$file_path
				)
			);
		}

		// Write SQL header.
		$this->write_header( $handle );

		// Retrieve all tables that belong to this WordPress installation.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$tables = $wpdb->get_col(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$wpdb->esc_like( $wpdb->prefix ) . '%'
			)
		);

		if ( empty( $tables ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $handle );
			return new WP_Error(
				'backup_export_no_tables',
				__( 'No WordPress tables found to export.', 'wp-sentinel-security' )
			);
		}

		foreach ( $tables as $table ) {
			$result = $this->export_table( $handle, $table );
			if ( is_wp_error( $result ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
				fclose( $handle );
				return $result;
			}
		}

		// Footer.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, "\n-- Export completed at " . gmdate( 'Y-m-d H:i:s' ) . " UTC\n" );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $handle );

		return true;
	}

	/**
	 * Import a SQL dump file into the database.
	 *
	 * Reads the file line by line, accumulates full SQL statements
	 * (which may span multiple lines), and executes each via $wpdb->query().
	 *
	 * @param string $file_path Absolute path to the .sql file to import.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function import( $file_path ) {
		global $wpdb;

		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return new WP_Error(
				'backup_import_file_missing',
				sprintf(
					/* translators: %s: file path */
					__( 'SQL file not found or not readable: %s', 'wp-sentinel-security' ),
					$file_path
				)
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$handle = fopen( $file_path, 'rb' );
		if ( false === $handle ) {
			return new WP_Error(
				'backup_import_open_failed',
				__( 'Cannot open SQL file for reading.', 'wp-sentinel-security' )
			);
		}

		$statement = '';
		$delimiter = ';';
		$errors    = array();

		// Execute SET FOREIGN_KEY_CHECKS=0 before the import loop.  If this
		// foundational statement fails, all subsequent INSERTs will fail on
		// constraint violations so we abort immediately to avoid leaving the
		// database in a partially-imported, inconsistent state.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( false === $wpdb->query( 'SET FOREIGN_KEY_CHECKS=0' ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $handle );
			return new WP_Error(
				'backup_import_init_failed',
				sprintf(
					/* translators: %s: database error */
					__( 'Import aborted: SET FOREIGN_KEY_CHECKS failed: %s', 'wp-sentinel-security' ),
					$wpdb->last_error
				)
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_feof
		while ( ! feof( $handle ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fgets
			$line = fgets( $handle );

			if ( false === $line ) {
				break;
			}

			$trimmed = trim( $line );

			// Skip empty lines and comment lines.
			if ( '' === $trimmed || '--' === substr( $trimmed, 0, 2 ) || '#' === $trimmed[0] ) {
				continue;
			}

			$statement .= $line;

			// A statement ends when the trimmed line ends with the delimiter.
			if ( $delimiter === substr( $trimmed, -strlen( $delimiter ) ) ) {
				$sql = trim( $statement );
				if ( '' !== $sql ) {
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
					$result = $wpdb->query( $sql );
					if ( false === $result ) {
						$errors[] = $wpdb->last_error;
					}
				}
				$statement = '';
			}
		}

		// Restore FK checks regardless of outcome.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'SET FOREIGN_KEY_CHECKS=1' );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $handle );

		if ( ! empty( $errors ) ) {
			return new WP_Error(
				'backup_import_query_failed',
				sprintf(
					/* translators: %s: list of database errors */
					__( 'Import completed with errors: %s', 'wp-sentinel-security' ),
					implode( ' | ', $errors )
				)
			);
		}

		return true;
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Write the SQL file header comment block.
	 *
	 * @param resource $handle Open file handle.
	 * @return void
	 */
	private function write_header( $handle ) {
		global $wpdb;

		$header  = "-- WP Sentinel Security — Database Export\n";
		$header .= '-- Generated: ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		$header .= '-- WordPress: ' . get_bloginfo( 'version' ) . "\n";
		$header .= '-- Site URL:  ' . esc_url_raw( get_site_url() ) . "\n";
		$header .= '-- Charset:   ' . $wpdb->charset . "\n";
		$header .= "-- -----------------------------------------------\n\n";
		$header .= "SET FOREIGN_KEY_CHECKS=0;\n";
		$header .= "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n";
		$header .= "SET NAMES utf8mb4;\n\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, $header );
	}

	/**
	 * Export a single table: DROP + CREATE + batched INSERTs.
	 *
	 * @param resource $handle Open file handle.
	 * @param string   $table  Table name (without any prefix; already fully qualified).
	 * @return true|WP_Error
	 */
	private function export_table( $handle, $table ) {
		global $wpdb;

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, "\n-- Table: `{$table}`\n" );

		// DROP + CREATE.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$create_row = $wpdb->get_row( "SHOW CREATE TABLE `{$table}`", ARRAY_N );
		if ( ! $create_row ) {
			return new WP_Error(
				'backup_export_create_failed',
				sprintf(
					/* translators: %s: table name */
					__( 'Could not retrieve CREATE TABLE statement for: %s', 'wp-sentinel-security' ),
					$table
				)
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, "DROP TABLE IF EXISTS `{$table}`;\n" );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, $create_row[1] . ";\n\n" );

		// Row count for LIMIT/OFFSET batching.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );

		if ( 0 === $row_count ) {
			return true;
		}

		$offset = 0;
		while ( $offset < $row_count ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"SELECT * FROM `{$table}` LIMIT %d OFFSET %d",
					self::BATCH_SIZE,
					$offset
				),
				ARRAY_A
			);

			if ( empty( $rows ) ) {
				break;
			}

			$columns = '`' . implode( '`, `', array_keys( $rows[0] ) ) . '`';

			$value_sets = array();
			foreach ( $rows as $row ) {
				$values = array_map( array( $this, 'escape_sql_value' ), array_values( $row ) );
				$value_sets[] = '(' . implode( ', ', $values ) . ')';
			}

			$insert_sql = "INSERT INTO `{$table}` ({$columns}) VALUES\n"
				. implode( ",\n", $value_sets ) . ";\n";

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
			fwrite( $handle, $insert_sql );

			$offset += self::BATCH_SIZE;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $handle, "\n" );

		return true;
	}

	/**
	 * Escape a single cell value for SQL output.
	 *
	 * Mirrors the approach used by mysqldump: NULL stays NULL,
	 * everything else is quoted and escaped.
	 *
	 * @param mixed $value Raw cell value from the database.
	 * @return string SQL-safe representation.
	 */
	private function escape_sql_value( $value ) {
		global $wpdb;

		if ( null === $value ) {
			return 'NULL';
		}

		// Use wpdb::_real_escape which handles all standard escaping.
		return "'" . $wpdb->_real_escape( $value ) . "'";
	}
}
