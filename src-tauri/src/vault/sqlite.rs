//! SQLite In-Memory Database Wrapper
//!
//! Provides in-memory SQLite database management for KiVault vaults.
//! In accordance with `database.md`, `vault-format.md`, and `technical-baseline.md`:
//! - Databases are opened strictly in memory via `Connection::open_in_memory()`.
//! - Input payloads are loaded into SQLite using deserialization (`deserialize`), NOT `execute_batch`.
//! - Database states are exported using `serialize` to produce ciphertext payload candidates.
//! - Bounds checks are enforced before allocating or deserializing database images.
//! - Exported plaintext buffers are wrapped in `Zeroizing` to ensure secure erasure upon drop.
//!
//! # Zeroization Boundaries & Limitations
//! While KiVault wraps exported plaintext buffers and key material in `Zeroizing<Vec<u8>>`:
//! - SQLite's internal C heap memory (managed by the SQLite engine's B-Tree / pager) is NOT zeroized
//!   when tables/pages are discarded or when `Connection` is closed.
//! - OS virtual memory paging (e.g., Windows `pagefile.sys` or swap) or system crash dumps may
//!   contain ephemeral SQLite memory pages outside userspace control.
//! - Once `close()` is called on [`InMemoryDb`], the connection is dropped and SQLite frees its
//!   allocated heap blocks back to the process memory allocator.

use std::ptr::NonNull;

use rusqlite::ffi;
use rusqlite::serialize::{Data, OwnedData};
use rusqlite::{Connection, DatabaseName};
use zeroize::Zeroizing;

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::{MAX_CIPHERTEXT_LEN, MIN_CIPHERTEXT_LEN};

/// Canonical initial schema definition for KiVault v1.
pub const INITIAL_SCHEMA_SQL: &str = include_str!("schema.sql");

/// Baseline database schema version (v1).
pub const SCHEMA_VERSION_V1: u32 = 1;

/// Maximum allowed serialized database image length (512 MiB - 16B auth tag = 536,870,896 bytes).
pub const MAX_DB_IMAGE_LEN: usize = (MAX_CIPHERTEXT_LEN - MIN_CIPHERTEXT_LEN) as usize;

/// In-memory SQLite database manager.
#[derive(Debug)]
pub struct InMemoryDb {
    conn: Option<Connection>,
}

impl InMemoryDb {
    /// Creates a fresh, empty in-memory SQLite database and applies the initial schema v1.
    ///
    /// Sets:
    /// - `PRAGMA foreign_keys = ON;`
    /// - `PRAGMA temp_store = MEMORY;`
    /// - `PRAGMA journal_mode = MEMORY;`
    /// - `PRAGMA user_version = 1;`
    pub fn create_empty() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure_pragmas(&conn)?;
        conn.execute_batch(INITIAL_SCHEMA_SQL)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION_V1)?;

        Ok(Self { conn: Some(conn) })
    }

    /// Imports an existing SQLite database image into an in-memory database using SQLite deserialization.
    ///
    /// # Security & Bounds
    /// - `bytes` must not exceed `MAX_DB_IMAGE_LEN`.
    /// - Deserializes the bytes into an in-memory database.
    /// - Verifies integrity and checks `user_version`.
    pub fn from_image(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DB_IMAGE_LEN {
            return Err(AppError::Database(DatabaseError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_DB_IMAGE_LEN,
            }));
        }

        // Must be at least 100 bytes (SQLite header size is 100 bytes)
        if bytes.len() < 100 {
            return Err(AppError::Database(DatabaseError::CorruptDatabase(
                "Image size is smaller than minimum SQLite header (100 bytes)".to_string(),
            )));
        }

        // SQLite magic header check: "SQLite format 3\0"
        if !bytes.starts_with(b"SQLite format 3\0") {
            return Err(AppError::Database(DatabaseError::CorruptDatabase(
                "Invalid SQLite header magic".to_string(),
            )));
        }

        let mut conn = Connection::open_in_memory()?;
        configure_pragmas(&conn)?;

        // Allocate SQLite-managed memory and copy the buffer into it for `OwnedData`.
        // SQLite will take ownership and free it on close via SQLITE_DESERIALIZE_FREEONCLOSE.
        let owned_data = unsafe {
            let ptr = ffi::sqlite3_malloc64(bytes.len() as u64) as *mut u8;
            if ptr.is_null() {
                return Err(AppError::Database(DatabaseError::CorruptDatabase(
                    "sqlite3_malloc64 allocation failed for deserialization".to_string(),
                )));
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            OwnedData::from_raw_nonnull(NonNull::new_unchecked(ptr), bytes.len())
        };

        // Deserialize the database image into the "main" database with read/write capability (read_only = false).
        conn.deserialize(DatabaseName::Main, owned_data, false)
            .map_err(|e| {
                DatabaseError::CorruptDatabase(format!("Failed to deserialize database image: {e}"))
            })?;

        // Run quick integrity check
        let integrity: String = conn
            .query_row("PRAGMA quick_check;", [], |row| row.get(0))
            .map_err(|e| {
                DatabaseError::CorruptDatabase(format!("Integrity check query failed: {e}"))
            })?;

        if integrity != "ok" {
            return Err(AppError::Database(DatabaseError::IntegrityCheckFailed(
                integrity,
            )));
        }

        let user_version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        if user_version != SCHEMA_VERSION_V1 {
            return Err(AppError::Database(
                DatabaseError::UnsupportedSchemaVersion {
                    version: user_version,
                    supported: SCHEMA_VERSION_V1,
                },
            ));
        }

        Ok(Self { conn: Some(conn) })
    }

    /// Serializes the in-memory database to a contiguous byte buffer.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`] to ensure that upon drop,
    /// the memory is securely cleared.
    pub fn to_image(&self) -> Result<Zeroizing<Vec<u8>>> {
        let conn = self.conn()?;
        let data: Data<'_> = conn.serialize(DatabaseName::Main)?;
        if data.len() > MAX_DB_IMAGE_LEN {
            return Err(AppError::Database(DatabaseError::PayloadTooLarge {
                size: data.len(),
                max: MAX_DB_IMAGE_LEN,
            }));
        }
        // Copy the serialized bytes into a Zeroizing container
        Ok(Zeroizing::new(data.to_vec()))
    }

    /// Returns a reference to the active `rusqlite::Connection`.
    ///
    /// Returns `DatabaseError::ConnectionClosed` if the connection has been closed.
    pub fn conn(&self) -> Result<&Connection> {
        self.conn
            .as_ref()
            .ok_or_else(|| AppError::Database(DatabaseError::ConnectionClosed))
    }

    /// Returns a mutable reference to the active `rusqlite::Connection`.
    ///
    /// Returns `DatabaseError::ConnectionClosed` if the connection has been closed.
    pub fn conn_mut(&mut self) -> Result<&mut Connection> {
        self.conn
            .as_mut()
            .ok_or_else(|| AppError::Database(DatabaseError::ConnectionClosed))
    }

    /// Reads the current `user_version` PRAGMA from the database.
    pub fn schema_version(&self) -> Result<u32> {
        let conn = self.conn()?;
        let version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        Ok(version)
    }

    /// Explicitly closes the database connection, freeing SQLite's allocated in-memory structures.
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// Returns `true` if the database connection is currently active/open.
    pub fn is_open(&self) -> bool {
        self.conn.is_some()
    }
}

impl Drop for InMemoryDb {
    fn drop(&mut self) {
        self.close();
    }
}

/// Sets performance and memory mitigation pragmas per `database.md`.
fn configure_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA journal_mode = MEMORY;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_empty_in_memory_db() {
        let db = InMemoryDb::create_empty().expect("Failed to create empty in-memory DB");
        assert!(db.is_open());
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION_V1);

        // Verify tables exist
        let conn = db.conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vault_metadata';",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_basic_crud_query() {
        let db = InMemoryDb::create_empty().expect("Failed to create empty in-memory DB");
        let conn = db.conn().unwrap();

        // Insert metadata
        conn.execute(
            "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
            ("v-1234", "Personal Vault", 1700000000i64, 1700000000i64),
        )
        .expect("Insert failed");

        // Query metadata
        let name: String = conn
            .query_row(
                "SELECT name FROM vault_metadata WHERE id = ?1;",
                ["v-1234"],
                |row| row.get(0),
            )
            .expect("Query failed");
        assert_eq!(name, "Personal Vault");

        // Insert platform & account with foreign key
        conn.execute(
            "INSERT INTO platforms (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
            ("p-1", "GitHub", 1700000000i64, 1700000000i64),
        )
        .expect("Insert platform failed");

        conn.execute(
            "INSERT INTO accounts (id, platform_id, username, password, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
            (
                "a-1",
                "p-1",
                "alice",
                "secret123",
                1700000000i64,
                1700000000i64,
            ),
        )
        .expect("Insert account failed");

        let acc_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM accounts WHERE platform_id = ?1;",
                ["p-1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acc_count, 1);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let db1 = InMemoryDb::create_empty().expect("Failed to create DB");
        {
            let conn = db1.conn().unwrap();
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                ("v-roundtrip", "Roundtrip Vault", 100, 200),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO platforms (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                ("p-rt", "ProtonMail", 100, 200),
            )
            .unwrap();
        }

        // Serialize to image
        let image = db1.to_image().expect("Serialization failed");
        assert!(!image.is_empty());
        assert!(image.starts_with(b"SQLite format 3\0"));

        // Deserialize in a new DB
        let db2 = InMemoryDb::from_image(&image).expect("Deserialization failed");
        assert!(db2.is_open());
        assert_eq!(db2.schema_version().unwrap(), SCHEMA_VERSION_V1);

        // Verify data preserved
        let conn2 = db2.conn().unwrap();
        let name: String = conn2
            .query_row(
                "SELECT name FROM vault_metadata WHERE id = ?1;",
                ["v-roundtrip"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Roundtrip Vault");

        let plat_name: String = conn2
            .query_row(
                "SELECT name FROM platforms WHERE id = ?1;",
                ["p-rt"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(plat_name, "ProtonMail");
    }

    #[test]
    fn test_rejects_oversized_image() {
        let fake_header = vec![0u8; 50];
        let err = InMemoryDb::from_image(&fake_header).unwrap_err();
        match err {
            AppError::Database(DatabaseError::CorruptDatabase(msg)) => {
                assert!(msg.contains("smaller than minimum"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rejects_invalid_magic_or_corrupt_database() {
        let mut bad_magic = vec![0u8; 200];
        bad_magic[..16].copy_from_slice(b"NOT A SQLITE DB!");

        let err = InMemoryDb::from_image(&bad_magic).unwrap_err();
        match err {
            AppError::Database(DatabaseError::CorruptDatabase(msg)) => {
                assert!(msg.contains("Invalid SQLite header magic"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }

        // Header says SQLite format 3\0 but contents are junk
        let mut junk = vec![0u8; 1024];
        junk[..16].copy_from_slice(b"SQLite format 3\0");
        let err2 = InMemoryDb::from_image(&junk).unwrap_err();
        match err2 {
            AppError::Database(DatabaseError::CorruptDatabase(msg)) => {
                assert!(msg.contains("Failed to deserialize") || msg.contains("Integrity"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rejects_unsupported_schema_version() {
        let db = InMemoryDb::create_empty().expect("Failed to create DB");
        {
            let conn = db.conn().unwrap();
            conn.pragma_update(None, "user_version", 99u32).unwrap();
        }
        let image = db.to_image().unwrap();

        let err = InMemoryDb::from_image(&image).unwrap_err();
        match err {
            AppError::Database(DatabaseError::UnsupportedSchemaVersion { version, supported }) => {
                assert_eq!(version, 99);
                assert_eq!(supported, SCHEMA_VERSION_V1);
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_connection_close_lifecycle() {
        let mut db = InMemoryDb::create_empty().expect("Failed to create DB");
        assert!(db.is_open());
        assert!(db.conn().is_ok());

        db.close();
        assert!(!db.is_open());
        match db.conn().unwrap_err() {
            AppError::Database(DatabaseError::ConnectionClosed) => {}
            other => panic!("Unexpected error: {:?}", other),
        }
        match db.to_image().unwrap_err() {
            AppError::Database(DatabaseError::ConnectionClosed) => {}
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}
