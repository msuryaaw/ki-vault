//! Logos Domain Repository & Sanitization
//!
//! Handles SQLite operations for the `logos` table (§10 of `database.md`),
//! logo format validation, size constraints, and SVG sanitization.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::sqlite::InMemoryDb;

/// Maximum allowed logo byte size (2 MiB = 2,097,152 bytes).
pub const MAX_LOGO_SIZE_BYTES: usize = 2 * 1024 * 1024;

/// Supported logo MIME types per PRD §11 and UI-UX Spec §11.
pub const MIME_PNG: &str = "image/png";
pub const MIME_JPEG: &str = "image/jpeg";
pub const MIME_WEBP: &str = "image/webp";
pub const MIME_SVG: &str = "image/svg+xml";

/// Full Logo entity stored in the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logo {
    pub id: String,
    pub name: String,
    pub mime_type: String,
    pub image_data: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Lightweight Logo summary without raw image bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoSummary {
    pub id: String,
    pub name: String,
    pub mime_type: String,
    pub size_bytes: usize,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Parameters for importing a new logo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportLogoParams {
    pub name: String,
    pub mime_type: String,
    pub image_data: Vec<u8>,
}

/// Normalizes and validates MIME type string against supported formats.
pub fn validate_and_normalize_mime(mime: &str) -> Result<String> {
    let normalized = mime.trim().to_lowercase();
    match normalized.as_str() {
        MIME_PNG => Ok(MIME_PNG.to_string()),
        MIME_JPEG | "image/jpg" => Ok(MIME_JPEG.to_string()),
        MIME_WEBP => Ok(MIME_WEBP.to_string()),
        MIME_SVG | "image/svg" => Ok(MIME_SVG.to_string()),
        _ => Err(AppError::Database(DatabaseError::InvalidInput {
            field: "mime_type",
            reason: format!("Unsupported MIME type '{mime}'. Supported: PNG, JPEG, WebP, SVG."),
        })),
    }
}

/// Validates binary image signatures / magic bytes for raster formats.
pub fn validate_raster_header(mime: &str, data: &[u8]) -> Result<()> {
    match mime {
        MIME_PNG => {
            // PNG magic: 89 50 4E 47 0D 0A 1A 0A
            const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            if data.len() < 8 || &data[..8] != PNG_MAGIC {
                return Err(AppError::Database(DatabaseError::InvalidInput {
                    field: "image_data",
                    reason: "Invalid PNG magic signature".to_string(),
                }));
            }
        }
        MIME_JPEG => {
            // JPEG starts with FF D8 and ends with FF D9 (or at least begins with FF D8 FF)
            if data.len() < 3 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
                return Err(AppError::Database(DatabaseError::InvalidInput {
                    field: "image_data",
                    reason: "Invalid JPEG magic signature".to_string(),
                }));
            }
        }
        MIME_WEBP if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" => {
            // WebP: RIFF....WEBP (bytes 0..4 == "RIFF", bytes 8..12 == "WEBP")
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "image_data",
                reason: "Invalid WebP magic signature".to_string(),
            }));
        }
        _ => {}
    }
    Ok(())
}

/// Sanitizes SVG markup using `svg_hush`.
///
/// Strips scripts, inline event handlers (onclick, onload), external references,
/// and rejects XML external entities or malformed XML structures.
pub fn sanitize_svg(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: "SVG content cannot be empty".to_string(),
        }));
    }

    // Reject external DTDs or system entities before parsing (ST-019 defense-in-depth)
    let lower_preview = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_lowercase();
    if lower_preview.contains("<!entity") && lower_preview.contains("system") {
        return Err(AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: "XML external entity (XXE) constructs are prohibited".to_string(),
        }));
    }

    let mut filter = svg_hush::Filter::new();
    // Allow standard base64/inline images if present, but external URLs are blocked
    filter.set_data_url_filter(svg_hush::data_url_filter::allow_standard_images);

    let mut sanitized = Vec::new();
    filter.filter(data, &mut sanitized).map_err(|err| {
        AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: format!("SVG parsing/sanitization failed: {err}"),
        })
    })?;

    if sanitized.is_empty() {
        return Err(AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: "SVG content became empty after sanitization".to_string(),
        }));
    }

    Ok(sanitized)
}

/// Validates logo payload size, MIME, magic bytes, and performs SVG sanitization.
pub fn process_logo_data(mime_type: &str, raw_data: &[u8]) -> Result<(String, Vec<u8>)> {
    if raw_data.is_empty() {
        return Err(AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: "Image data cannot be empty".to_string(),
        }));
    }

    if raw_data.len() > MAX_LOGO_SIZE_BYTES {
        return Err(AppError::Database(DatabaseError::InvalidInput {
            field: "image_data",
            reason: format!(
                "Image size ({} bytes) exceeds maximum allowed limit ({} bytes)",
                raw_data.len(),
                MAX_LOGO_SIZE_BYTES
            ),
        }));
    }

    let normalized_mime = validate_and_normalize_mime(mime_type)?;

    let clean_data = if normalized_mime == MIME_SVG {
        sanitize_svg(raw_data)?
    } else {
        validate_raster_header(&normalized_mime, raw_data)?;
        raw_data.to_vec()
    };

    Ok((normalized_mime, clean_data))
}

pub struct LogoRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> LogoRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Imports a new logo into the database after validating and sanitizing.
    pub fn import(&self, params: ImportLogoParams, now: i64) -> Result<Logo> {
        let trimmed_name = params.name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                reason: "Logo name must not be empty".to_string(),
            }));
        }

        let (mime_type, image_data) = process_logo_data(&params.mime_type, &params.image_data)?;

        let id = uuid::Uuid::new_v4().to_string();
        let conn = self.db.conn()?;

        conn.execute(
            "INSERT INTO logos (id, name, mime_type, image_data, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
            params![id, trimmed_name, mime_type, image_data, now, now],
        )?;

        Ok(Logo {
            id,
            name: trimmed_name.to_string(),
            mime_type,
            image_data,
            created_at: now,
            updated_at: now,
        })
    }

    /// Lists all logos as lightweight summaries without raw BLOB bytes.
    pub fn list(&self) -> Result<Vec<LogoSummary>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, mime_type, length(image_data), created_at, updated_at
             FROM logos
             ORDER BY name ASC, created_at ASC;",
        )?;

        let rows = stmt.query_map([], |row| {
            let size_i64: i64 = row.get(3)?;
            Ok(LogoSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                mime_type: row.get(2)?,
                size_bytes: size_i64 as usize,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?;

        let mut summaries = Vec::new();
        for r in rows {
            summaries.push(r?);
        }
        Ok(summaries)
    }

    /// Retrieves full logo including raw binary BLOB.
    pub fn get_by_id(&self, id: &str) -> Result<Logo> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, mime_type, image_data, created_at, updated_at
             FROM logos
             WHERE id = ?1;",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Logo {
                id: row.get(0)?,
                name: row.get(1)?,
                mime_type: row.get(2)?,
                image_data: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        } else {
            Err(AppError::Database(DatabaseError::NotFound {
                entity: "Logo",
                id: id.to_string(),
            }))
        }
    }

    /// Renames an existing logo.
    pub fn rename(&self, id: &str, new_name: &str, now: i64) -> Result<Logo> {
        let trimmed_name = new_name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                reason: "Logo name must not be empty".to_string(),
            }));
        }

        let current = self.get_by_id(id)?;
        let conn = self.db.conn()?;

        conn.execute(
            "UPDATE logos
             SET name = ?1, updated_at = ?2
             WHERE id = ?3;",
            params![trimmed_name, now, id],
        )?;

        Ok(Logo {
            id: current.id,
            name: trimmed_name.to_string(),
            mime_type: current.mime_type,
            image_data: current.image_data,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    /// Replaces the image content and optionally MIME type of an existing logo.
    /// Re-sanitizes SVG content and validates binary payload.
    pub fn replace_content(
        &self,
        id: &str,
        new_mime_type: &str,
        new_data: &[u8],
        now: i64,
    ) -> Result<Logo> {
        let current = self.get_by_id(id)?;
        let (clean_mime, clean_data) = process_logo_data(new_mime_type, new_data)?;

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE logos
             SET mime_type = ?1, image_data = ?2, updated_at = ?3
             WHERE id = ?4;",
            params![clean_mime, clean_data, now, id],
        )?;

        Ok(Logo {
            id: current.id,
            name: current.name,
            mime_type: clean_mime,
            image_data: clean_data,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    /// Deletes a logo by ID and nulls out any references in `platforms.logo_id`.
    pub fn delete(&self, id: &str) -> Result<()> {
        let conn = self.db.conn()?;

        // First check existence
        let _ = self.get_by_id(id)?;

        // Nullify logo references in platforms and accounts
        conn.execute(
            "UPDATE platforms SET logo_id = NULL WHERE logo_id = ?1;",
            params![id],
        )?;
        conn.execute(
            "UPDATE accounts SET logo_id = NULL WHERE logo_id = ?1;",
            params![id],
        )?;

        // Delete logo record
        let affected = conn.execute("DELETE FROM logos WHERE id = ?1;", params![id])?;
        if affected == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Logo",
                id: id.to_string(),
            }));
        }

        Ok(())
    }

    /// Assigns a logo to a platform (or unassigns if `logo_id` is None),
    /// validating that both platform and logo exist before updating.
    pub fn assign_to_platform(
        &self,
        platform_id: &str,
        logo_id: Option<&str>,
        now: i64,
    ) -> Result<()> {
        let conn = self.db.conn()?;

        // Validate platform exists
        let platform_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM platforms WHERE id = ?1);",
                params![platform_id],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        if !platform_exists {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Platform",
                id: platform_id.to_string(),
            }));
        }

        // Validate logo exists if provided
        if let Some(lid) = logo_id {
            let logo_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM logos WHERE id = ?1);",
                    params![lid],
                    |row| row.get(0),
                )
                .map_err(DatabaseError::Sqlite)?;

            if !logo_exists {
                return Err(AppError::Database(DatabaseError::NotFound {
                    entity: "Logo",
                    id: lid.to_string(),
                }));
            }
        }

        conn.execute(
            "UPDATE platforms SET logo_id = ?1, updated_at = ?2 WHERE id = ?3;",
            params![logo_id, now, platform_id],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logo_crud_lifecycle() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = LogoRepository::new(&db);

        let svg_bytes = br#"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40" fill="red"/></svg>"#;
        let params = ImportLogoParams {
            name: "Test Logo".to_string(),
            mime_type: "image/svg+xml".to_string(),
            image_data: svg_bytes.to_vec(),
        };

        let logo = repo.import(params, 1000).unwrap();
        assert_eq!(logo.name, "Test Logo");
        assert_eq!(logo.mime_type, "image/svg+xml");

        // List
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, logo.id);
        assert_eq!(list[0].name, "Test Logo");

        // Get by ID
        let fetched = repo.get_by_id(&logo.id).unwrap();
        assert_eq!(fetched.id, logo.id);
        assert!(!fetched.image_data.is_empty());

        // Rename
        let renamed = repo.rename(&logo.id, "Renamed Logo", 1050).unwrap();
        assert_eq!(renamed.name, "Renamed Logo");
        assert_eq!(renamed.updated_at, 1050);

        // Replace
        let png_bytes = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        let replaced = repo
            .replace_content(&logo.id, "image/png", png_bytes, 1100)
            .unwrap();
        assert_eq!(replaced.mime_type, "image/png");
        assert_eq!(replaced.image_data, png_bytes);

        // Delete
        repo.delete(&logo.id).unwrap();
        assert!(repo.get_by_id(&logo.id).is_err());
        assert_eq!(repo.list().unwrap().len(), 0);
    }

    #[test]
    fn test_svg_sanitization_removes_scripts_and_handlers() {
        let malicious_svg = br#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert('pwn')">
            <script>alert('xss')</script>
            <circle cx="50" cy="50" r="40" fill="red" onclick="malicious()"/>
        </svg>"#;

        let sanitized = sanitize_svg(malicious_svg).unwrap();
        let sanitized_str = String::from_utf8(sanitized).unwrap();

        assert!(!sanitized_str.contains("<script"));
        assert!(!sanitized_str.contains("alert("));
        assert!(!sanitized_str.contains("onload"));
        assert!(!sanitized_str.contains("onclick"));
        assert!(!sanitized_str.contains("malicious"));
        assert!(sanitized_str.contains("circle"));
    }

    #[test]
    fn test_svg_sanitization_rejects_xxe() {
        let xxe_svg = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"#;

        let result = sanitize_svg(xxe_svg);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_oversized_logo() {
        let large_data = vec![0u8; MAX_LOGO_SIZE_BYTES + 1];
        let res = process_logo_data("image/png", &large_data);
        assert!(res.is_err());
    }

    #[test]
    fn test_rejects_unsupported_mime() {
        let data = b"some data";
        let res = process_logo_data("application/pdf", data);
        assert!(res.is_err());
    }

    #[test]
    fn test_rejects_invalid_magic_bytes() {
        let bad_png = b"NOT_A_PNG_FILE";
        let res = process_logo_data("image/png", bad_png);
        assert!(res.is_err());
    }

    #[test]
    fn test_delete_logo_nullifies_platform_reference() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = LogoRepository::new(&db);

        // 1. Insert a logo
        let svg_bytes =
            br#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>"#;
        let logo = repo
            .import(
                ImportLogoParams {
                    name: "Platform Logo".to_string(),
                    mime_type: "image/svg+xml".to_string(),
                    image_data: svg_bytes.to_vec(),
                },
                100,
            )
            .unwrap();

        // 2. Insert platform referencing the logo
        let conn = db.conn().unwrap();
        let platform_id = "plat-1";
        conn.execute(
            "INSERT INTO platforms (id, name, logo_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            params![platform_id, "Platform 1", logo.id, 100, 100],
        )
        .unwrap();

        // 3. Delete logo
        repo.delete(&logo.id).unwrap();

        // 4. Verify platform logo_id is now NULL
        let current_logo_id: Option<String> = conn
            .query_row(
                "SELECT logo_id FROM platforms WHERE id = ?1;",
                params![platform_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_logo_id, None);
    }

    #[test]
    fn test_assign_logo_to_platform() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = LogoRepository::new(&db);

        let svg_bytes =
            br#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>"#;
        let logo = repo
            .import(
                ImportLogoParams {
                    name: "Brand".to_string(),
                    mime_type: "image/svg+xml".to_string(),
                    image_data: svg_bytes.to_vec(),
                },
                100,
            )
            .unwrap();

        let conn = db.conn().unwrap();
        let platform_id = "plat-2";
        conn.execute(
            "INSERT INTO platforms (id, name, logo_id, created_at, updated_at)
             VALUES (?1, ?2, NULL, ?3, ?4);",
            params![platform_id, "Platform 2", 100, 100],
        )
        .unwrap();

        // Assign valid logo
        repo.assign_to_platform(platform_id, Some(&logo.id), 200)
            .unwrap();
        let current_logo_id: Option<String> = conn
            .query_row(
                "SELECT logo_id FROM platforms WHERE id = ?1;",
                params![platform_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_logo_id, Some(logo.id.clone()));

        // Assign non-existent logo fails
        let err = repo.assign_to_platform(platform_id, Some("non-existent-logo"), 250);
        assert!(err.is_err());

        // Unassign logo
        repo.assign_to_platform(platform_id, None, 300).unwrap();
        let current_logo_id: Option<String> = conn
            .query_row(
                "SELECT logo_id FROM platforms WHERE id = ?1;",
                params![platform_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_logo_id, None);
    }
}
