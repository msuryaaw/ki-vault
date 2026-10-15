//! Platforms Domain Repository & CRUD
//!
//! Handles SQLite operations for the `platforms` table (§5 of `database.md`).

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::sqlite::InMemoryDb;

/// Platform entity stored in the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub id: String,
    pub name: String,
    pub category: Option<String>,
    pub website: Option<String>,
    pub logo_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Parameters for creating a new platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePlatformParams {
    pub name: String,
    pub category: Option<String>,
    pub website: Option<String>,
    pub logo_id: Option<String>,
}

/// Parameters for updating an existing platform.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdatePlatformParams {
    pub name: Option<String>,
    pub category: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub logo_id: Option<Option<String>>,
}

/// Summary of a platform (used in listings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSummary {
    pub id: String,
    pub name: String,
    pub category: Option<String>,
    pub website: Option<String>,
    pub logo_id: Option<String>,
    pub account_count: i64,
}

pub struct PlatformRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> PlatformRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Creates a new platform in the database.
    pub fn create(&self, params: CreatePlatformParams, now: i64) -> Result<Platform> {
        let trimmed_name = params.name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                reason: "Platform name must not be empty".to_string(),
            }));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let conn = self.db.conn()?;

        conn.execute(
            "INSERT INTO platforms (id, name, category, website, logo_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            params![
                id,
                trimmed_name,
                params.category,
                params.website,
                params.logo_id,
                now,
                now
            ],
        )?;

        Ok(Platform {
            id,
            name: trimmed_name.to_string(),
            category: params.category,
            website: params.website,
            logo_id: params.logo_id,
            created_at: now,
            updated_at: now,
        })
    }

    /// Retrieves a single platform by ID.
    pub fn get_by_id(&self, id: &str) -> Result<Platform> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, category, website, logo_id, created_at, updated_at
             FROM platforms WHERE id = ?1;",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Platform {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                website: row.get(3)?,
                logo_id: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        } else {
            Err(AppError::Database(DatabaseError::NotFound {
                entity: "Platform",
                id: id.to_string(),
            }))
        }
    }

    /// Lists all platforms ordered by name ascending, with their associated account counts.
    pub fn list(&self) -> Result<Vec<PlatformSummary>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.name, p.category, p.website, p.logo_id,
                    COUNT(a.id) as account_count
             FROM platforms p
             LEFT JOIN accounts a ON p.id = a.platform_id
             GROUP BY p.id, p.name, p.category, p.website, p.logo_id
             ORDER BY p.name COLLATE NOCASE ASC;",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(PlatformSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                website: row.get(3)?,
                logo_id: row.get(4)?,
                account_count: row.get(5)?,
            })
        })?;

        let mut summaries = Vec::new();
        for r in rows {
            summaries.push(r?);
        }
        Ok(summaries)
    }

    /// Updates fields of an existing platform.
    pub fn update(&self, id: &str, params: UpdatePlatformParams, now: i64) -> Result<Platform> {
        let current = self.get_by_id(id)?;

        let new_name = match params.name {
            Some(n) => {
                let trimmed = n.trim().to_string();
                if trimmed.is_empty() {
                    return Err(AppError::Database(DatabaseError::InvalidInput {
                        field: "name",
                        reason: "Platform name must not be empty".to_string(),
                    }));
                }
                trimmed
            }
            None => current.name,
        };

        let new_category = params.category.unwrap_or(current.category);
        let new_website = params.website.unwrap_or(current.website);
        let new_logo_id = params.logo_id.unwrap_or(current.logo_id);

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE platforms
             SET name = ?1, category = ?2, website = ?3, logo_id = ?4, updated_at = ?5
             WHERE id = ?6;",
            params![new_name, new_category, new_website, new_logo_id, now, id],
        )?;

        Ok(Platform {
            id: id.to_string(),
            name: new_name,
            category: new_category,
            website: new_website,
            logo_id: new_logo_id,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    /// Deletes a platform by ID.
    ///
    /// Note: Per `database.md` §15, cascading account deletion occurs via FOREIGN KEY ON DELETE CASCADE.
    pub fn delete(&self, id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        let affected = conn.execute("DELETE FROM platforms WHERE id = ?1;", params![id])?;
        if affected == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Platform",
                id: id.to_string(),
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_crud_lifecycle() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = PlatformRepository::new(&db);

        // 1. Create platform
        let p = repo
            .create(
                CreatePlatformParams {
                    name: "Google".into(),
                    category: Some("Technology".into()),
                    website: Some("https://google.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        assert_eq!(p.name, "Google");
        assert_eq!(p.category.as_deref(), Some("Technology"));
        assert_eq!(p.created_at, 1000);

        // 2. Get by ID
        let fetched = repo.get_by_id(&p.id).unwrap();
        assert_eq!(fetched, p);

        // 3. List platforms
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Google");
        assert_eq!(list[0].account_count, 0);

        // 4. Update platform
        let updated = repo
            .update(
                &p.id,
                UpdatePlatformParams {
                    name: Some("Alphabet / Google".into()),
                    category: None,
                    website: Some(Some("https://abc.xyz".into())),
                    logo_id: None,
                },
                1500,
            )
            .unwrap();

        assert_eq!(updated.name, "Alphabet / Google");
        assert_eq!(updated.website.as_deref(), Some("https://abc.xyz"));
        assert_eq!(updated.category.as_deref(), Some("Technology"));
        assert_eq!(updated.updated_at, 1500);

        // 5. Delete platform
        repo.delete(&p.id).unwrap();
        let res = repo.get_by_id(&p.id);
        assert!(matches!(
            res,
            Err(AppError::Database(DatabaseError::NotFound { .. }))
        ));
    }

    #[test]
    fn test_platform_rejects_empty_name() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = PlatformRepository::new(&db);

        let res = repo.create(
            CreatePlatformParams {
                name: "   ".into(),
                category: None,
                website: None,
                logo_id: None,
            },
            1000,
        );

        assert!(matches!(
            res,
            Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                ..
            }))
        ));
    }
}
