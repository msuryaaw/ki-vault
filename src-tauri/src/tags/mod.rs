//! Tags Domain Repository & CRUD
//!
//! Handles SQLite operations for the `tags` and `account_tags` tables (§8, §9 of `database.md`).

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::sqlite::InMemoryDb;

/// Tag entity stored in the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

pub struct TagRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> TagRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Creates a new tag in the database.
    pub fn create(&self, name: &str, now: i64) -> Result<Tag> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                reason: "Tag name must not be empty".to_string(),
            }));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let conn = self.db.conn()?;

        conn.execute(
            "INSERT INTO tags (id, name, created_at) VALUES (?1, ?2, ?3);",
            params![id, trimmed_name, now],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref ffi_err, _) = e {
                if ffi_err.extended_code == 2067
                    || ffi_err.code == rusqlite::ErrorCode::ConstraintViolation
                {
                    return DatabaseError::Conflict(format!("Tag '{trimmed_name}' already exists"));
                }
            }
            DatabaseError::Sqlite(e)
        })?;

        Ok(Tag {
            id,
            name: trimmed_name.to_string(),
            created_at: now,
        })
    }

    /// Retrieves a tag by ID.
    pub fn get_by_id(&self, id: &str) -> Result<Tag> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, created_at FROM tags WHERE id = ?1;")?;
        let mut rows = stmt.query(params![id])?;

        if let Some(row) = rows.next()? {
            Ok(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
            })
        } else {
            Err(AppError::Database(DatabaseError::NotFound {
                entity: "Tag",
                id: id.to_string(),
            }))
        }
    }

    /// Retrieves a tag by exact name.
    pub fn get_by_name(&self, name: &str) -> Result<Option<Tag>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, created_at FROM tags WHERE name = ?1;")?;
        let mut rows = stmt.query(params![name.trim()])?;

        if let Some(row) = rows.next()? {
            Ok(Some(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Lists all tags ordered by name.
    pub fn list(&self) -> Result<Vec<Tag>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare("SELECT id, name, created_at FROM tags ORDER BY name COLLATE NOCASE ASC;")?;
        let rows = stmt.query_map([], |row| {
            Ok(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;

        let mut tags = Vec::new();
        for r in rows {
            tags.push(r?);
        }
        Ok(tags)
    }

    /// Renames an existing tag.
    pub fn rename(&self, id: &str, new_name: &str) -> Result<Tag> {
        let current = self.get_by_id(id)?;
        let trimmed_name = new_name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "name",
                reason: "Tag name must not be empty".to_string(),
            }));
        }

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE tags SET name = ?1 WHERE id = ?2;",
            params![trimmed_name, id],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref ffi_err, _) = e {
                if ffi_err.extended_code == 2067
                    || ffi_err.code == rusqlite::ErrorCode::ConstraintViolation
                {
                    return DatabaseError::Conflict(format!("Tag '{trimmed_name}' already exists"));
                }
            }
            DatabaseError::Sqlite(e)
        })?;

        Ok(Tag {
            id: id.to_string(),
            name: trimmed_name.to_string(),
            created_at: current.created_at,
        })
    }

    /// Deletes a tag by ID.
    ///
    /// Note: `account_tags` references are automatically removed via ON DELETE CASCADE.
    pub fn delete(&self, id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        let affected = conn.execute("DELETE FROM tags WHERE id = ?1;", params![id])?;
        if affected == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Tag",
                id: id.to_string(),
            }));
        }
        Ok(())
    }

    /// Assigns a tag to an account.
    pub fn assign_to_account(&self, account_id: &str, tag_id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO account_tags (account_id, tag_id) VALUES (?1, ?2);",
            params![account_id, tag_id],
        )?;
        Ok(())
    }

    /// Removes a tag from an account.
    pub fn remove_from_account(&self, account_id: &str, tag_id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "DELETE FROM account_tags WHERE account_id = ?1 AND tag_id = ?2;",
            params![account_id, tag_id],
        )?;
        Ok(())
    }

    /// Lists all tags assigned to a specific account.
    pub fn list_by_account(&self, account_id: &str) -> Result<Vec<Tag>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT t.id, t.name, t.created_at
             FROM tags t
             INNER JOIN account_tags at ON t.id = at.tag_id
             WHERE at.account_id = ?1
             ORDER BY t.name COLLATE NOCASE ASC;",
        )?;

        let rows = stmt.query_map(params![account_id], |row| {
            Ok(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;

        let mut tags = Vec::new();
        for r in rows {
            tags.push(r?);
        }
        Ok(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_crud_and_uniqueness() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = TagRepository::new(&db);

        // 1. Create tag
        let tag = repo.create("Finance", 1000).unwrap();
        assert_eq!(tag.name, "Finance");

        // 2. Conflict on duplicate tag
        let duplicate_res = repo.create("Finance", 1001);
        assert!(matches!(
            duplicate_res,
            Err(AppError::Database(DatabaseError::Conflict(_)))
        ));

        // 3. Rename tag
        let renamed = repo.rename(&tag.id, "Banking").unwrap();
        assert_eq!(renamed.name, "Banking");

        // 4. List tags
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Banking");

        // 5. Delete tag
        repo.delete(&tag.id).unwrap();
        assert!(repo.list().unwrap().is_empty());
    }
}
