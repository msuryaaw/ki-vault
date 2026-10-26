//! Custom Fields Domain Repository & CRUD
//!
//! Handles SQLite operations for the `custom_fields` table (§7 of `database.md`).

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::sqlite::InMemoryDb;

/// Custom Field entity stored in the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub id: String,
    pub account_id: String,
    pub field_name: String,
    pub field_value: String,
    pub field_type: String,
    pub is_sensitive: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Parameters for creating a custom field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCustomFieldParams {
    pub account_id: String,
    pub field_name: String,
    pub field_value: String,
    pub field_type: Option<String>,
    pub is_sensitive: Option<bool>,
}

/// Parameters for updating a custom field.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdateCustomFieldParams {
    pub field_name: Option<String>,
    pub field_value: Option<String>,
    pub field_type: Option<String>,
    pub is_sensitive: Option<bool>,
}

pub struct CustomFieldRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> CustomFieldRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Creates a custom field for an account.
    pub fn create(&self, params: CreateCustomFieldParams, now: i64) -> Result<CustomField> {
        let trimmed_name = params.field_name.trim();
        if trimmed_name.is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "field_name",
                reason: "Field name must not be empty".to_string(),
            }));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let field_type = params.field_type.unwrap_or_else(|| "text".to_string());
        let is_sensitive = params.is_sensitive.unwrap_or(true);

        let conn = self.db.conn()?;
        conn.execute(
            "INSERT INTO custom_fields (id, account_id, field_name, field_value, field_type, is_sensitive, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
            params![
                id,
                params.account_id,
                trimmed_name,
                params.field_value,
                field_type,
                if is_sensitive { 1 } else { 0 },
                now,
                now
            ],
        )?;

        Ok(CustomField {
            id,
            account_id: params.account_id,
            field_name: trimmed_name.to_string(),
            field_value: params.field_value,
            field_type,
            is_sensitive,
            created_at: now,
            updated_at: now,
        })
    }

    /// Retrieves a custom field by ID.
    pub fn get_by_id(&self, id: &str) -> Result<CustomField> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, account_id, field_name, field_value, field_type, is_sensitive, created_at, updated_at
             FROM custom_fields WHERE id = ?1;",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let is_sens_int: i64 = row.get(5)?;
            Ok(CustomField {
                id: row.get(0)?,
                account_id: row.get(1)?,
                field_name: row.get(2)?,
                field_value: row.get(3)?,
                field_type: row.get(4)?,
                is_sensitive: is_sens_int != 0,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        } else {
            Err(AppError::Database(DatabaseError::NotFound {
                entity: "CustomField",
                id: id.to_string(),
            }))
        }
    }

    /// Lists all custom fields for an account.
    pub fn list_by_account(&self, account_id: &str) -> Result<Vec<CustomField>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, account_id, field_name, field_value, field_type, is_sensitive, created_at, updated_at
             FROM custom_fields WHERE account_id = ?1
             ORDER BY created_at ASC;",
        )?;

        let rows = stmt.query_map(params![account_id], |row| {
            let is_sens_int: i64 = row.get(5)?;
            Ok(CustomField {
                id: row.get(0)?,
                account_id: row.get(1)?,
                field_name: row.get(2)?,
                field_value: row.get(3)?,
                field_type: row.get(4)?,
                is_sensitive: is_sens_int != 0,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;

        let mut fields = Vec::new();
        for r in rows {
            fields.push(r?);
        }
        Ok(fields)
    }

    /// Updates a custom field.
    pub fn update(
        &self,
        id: &str,
        params: UpdateCustomFieldParams,
        now: i64,
    ) -> Result<CustomField> {
        let current = self.get_by_id(id)?;

        let new_name = match params.field_name {
            Some(n) => {
                let trimmed = n.trim().to_string();
                if trimmed.is_empty() {
                    return Err(AppError::Database(DatabaseError::InvalidInput {
                        field: "field_name",
                        reason: "Field name must not be empty".to_string(),
                    }));
                }
                trimmed
            }
            None => current.field_name,
        };

        let new_value = params.field_value.unwrap_or(current.field_value);
        let new_type = params.field_type.unwrap_or(current.field_type);
        let new_sensitive = params.is_sensitive.unwrap_or(current.is_sensitive);

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE custom_fields
             SET field_name = ?1, field_value = ?2, field_type = ?3, is_sensitive = ?4, updated_at = ?5
             WHERE id = ?6;",
            params![
                new_name,
                new_value,
                new_type,
                if new_sensitive { 1 } else { 0 },
                now,
                id
            ],
        )?;

        Ok(CustomField {
            id: id.to_string(),
            account_id: current.account_id,
            field_name: new_name,
            field_value: new_value,
            field_type: new_type,
            is_sensitive: new_sensitive,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    /// Deletes a custom field by ID.
    pub fn delete(&self, id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        let affected = conn.execute("DELETE FROM custom_fields WHERE id = ?1;", params![id])?;
        if affected == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "CustomField",
                id: id.to_string(),
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountRepository, CreateAccountParams};
    use crate::platforms::{CreatePlatformParams, PlatformRepository};

    #[test]
    fn test_custom_field_crud_and_validation() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);
        let cf_repo = CustomFieldRepository::new(&db);

        // Setup platform & account
        let platform = plat_repo
            .create(
                CreatePlatformParams {
                    name: "GitHub".into(),
                    category: None,
                    website: None,
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let detail = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: platform.id,
                    display_name: None,
                    username: Some("user".into()),
                    email: None,
                    password: None,
                    url: None,
                    notes: None,
                    logo_id: None,
                    is_favorite: false,
                    tag_ids: vec![],
                    custom_fields: vec![],
                },
                1000,
            )
            .unwrap();

        // 1. Create custom field
        let cf = cf_repo
            .create(
                CreateCustomFieldParams {
                    account_id: detail.account.id.clone(),
                    field_name: "API Token".into(),
                    field_value: "ghp_secret".into(),
                    field_type: Some("secret".into()),
                    is_sensitive: Some(true),
                },
                1000,
            )
            .unwrap();

        assert_eq!(cf.field_name, "API Token");
        assert_eq!(cf.field_value, "ghp_secret");
        assert!(cf.is_sensitive);

        // 2. Reject empty field name
        let empty_res = cf_repo.create(
            CreateCustomFieldParams {
                account_id: detail.account.id.clone(),
                field_name: "  ".into(),
                field_value: "val".into(),
                field_type: None,
                is_sensitive: None,
            },
            1000,
        );
        assert!(matches!(
            empty_res,
            Err(AppError::Database(DatabaseError::InvalidInput { .. }))
        ));

        // 3. Update custom field
        let updated = cf_repo
            .update(
                &cf.id,
                UpdateCustomFieldParams {
                    field_name: Some("Personal Access Token".into()),
                    field_value: Some("ghp_updated".into()),
                    field_type: None,
                    is_sensitive: Some(false),
                },
                1200,
            )
            .unwrap();
        assert_eq!(updated.field_name, "Personal Access Token");
        assert_eq!(updated.field_value, "ghp_updated");
        assert!(!updated.is_sensitive);
        assert_eq!(updated.updated_at, 1200);

        // 4. List by account
        let list = cf_repo.list_by_account(&detail.account.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, cf.id);

        // 5. Delete custom field
        cf_repo.delete(&cf.id).unwrap();
        assert!(cf_repo
            .list_by_account(&detail.account.id)
            .unwrap()
            .is_empty());
    }
}
