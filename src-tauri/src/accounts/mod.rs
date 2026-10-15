//! Accounts Domain Repository & CRUD
//!
//! Handles SQLite operations for the `accounts` table (§6 of `database.md`),
//! including transactional multi-record mutations with custom fields and tags.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::custom_fields::{CustomField, CustomFieldRepository};
use crate::errors::{AppError, DatabaseError, Result};
use crate::tags::{Tag, TagRepository};
use crate::vault::sqlite::InMemoryDb;

/// Account entity stored in the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub platform_id: String,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub is_favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Detailed account representation returned by `get_account_detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDetail {
    pub account: Account,
    pub tags: Vec<Tag>,
    pub custom_fields: Vec<CustomField>,
}

/// Summary representation of an account (used in lists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub platform_id: String,
    pub platform_name: String,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub is_favorite: bool,
    pub updated_at: i64,
}

/// Parameters for creating a new account.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CreateAccountParams {
    pub platform_id: String,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub is_favorite: bool,
    pub tag_ids: Vec<String>,
    pub custom_fields: Vec<CreateCustomFieldParamsInput>,
}

/// Input parameter for custom fields when creating an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCustomFieldParamsInput {
    pub field_name: String,
    pub field_value: String,
    pub field_type: Option<String>,
    pub is_sensitive: Option<bool>,
}

/// Parameters for updating an existing account.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdateAccountParams {
    pub platform_id: Option<String>,
    pub display_name: Option<Option<String>>,
    pub username: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub password: Option<Option<String>>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub is_favorite: Option<bool>,
}

/// Filters for listing accounts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListAccountsFilter {
    pub platform_id: Option<String>,
    pub favorite_only: bool,
    pub tag_id: Option<String>,
}

pub struct AccountRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> AccountRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Transactionally creates a new account along with its custom fields and assigned tags.
    ///
    /// Per `database.md` §14:
    /// ```text
    /// BEGIN
    ///   Insert Account
    ///   Insert Custom Fields
    ///   Insert Account Tags
    /// COMMIT
    /// ```
    pub fn create(&self, params: CreateAccountParams, now: i64) -> Result<AccountDetail> {
        if params.platform_id.trim().is_empty() {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "platform_id",
                reason: "Platform ID must not be empty".to_string(),
            }));
        }

        let account_id = uuid::Uuid::new_v4().to_string();

        let conn = self.db.conn()?;

        // Verify foreign key: platform must exist
        let platform_exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM platforms WHERE id = ?1;",
            params![params.platform_id],
            |row| row.get(0),
        )?;
        if platform_exists == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Platform",
                id: params.platform_id,
            }));
        }

        // Execute inside an explicit SQLite transaction
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO accounts (id, platform_id, display_name, username, email, password, url, notes, is_favorite, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);",
            params![
                account_id,
                params.platform_id,
                params.display_name,
                params.username,
                params.email,
                params.password,
                params.url,
                params.notes,
                if params.is_favorite { 1 } else { 0 },
                now,
                now
            ],
        )?;

        // Insert custom fields
        let mut created_fields = Vec::new();
        for cf in params.custom_fields {
            let field_id = uuid::Uuid::new_v4().to_string();
            let trimmed_name = cf.field_name.trim();
            if trimmed_name.is_empty() {
                let _ = tx.rollback();
                return Err(AppError::Database(DatabaseError::InvalidInput {
                    field: "field_name",
                    reason: "Custom field name cannot be empty".to_string(),
                }));
            }
            let field_type = cf.field_type.unwrap_or_else(|| "text".to_string());
            let is_sensitive = cf.is_sensitive.unwrap_or(true);

            tx.execute(
                "INSERT INTO custom_fields (id, account_id, field_name, field_value, field_type, is_sensitive, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
                params![
                    field_id,
                    account_id,
                    trimmed_name,
                    cf.field_value,
                    field_type,
                    if is_sensitive { 1 } else { 0 },
                    now,
                    now
                ],
            )?;

            created_fields.push(CustomField {
                id: field_id,
                account_id: account_id.clone(),
                field_name: trimmed_name.to_string(),
                field_value: cf.field_value,
                field_type,
                is_sensitive,
                created_at: now,
                updated_at: now,
            });
        }

        // Assign tags
        for tag_id in &params.tag_ids {
            tx.execute(
                "INSERT OR IGNORE INTO account_tags (account_id, tag_id) VALUES (?1, ?2);",
                params![account_id, tag_id],
            )?;
        }

        tx.commit()?;

        // Retrieve tags assigned
        let tag_repo = TagRepository::new(self.db);
        let tags = tag_repo.list_by_account(&account_id)?;

        Ok(AccountDetail {
            account: Account {
                id: account_id,
                platform_id: params.platform_id,
                display_name: params.display_name,
                username: params.username,
                email: params.email,
                password: params.password,
                url: params.url,
                notes: params.notes,
                is_favorite: params.is_favorite,
                created_at: now,
                updated_at: now,
            },
            tags,
            custom_fields: created_fields,
        })
    }

    /// Retrieves an account entity by ID.
    pub fn get_by_id(&self, id: &str) -> Result<Account> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, platform_id, display_name, username, email, password, url, notes, is_favorite, created_at, updated_at
             FROM accounts WHERE id = ?1;",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let is_fav: i64 = row.get(8)?;
            Ok(Account {
                id: row.get(0)?,
                platform_id: row.get(1)?,
                display_name: row.get(2)?,
                username: row.get(3)?,
                email: row.get(4)?,
                password: row.get(5)?,
                url: row.get(6)?,
                notes: row.get(7)?,
                is_favorite: is_fav != 0,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        } else {
            Err(AppError::Database(DatabaseError::NotFound {
                entity: "Account",
                id: id.to_string(),
            }))
        }
    }

    /// Retrieves full account detail including its tags and custom fields.
    pub fn get_detail(&self, id: &str) -> Result<AccountDetail> {
        let account = self.get_by_id(id)?;
        let tag_repo = TagRepository::new(self.db);
        let tags = tag_repo.list_by_account(id)?;

        let cf_repo = CustomFieldRepository::new(self.db);
        let custom_fields = cf_repo.list_by_account(id)?;

        Ok(AccountDetail {
            account,
            tags,
            custom_fields,
        })
    }

    /// Lists accounts with optional filtering (platform, favorites, tag).
    pub fn list(&self, filter: ListAccountsFilter) -> Result<Vec<AccountSummary>> {
        let conn = self.db.conn()?;

        let mut query = String::from(
            "SELECT a.id, a.platform_id, p.name as platform_name,
                    a.display_name, a.username, a.email, a.is_favorite, a.updated_at
             FROM accounts a
             INNER JOIN platforms p ON a.platform_id = p.id ",
        );

        let mut clauses = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(tag_id) = filter.tag_id {
            query.push_str("INNER JOIN account_tags at ON a.id = at.account_id ");
            clauses.push("at.tag_id = ?");
            params_vec.push(Box::new(tag_id));
        }

        if let Some(platform_id) = filter.platform_id {
            clauses.push("a.platform_id = ?");
            params_vec.push(Box::new(platform_id));
        }

        if filter.favorite_only {
            clauses.push("a.is_favorite = 1");
        }

        if !clauses.is_empty() {
            query.push_str("WHERE ");
            query.push_str(&clauses.join(" AND "));
        }

        query.push_str(" ORDER BY a.updated_at DESC;");

        let mut stmt = conn.prepare(&query)?;
        let params_slice: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();

        let rows = stmt.query_map(&params_slice[..], |row| {
            let is_fav: i64 = row.get(6)?;
            Ok(AccountSummary {
                id: row.get(0)?,
                platform_id: row.get(1)?,
                platform_name: row.get(2)?,
                display_name: row.get(3)?,
                username: row.get(4)?,
                email: row.get(5)?,
                is_favorite: is_fav != 0,
                updated_at: row.get(7)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Updates fields of an existing account.
    pub fn update(&self, id: &str, params: UpdateAccountParams, now: i64) -> Result<Account> {
        let current = self.get_by_id(id)?;

        let new_platform_id = params.platform_id.unwrap_or(current.platform_id);
        let new_display_name = params.display_name.unwrap_or(current.display_name);
        let new_username = params.username.unwrap_or(current.username);
        let new_email = params.email.unwrap_or(current.email);
        let new_password = params.password.unwrap_or(current.password);
        let new_url = params.url.unwrap_or(current.url);
        let new_notes = params.notes.unwrap_or(current.notes);
        let new_is_favorite = params.is_favorite.unwrap_or(current.is_favorite);

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE accounts
             SET platform_id = ?1, display_name = ?2, username = ?3, email = ?4,
                 password = ?5, url = ?6, notes = ?7, is_favorite = ?8, updated_at = ?9
             WHERE id = ?10;",
            params![
                new_platform_id,
                new_display_name,
                new_username,
                new_email,
                new_password,
                new_url,
                new_notes,
                if new_is_favorite { 1 } else { 0 },
                now,
                id
            ],
        )?;

        Ok(Account {
            id: id.to_string(),
            platform_id: new_platform_id,
            display_name: new_display_name,
            username: new_username,
            email: new_email,
            password: new_password,
            url: new_url,
            notes: new_notes,
            is_favorite: new_is_favorite,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    /// Deletes an account by ID.
    ///
    /// Custom fields and tag associations are deleted automatically via CASCADE.
    pub fn delete(&self, id: &str) -> Result<()> {
        let conn = self.db.conn()?;
        let affected = conn.execute("DELETE FROM accounts WHERE id = ?1;", params![id])?;
        if affected == 0 {
            return Err(AppError::Database(DatabaseError::NotFound {
                entity: "Account",
                id: id.to_string(),
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::{CreatePlatformParams, PlatformRepository};

    #[test]
    fn test_account_transactional_create_and_cascade_delete() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);
        let tag_repo = TagRepository::new(&db);
        let cf_repo = CustomFieldRepository::new(&db);

        // 1. Setup platform & tag
        let platform = plat_repo
            .create(
                CreatePlatformParams {
                    name: "Amazon".into(),
                    category: Some("Shopping".into()),
                    website: Some("https://amazon.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let tag = tag_repo.create("Shopping", 1000).unwrap();

        // 2. Transactionally create account with custom fields and tags
        let detail = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: platform.id.clone(),
                    display_name: Some("Prime Account".into()),
                    username: Some("prime_user".into()),
                    email: Some("prime@example.com".into()),
                    password: Some("hunter2".into()),
                    url: Some("https://amazon.com".into()),
                    notes: Some("Family account".into()),
                    is_favorite: true,
                    tag_ids: vec![tag.id.clone()],
                    custom_fields: vec![CreateCustomFieldParamsInput {
                        field_name: "Customer ID".into(),
                        field_value: "CUST-999".into(),
                        field_type: Some("text".into()),
                        is_sensitive: Some(false),
                    }],
                },
                1100,
            )
            .unwrap();

        assert_eq!(detail.account.username.as_deref(), Some("prime_user"));
        assert_eq!(detail.tags.len(), 1);
        assert_eq!(detail.tags[0].name, "Shopping");
        assert_eq!(detail.custom_fields.len(), 1);
        assert_eq!(detail.custom_fields[0].field_name, "Customer ID");

        // 3. Test list with filtering
        let list = acc_repo
            .list(ListAccountsFilter {
                platform_id: Some(platform.id.clone()),
                favorite_only: true,
                tag_id: Some(tag.id.clone()),
            })
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].platform_name, "Amazon");

        // 4. Test cascading delete when deleting platform (§15 of database.md)
        plat_repo.delete(&platform.id).unwrap();

        // Account must be gone
        assert!(matches!(
            acc_repo.get_by_id(&detail.account.id),
            Err(AppError::Database(DatabaseError::NotFound { .. }))
        ));

        // Custom fields of the account must also be deleted via cascade
        let cfs = cf_repo.list_by_account(&detail.account.id).unwrap();
        assert!(cfs.is_empty());

        // Account tags associations must also be removed
        let acc_tags = tag_repo.list_by_account(&detail.account.id).unwrap();
        assert!(acc_tags.is_empty());
    }

    #[test]
    fn test_account_creation_rollback_on_invalid_custom_field() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);

        let platform = plat_repo
            .create(
                CreatePlatformParams {
                    name: "Netflix".into(),
                    category: None,
                    website: None,
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        // Provide an invalid custom field (empty name)
        let res = acc_repo.create(
            CreateAccountParams {
                platform_id: platform.id,
                display_name: None,
                username: Some("user".into()),
                email: None,
                password: None,
                url: None,
                notes: None,
                is_favorite: false,
                tag_ids: vec![],
                custom_fields: vec![CreateCustomFieldParamsInput {
                    field_name: "   ".into(),
                    field_value: "val".into(),
                    field_type: None,
                    is_sensitive: None,
                }],
            },
            1100,
        );

        assert!(res.is_err());

        // No accounts must have been inserted
        let list = acc_repo.list(ListAccountsFilter::default()).unwrap();
        assert!(list.is_empty());
    }
}
