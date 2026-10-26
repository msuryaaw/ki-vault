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
    /// Master/account password: never serialised to frontend responses by default (api-contract.md §5).
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub logo_id: Option<String>,
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
    pub logo_id: Option<String>,
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
    pub logo_id: Option<String>,
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
    pub logo_id: Option<Option<String>>,
    pub is_favorite: Option<bool>,
}

/// Filters for listing accounts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListAccountsFilter {
    pub platform_id: Option<String>,
    pub favorite_only: bool,
    pub tag_id: Option<String>,
}

/// Optional filters for searching accounts (`api-contract.md` §5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SearchFilters {
    pub platform_id: Option<String>,
    pub tag_id: Option<String>,
    pub category: Option<String>,
    pub favorite_only: Option<bool>,
}

/// Sorting direction / criteria for account queries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    #[default]
    UpdatedAtDesc,
    UpdatedAtAsc,
    TitleAsc,
    TitleDesc,
    CreatedAtDesc,
    CreatedAtAsc,
}

pub struct AccountRepository<'a> {
    db: &'a InMemoryDb,
}

/// Escapes SQLite `LIKE` metacharacters (`\`, `%`, `_`) using `\` as the escape character.
/// The backslash character MUST be escaped first so that subsequent replacements
/// do not produce duplicate escapes.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
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
            "INSERT INTO accounts (id, platform_id, display_name, username, email, password, url, notes, logo_id, is_favorite, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);",
            params![
                account_id,
                params.platform_id,
                params.display_name,
                params.username,
                params.email,
                params.password,
                params.url,
                params.notes,
                params.logo_id,
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
                logo_id: params.logo_id,
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
            "SELECT id, platform_id, display_name, username, email, password, url, notes, logo_id, is_favorite, created_at, updated_at
             FROM accounts WHERE id = ?1;",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let is_fav: i64 = row.get(9)?;
            Ok(Account {
                id: row.get(0)?,
                platform_id: row.get(1)?,
                display_name: row.get(2)?,
                username: row.get(3)?,
                email: row.get(4)?,
                password: row.get(5)?,
                url: row.get(6)?,
                notes: row.get(7)?,
                logo_id: row.get(8)?,
                is_favorite: is_fav != 0,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
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
                    a.display_name, a.username, a.email, a.logo_id, a.is_favorite, a.updated_at
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
            let is_fav: i64 = row.get(7)?;
            Ok(AccountSummary {
                id: row.get(0)?,
                platform_id: row.get(1)?,
                platform_name: row.get(2)?,
                display_name: row.get(3)?,
                username: row.get(4)?,
                email: row.get(5)?,
                logo_id: row.get(6)?,
                is_favorite: is_fav != 0,
                updated_at: row.get(8)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Searches accounts in the in-memory database according to `database.md` §13 and `api-contract.md` §5.
    ///
    /// Searchable fields:
    /// - Platform name (`p.name`)
    /// - Platform category (`p.category`)
    /// - Account display name (`a.display_name`)
    /// - Account username (`a.username`)
    /// - Account email (`a.email`)
    /// - Associated tag names
    ///
    /// Excluded from search: passwords, recovery codes, notes, and custom fields.
    pub fn search(
        &self,
        query_text: &str,
        filters: Option<SearchFilters>,
        sort: Option<SortOrder>,
    ) -> Result<Vec<AccountSummary>> {
        let conn = self.db.conn()?;

        let mut query = String::from(
            "SELECT DISTINCT a.id, a.platform_id, p.name as platform_name,
                    a.display_name, a.username, a.email, a.logo_id, a.is_favorite, a.updated_at, a.created_at
             FROM accounts a
             INNER JOIN platforms p ON a.platform_id = p.id
             LEFT JOIN account_tags at_rel ON a.id = at_rel.account_id
             LEFT JOIN tags t ON at_rel.tag_id = t.id ",
        );

        let mut clauses = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        // 1. Text search across allowed fields
        let trimmed_query = query_text.trim();
        if !trimmed_query.is_empty() {
            let escaped_query = escape_like(trimmed_query);
            let like_pattern = format!("%{escaped_query}%");
            clauses.push(
                "(p.name LIKE ? ESCAPE '\\' OR \
                  p.category LIKE ? ESCAPE '\\' OR \
                  a.display_name LIKE ? ESCAPE '\\' OR \
                  a.username LIKE ? ESCAPE '\\' OR \
                  a.email LIKE ? ESCAPE '\\' OR \
                  t.name LIKE ? ESCAPE '\\')",
            );
            for _ in 0..6 {
                params_vec.push(Box::new(like_pattern.clone()));
            }
        }

        // 2. Filters
        if let Some(f) = filters {
            if let Some(platform_id) = f.platform_id {
                clauses.push("a.platform_id = ?");
                params_vec.push(Box::new(platform_id));
            }

            if let Some(tag_id) = f.tag_id {
                clauses.push("EXISTS (SELECT 1 FROM account_tags at_sub WHERE at_sub.account_id = a.id AND at_sub.tag_id = ?)");
                params_vec.push(Box::new(tag_id));
            }

            if let Some(category) = f.category {
                clauses.push("p.category = ?");
                params_vec.push(Box::new(category));
            }

            if let Some(fav_only) = f.favorite_only {
                if fav_only {
                    clauses.push("a.is_favorite = 1");
                }
            }
        }

        if !clauses.is_empty() {
            query.push_str("WHERE ");
            query.push_str(&clauses.join(" AND "));
        }

        // 3. Sorting
        let order_clause = match sort.unwrap_or_default() {
            SortOrder::UpdatedAtDesc => " ORDER BY a.updated_at DESC, a.id ASC",
            SortOrder::UpdatedAtAsc => " ORDER BY a.updated_at ASC, a.id ASC",
            SortOrder::TitleAsc => {
                " ORDER BY COALESCE(a.display_name, a.username, p.name) ASC, a.id ASC"
            }
            SortOrder::TitleDesc => {
                " ORDER BY COALESCE(a.display_name, a.username, p.name) DESC, a.id ASC"
            }
            SortOrder::CreatedAtDesc => " ORDER BY a.created_at DESC, a.id ASC",
            SortOrder::CreatedAtAsc => " ORDER BY a.created_at ASC, a.id ASC",
        };
        query.push_str(order_clause);
        query.push(';');

        let mut stmt = conn.prepare(&query)?;
        let params_slice: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();

        let rows = stmt.query_map(&params_slice[..], |row| {
            let is_fav: i64 = row.get(7)?;
            Ok(AccountSummary {
                id: row.get(0)?,
                platform_id: row.get(1)?,
                platform_name: row.get(2)?,
                display_name: row.get(3)?,
                username: row.get(4)?,
                email: row.get(5)?,
                logo_id: row.get(6)?,
                is_favorite: is_fav != 0,
                updated_at: row.get(8)?,
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
        let new_logo_id = params.logo_id.unwrap_or(current.logo_id);
        let new_is_favorite = params.is_favorite.unwrap_or(current.is_favorite);

        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE accounts
             SET platform_id = ?1, display_name = ?2, username = ?3, email = ?4,
                 password = ?5, url = ?6, notes = ?7, logo_id = ?8, is_favorite = ?9, updated_at = ?10
             WHERE id = ?11;",
            params![
                new_platform_id,
                new_display_name,
                new_username,
                new_email,
                new_password,
                new_url,
                new_notes,
                new_logo_id,
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
            logo_id: new_logo_id,
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
                    logo_id: None,
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
                logo_id: None,
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

    #[test]
    fn test_account_password_omitted_from_serialization_but_preserved_in_db() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);

        let platform = plat_repo
            .create(
                CreatePlatformParams {
                    name: "SecureService".into(),
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
                    display_name: Some("MyAccount".into()),
                    username: Some("user1".into()),
                    email: Some("u@example.com".into()),
                    password: Some("TopSecretP@ssw0rd!".into()),
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

        // 1. In Rust memory/internal domain model, password is preserved
        assert_eq!(
            detail.account.password.as_deref(),
            Some("TopSecretP@ssw0rd!")
        );

        // 2. In database, password row is persisted
        let conn = db.conn().unwrap();
        let db_password: Option<String> = conn
            .query_row(
                "SELECT password FROM accounts WHERE id = ?1;",
                rusqlite::params![detail.account.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(db_password.as_deref(), Some("TopSecretP@ssw0rd!"));

        // 3. When serialized to JSON (sent over Tauri IPC to frontend), password field is omitted
        let json_detail = serde_json::to_string(&detail).unwrap();
        assert!(
            !json_detail.contains("TopSecretP@ssw0rd!"),
            "Password must never appear in serialized JSON: {json_detail}"
        );
        assert!(
            !json_detail.contains("\"password\""),
            "Password key must not appear in serialized JSON: {json_detail}"
        );

        let json_account = serde_json::to_string(&detail.account).unwrap();
        assert!(
            !json_account.contains("TopSecretP@ssw0rd!"),
            "Password must never appear in serialized Account: {json_account}"
        );
        assert!(
            !json_account.contains("\"password\""),
            "Password key must not appear in serialized Account: {json_account}"
        );
    }

    #[test]
    fn test_account_search_queries_filters_sorting_and_secret_absence() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);
        let tag_repo = TagRepository::new(&db);

        // Setup platform Google (Category: Web) and GitHub (Category: Dev)
        let google = plat_repo
            .create(
                CreatePlatformParams {
                    name: "Google Workspace".into(),
                    category: Some("Productivity".into()),
                    website: Some("https://google.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let github = plat_repo
            .create(
                CreatePlatformParams {
                    name: "GitHub".into(),
                    category: Some("Development".into()),
                    website: Some("https://github.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let tag_work = tag_repo.create("Work", 1000).unwrap();
        let tag_personal = tag_repo.create("Personal", 1000).unwrap();

        // Account 1: Google - user: alice@work.com, tag: Work, fav: true
        acc_repo
            .create(
                CreateAccountParams {
                    platform_id: google.id.clone(),
                    display_name: Some("Alice Work Email".into()),
                    username: Some("alice_corp".into()),
                    email: Some("alice@work.com".into()),
                    password: Some("SuperSecretPassword1!".into()),
                    url: None,
                    notes: Some("Confidential notes here".into()),
                    logo_id: None,
                    is_favorite: true,
                    tag_ids: vec![tag_work.id.clone()],
                    custom_fields: vec![],
                },
                1100,
            )
            .unwrap();

        // Account 2: GitHub - user: octocat, tag: Personal, fav: false
        acc_repo
            .create(
                CreateAccountParams {
                    platform_id: github.id.clone(),
                    display_name: Some("Octocat Profile".into()),
                    username: Some("octocat".into()),
                    email: Some("octocat@github.com".into()),
                    password: Some("SuperSecretPassword2!".into()),
                    url: None,
                    notes: None,
                    logo_id: None,
                    is_favorite: false,
                    tag_ids: vec![tag_personal.id.clone()],
                    custom_fields: vec![],
                },
                1200,
            )
            .unwrap();

        // 1. Text search matching platform name
        let res = acc_repo.search("Google", None, None).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].platform_name, "Google Workspace");

        // 2. Text search matching tag name
        let res = acc_repo.search("Personal", None, None).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].username.as_deref(), Some("octocat"));

        // 3. Text search matching username
        let res = acc_repo.search("alice", None, None).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].email.as_deref(), Some("alice@work.com"));

        // 4. Searching for password or private notes must return 0 results
        let res = acc_repo.search("SuperSecretPassword1", None, None).unwrap();
        assert_eq!(res.len(), 0);
        let res = acc_repo.search("Confidential", None, None).unwrap();
        assert_eq!(res.len(), 0);

        // 5. Search with filters (platform_id and favorite_only)
        let res = acc_repo
            .search(
                "",
                Some(SearchFilters {
                    platform_id: Some(google.id.clone()),
                    tag_id: None,
                    category: None,
                    favorite_only: Some(true),
                }),
                None,
            )
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].display_name.as_deref(), Some("Alice Work Email"));

        // 6. Search with tag filter
        let res = acc_repo
            .search(
                "",
                Some(SearchFilters {
                    platform_id: None,
                    tag_id: Some(tag_work.id.clone()),
                    category: None,
                    favorite_only: None,
                }),
                None,
            )
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].platform_name, "Google Workspace");

        // 7. Search with category filter
        let res = acc_repo
            .search(
                "",
                Some(SearchFilters {
                    platform_id: None,
                    tag_id: None,
                    category: Some("Development".into()),
                    favorite_only: None,
                }),
                None,
            )
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].platform_name, "GitHub");

        // 8. Sorting test
        let res_asc = acc_repo
            .search("", None, Some(SortOrder::TitleAsc))
            .unwrap();
        assert_eq!(res_asc.len(), 2);
        // "Alice Work Email" < "Octocat Profile"
        assert_eq!(res_asc[0].display_name.as_deref(), Some("Alice Work Email"));
        assert_eq!(res_asc[1].display_name.as_deref(), Some("Octocat Profile"));

        let res_desc = acc_repo
            .search("", None, Some(SortOrder::TitleDesc))
            .unwrap();
        assert_eq!(res_desc[0].display_name.as_deref(), Some("Octocat Profile"));
        assert_eq!(
            res_desc[1].display_name.as_deref(),
            Some("Alice Work Email")
        );

        // 9. Verify serialized AccountSummary contains zero secret fields
        let json_summaries = serde_json::to_string(&res).unwrap();
        assert!(!json_summaries.contains("SuperSecretPassword"));
        assert!(!json_summaries.contains("\"password\""));
        assert!(!json_summaries.contains("notes"));
    }

    #[test]
    fn test_account_search_regression_like_escaping_whitespace_email_and_sorting() {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);
        let tag_repo = TagRepository::new(&db);

        // Platform 1: "Acme_Corp" (contains underscore)
        let plat1 = plat_repo
            .create(
                CreatePlatformParams {
                    name: "Acme_Corp".into(),
                    category: Some("Enterprise%Services".into()), // contains percent
                    website: Some("https://acme.example.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        // Platform 2: "AcmeXCorp" (matches wildcard Acme_Corp if not escaped)
        let plat2 = plat_repo
            .create(
                CreatePlatformParams {
                    name: "AcmeXCorp".into(),
                    category: Some("EnterpriseXServices".into()),
                    website: Some("https://acmex.example.com".into()),
                    logo_id: None,
                },
                2000,
            )
            .unwrap();

        let tag_special = tag_repo.create("Tag\\Backslash", 1000).unwrap();
        let tag_normal = tag_repo.create("TagXBackslash", 2000).unwrap();

        // Account 1 (created_at = 1000)
        let acc1 = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: plat1.id.clone(),
                    display_name: Some("User 100% Legit".into()), // contains %
                    username: Some("user_special\\admin".into()), // contains _ and \
                    email: Some("audit_test@special.corp".into()),
                    password: Some("HiddenPassword123!".into()),
                    url: None,
                    notes: Some("Top secret internal note".into()),
                    logo_id: None,
                    is_favorite: true,
                    tag_ids: vec![tag_special.id.clone()],
                    custom_fields: vec![],
                },
                1000,
            )
            .unwrap();

        // Account 2 (created_at = 2000)
        let acc2 = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: plat2.id.clone(),
                    display_name: Some("User 100X Legit".into()),
                    username: Some("userXspecialXadmin".into()),
                    email: Some("normal.user@other.corp".into()),
                    password: Some("AnotherSecret456!".into()),
                    url: None,
                    notes: None,
                    logo_id: None,
                    is_favorite: false,
                    tag_ids: vec![tag_normal.id.clone()],
                    custom_fields: vec![],
                },
                2000,
            )
            .unwrap();

        // Account 3: Identical timestamp as Account 2 for tie-breaking test (created_at = 2000)
        let acc3 = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: plat2.id.clone(),
                    display_name: Some("Alpha User Same Time".into()),
                    username: Some("alpha_same".into()),
                    email: Some("alpha@other.corp".into()),
                    password: Some("ThirdSecret789!".into()),
                    url: None,
                    notes: None,
                    logo_id: None,
                    is_favorite: false,
                    tag_ids: vec![],
                    custom_fields: vec![],
                },
                2000,
            )
            .unwrap();

        // --- 1. Literal LIKE Escaping: Underscore '_' ---
        // Searching for "_" must match only acc1 ("Acme_Corp", "user_special\admin", "audit_test@special.corp", "alpha_same"), NOT acc2!
        let res_underscore = acc_repo.search("Acme_Corp", None, None).unwrap();
        assert_eq!(
            res_underscore.len(),
            1,
            "Expected exactly 1 result matching literal 'Acme_Corp'"
        );
        assert_eq!(res_underscore[0].id, acc1.account.id);

        let res_no_match_underscore = acc_repo.search("Acme_None", None, None).unwrap();
        assert_eq!(res_no_match_underscore.len(), 0);

        // --- 2. Literal LIKE Escaping: Percent '%' ---
        // Searching for "100%" must match only acc1 ("User 100% Legit"), NOT acc2 ("User 100X Legit")
        let res_percent = acc_repo.search("100%", None, None).unwrap();
        assert_eq!(
            res_percent.len(),
            1,
            "Expected exactly 1 result matching literal '100%'"
        );
        assert_eq!(res_percent[0].id, acc1.account.id);

        let res_category_percent = acc_repo.search("Enterprise%Services", None, None).unwrap();
        assert_eq!(res_category_percent.len(), 1);
        assert_eq!(res_category_percent[0].id, acc1.account.id);

        // --- 3. Literal LIKE Escaping: Backslash '\' ---
        // Searching for "\\" must match only acc1 ("user_special\admin" or "Tag\Backslash")
        let res_backslash = acc_repo.search("\\", None, None).unwrap();
        assert_eq!(
            res_backslash.len(),
            1,
            "Expected exactly 1 result containing literal backslash"
        );
        assert_eq!(res_backslash[0].id, acc1.account.id);

        // --- 4. Whitespace-only query ---
        // Whitespace query ("   ") should be treated as empty query and return all 3 accounts
        let res_whitespace = acc_repo.search("   \t  \n ", None, None).unwrap();
        assert_eq!(
            res_whitespace.len(),
            3,
            "Whitespace-only query should return all accounts"
        );

        // --- 5. Search by Email ---
        let res_email = acc_repo
            .search("audit_test@special.corp", None, None)
            .unwrap();
        assert_eq!(res_email.len(), 1);
        assert_eq!(res_email[0].id, acc1.account.id);
        assert_eq!(
            res_email[0].email.as_deref(),
            Some("audit_test@special.corp")
        );

        let res_email_domain = acc_repo.search("@other.corp", None, None).unwrap();
        assert_eq!(
            res_email_domain.len(),
            2,
            "Should match both acc2 and acc3 having @other.corp"
        );

        // --- 6. Combination of Text Query and Filters ---
        // Text query matches acc1 ("Legit"), but filter platform_id is plat2 -> 0 results
        let res_filtered_out = acc_repo
            .search(
                "Legit",
                Some(SearchFilters {
                    platform_id: Some(plat2.id.clone()),
                    tag_id: None,
                    category: None,
                    favorite_only: None,
                }),
                None,
            )
            .unwrap();
        // acc2 matches "Legit" ("User 100X Legit") and has plat2, but acc1 has plat1
        assert_eq!(res_filtered_out.len(), 1);
        assert_eq!(res_filtered_out[0].id, acc2.account.id);

        // Text query "Legit" + favorite_only=true -> only acc1 is favorite
        let res_fav_combo = acc_repo
            .search(
                "Legit",
                Some(SearchFilters {
                    platform_id: None,
                    tag_id: None,
                    category: None,
                    favorite_only: Some(true),
                }),
                None,
            )
            .unwrap();
        assert_eq!(res_fav_combo.len(), 1);
        assert_eq!(res_fav_combo[0].id, acc1.account.id);

        // --- 7. CreatedAtAsc and CreatedAtDesc Sorting with Tie-breaking ---
        let res_created_asc = acc_repo
            .search("", None, Some(SortOrder::CreatedAtAsc))
            .unwrap();
        assert_eq!(res_created_asc.len(), 3);
        // acc1 was created at 1000, acc2 & acc3 created at 2000
        assert_eq!(res_created_asc[0].id, acc1.account.id);
        // For identical timestamps (acc2 & acc3), tie-break is `a.id ASC`
        if acc2.account.id < acc3.account.id {
            assert_eq!(res_created_asc[1].id, acc2.account.id);
            assert_eq!(res_created_asc[2].id, acc3.account.id);
        } else {
            assert_eq!(res_created_asc[1].id, acc3.account.id);
            assert_eq!(res_created_asc[2].id, acc2.account.id);
        }

        let res_created_desc = acc_repo
            .search("", None, Some(SortOrder::CreatedAtDesc))
            .unwrap();
        assert_eq!(res_created_desc.len(), 3);
        // acc1 must be last
        assert_eq!(res_created_desc[2].id, acc1.account.id);
        // Between acc2 and acc3 (created_at = 2000), tie-break is `a.id ASC`
        if acc2.account.id < acc3.account.id {
            assert_eq!(res_created_desc[0].id, acc2.account.id);
            assert_eq!(res_created_desc[1].id, acc3.account.id);
        } else {
            assert_eq!(res_created_desc[0].id, acc3.account.id);
            assert_eq!(res_created_desc[1].id, acc2.account.id);
        }

        // --- 8. Security verification: secret fields not searchable or returned ---
        assert_eq!(
            acc_repo
                .search("HiddenPassword123", None, None)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            acc_repo
                .search("AnotherSecret456", None, None)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            acc_repo
                .search("Top secret internal note", None, None)
                .unwrap()
                .len(),
            0
        );
    }
}
