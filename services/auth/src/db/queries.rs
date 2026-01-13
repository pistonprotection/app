//! Database queries for the auth service

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;

use crate::models::*;

// ============================================================================
// User Queries
// ============================================================================

/// Create a new user
pub async fn create_user(
    pool: &PgPool,
    id: &str,
    email: &str,
    username: &str,
    name: &str,
    password_hash: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, email, username, name, password_hash, avatar_url)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(email)
    .bind(username)
    .bind(name)
    .bind(password_hash)
    .bind(avatar_url)
    .fetch_one(pool)
    .await
}

/// Get user by ID
pub async fn get_user_by_id(pool: &PgPool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Get user by email
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

/// Get user by username
pub async fn get_user_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE username = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

/// Update user
pub async fn update_user(
    pool: &PgPool,
    id: &str,
    email: Option<&str>,
    username: Option<&str>,
    name: Option<&str>,
    avatar_url: Option<&str>,
    role: Option<UserRole>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET
            email = COALESCE($2, email),
            username = COALESCE($3, username),
            name = COALESCE($4, name),
            avatar_url = COALESCE($5, avatar_url),
            role = COALESCE($6, role),
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(email)
    .bind(username)
    .bind(name)
    .bind(avatar_url)
    .bind(role)
    .fetch_one(pool)
    .await
}

/// Soft delete user
pub async fn delete_user(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Update user password
pub async fn update_user_password(
    pool: &PgPool,
    id: &str,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(password_hash)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update user last login
pub async fn update_user_last_login(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Verify user email
pub async fn verify_user_email(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// List users with pagination
pub async fn list_users(
    pool: &PgPool,
    page: u32,
    page_size: u32,
) -> Result<(Vec<User>, u32), sqlx::Error> {
    let offset = (page.saturating_sub(1)) * page_size;

    let users = sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(page_size as i32)
    .bind(offset as i32)
    .fetch_all(pool)
    .await?;

    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM users WHERE deleted_at IS NULL
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok((users, count.0 as u32))
}

// ============================================================================
// Organization Queries
// ============================================================================

/// Create a new organization
pub async fn create_organization(
    pool: &PgPool,
    id: &str,
    name: &str,
    slug: &str,
    logo_url: Option<&str>,
) -> Result<Organization, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        r#"
        INSERT INTO organizations (id, name, slug, logo_url)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .bind(logo_url)
    .fetch_one(pool)
    .await
}

/// Get organization by ID
pub async fn get_organization_by_id(
    pool: &PgPool,
    id: &str,
) -> Result<Option<Organization>, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        r#"
        SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Get organization by slug
pub async fn get_organization_by_slug(
    pool: &PgPool,
    slug: &str,
) -> Result<Option<Organization>, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        r#"
        SELECT * FROM organizations WHERE slug = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(slug)
    .fetch_optional(pool)
    .await
}

/// Update organization
pub async fn update_organization(
    pool: &PgPool,
    id: &str,
    name: Option<&str>,
    slug: Option<&str>,
    logo_url: Option<&str>,
) -> Result<Organization, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET
            name = COALESCE($2, name),
            slug = COALESCE($3, slug),
            logo_url = COALESCE($4, logo_url),
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .bind(logo_url)
    .fetch_one(pool)
    .await
}

/// Delete organization
pub async fn delete_organization(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE organizations SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List organizations for a user
pub async fn list_user_organizations(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<Organization>, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        r#"
        SELECT o.* FROM organizations o
        INNER JOIN organization_members om ON o.id = om.organization_id
        WHERE om.user_id = $1 AND o.deleted_at IS NULL
        ORDER BY o.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

// ============================================================================
// Organization Member Queries
// ============================================================================

/// Add member to organization
pub async fn add_organization_member(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    organization_id: &str,
    role: OrganizationRole,
) -> Result<OrganizationMember, sqlx::Error> {
    sqlx::query_as::<_, OrganizationMember>(
        r#"
        INSERT INTO organization_members (id, user_id, organization_id, role, joined_at)
        VALUES ($1, $2, $3, $4, NOW())
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(organization_id)
    .bind(role)
    .fetch_one(pool)
    .await
}

/// Get organization member
pub async fn get_organization_member(
    pool: &PgPool,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<OrganizationMember>, sqlx::Error> {
    sqlx::query_as::<_, OrganizationMember>(
        r#"
        SELECT * FROM organization_members
        WHERE organization_id = $1 AND user_id = $2
        "#,
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Update organization member role
pub async fn update_organization_member_role(
    pool: &PgPool,
    organization_id: &str,
    user_id: &str,
    role: OrganizationRole,
) -> Result<OrganizationMember, sqlx::Error> {
    sqlx::query_as::<_, OrganizationMember>(
        r#"
        UPDATE organization_members
        SET role = $3, updated_at = NOW()
        WHERE organization_id = $1 AND user_id = $2
        RETURNING *
        "#,
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(role)
    .fetch_one(pool)
    .await
}

/// Remove member from organization
pub async fn remove_organization_member(
    pool: &PgPool,
    organization_id: &str,
    user_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM organization_members
        WHERE organization_id = $1 AND user_id = $2
        "#,
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List organization members
pub async fn list_organization_members(
    pool: &PgPool,
    organization_id: &str,
    page: u32,
    page_size: u32,
) -> Result<(Vec<OrganizationMember>, u32), sqlx::Error> {
    let offset = (page.saturating_sub(1)) * page_size;

    let members = sqlx::query_as::<_, OrganizationMember>(
        r#"
        SELECT * FROM organization_members
        WHERE organization_id = $1
        ORDER BY joined_at
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(organization_id)
    .bind(page_size as i32)
    .bind(offset as i32)
    .fetch_all(pool)
    .await?;

    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM organization_members WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;

    Ok((members, count.0 as u32))
}

// ============================================================================
// Session Queries
// ============================================================================

/// Create a session
pub async fn create_session(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    token_hash: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    device_type: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<Session, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, device_type, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(ip_address)
    .bind(user_agent)
    .bind(device_type)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Get session by token hash
pub async fn get_session_by_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        r#"
        SELECT * FROM sessions
        WHERE token_hash = $1 AND active = TRUE AND expires_at > NOW()
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Update session last active
pub async fn update_session_last_active(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions SET last_active_at = NOW() WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Invalidate session
pub async fn invalidate_session(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions SET active = FALSE WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Invalidate all user sessions
pub async fn invalidate_user_sessions(pool: &PgPool, user_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE sessions SET active = FALSE WHERE user_id = $1 AND active = TRUE
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// List user sessions
pub async fn list_user_sessions(pool: &PgPool, user_id: &str) -> Result<Vec<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        r#"
        SELECT * FROM sessions
        WHERE user_id = $1 AND active = TRUE AND expires_at > NOW()
        ORDER BY last_active_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Count active user sessions
pub async fn count_active_sessions(pool: &PgPool, user_id: &str) -> Result<i64, sqlx::Error> {
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM sessions
        WHERE user_id = $1 AND active = TRUE AND expires_at > NOW()
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0)
}

// ============================================================================
// API Key Queries
// ============================================================================

/// Create an API key
pub async fn create_api_key(
    pool: &PgPool,
    id: &str,
    organization_id: &str,
    created_by_user_id: &str,
    name: &str,
    prefix: &str,
    key_hash: &str,
    permissions: &[String],
    allowed_ips: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> Result<ApiKey, sqlx::Error> {
    sqlx::query_as::<_, ApiKey>(
        r#"
        INSERT INTO api_keys (id, organization_id, created_by_user_id, name, prefix, key_hash, permissions, allowed_ips, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::JSONB, $8::JSONB, $9)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(organization_id)
    .bind(created_by_user_id)
    .bind(name)
    .bind(prefix)
    .bind(key_hash)
    .bind(serde_json::to_value(permissions).unwrap())
    .bind(serde_json::to_value(allowed_ips).unwrap())
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Get API key by hash
pub async fn get_api_key_by_hash(
    pool: &PgPool,
    key_hash: &str,
) -> Result<Option<ApiKey>, sqlx::Error> {
    sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys
        WHERE key_hash = $1 AND enabled = TRUE
        AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await
}

/// Get API key by ID
pub async fn get_api_key_by_id(pool: &PgPool, id: &str) -> Result<Option<ApiKey>, sqlx::Error> {
    sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Update API key last used
pub async fn update_api_key_last_used(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Revoke API key
pub async fn revoke_api_key(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE api_keys SET enabled = FALSE, updated_at = NOW() WHERE id = $1 AND enabled = TRUE
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List organization API keys
pub async fn list_api_keys(
    pool: &PgPool,
    organization_id: &str,
    page: u32,
    page_size: u32,
) -> Result<(Vec<ApiKey>, u32), sqlx::Error> {
    let offset = (page.saturating_sub(1)) * page_size;

    let keys = sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(organization_id)
    .bind(page_size as i32)
    .bind(offset as i32)
    .fetch_all(pool)
    .await?;

    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM api_keys WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;

    Ok((keys, count.0 as u32))
}

// ============================================================================
// Invitation Queries
// ============================================================================

/// Create an invitation
pub async fn create_invitation(
    pool: &PgPool,
    id: &str,
    organization_id: &str,
    email: &str,
    role: OrganizationRole,
    invited_by_user_id: &str,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<Invitation, sqlx::Error> {
    sqlx::query_as::<_, Invitation>(
        r#"
        INSERT INTO invitations (id, organization_id, email, role, invited_by_user_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(organization_id)
    .bind(email)
    .bind(role)
    .bind(invited_by_user_id)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Get invitation by token hash
pub async fn get_invitation_by_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Invitation>, sqlx::Error> {
    sqlx::query_as::<_, Invitation>(
        r#"
        SELECT * FROM invitations
        WHERE token_hash = $1 AND status = 'pending' AND expires_at > NOW()
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Accept invitation
pub async fn accept_invitation(pool: &PgPool, id: &str) -> Result<Invitation, sqlx::Error> {
    sqlx::query_as::<_, Invitation>(
        r#"
        UPDATE invitations
        SET status = 'accepted', accepted_at = NOW(), updated_at = NOW()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
}

/// Revoke invitation
pub async fn revoke_invitation(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE invitations
        SET status = 'revoked', updated_at = NOW()
        WHERE id = $1 AND status = 'pending'
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List organization invitations
pub async fn list_invitations(
    pool: &PgPool,
    organization_id: &str,
    status: Option<InvitationStatus>,
    page: u32,
    page_size: u32,
) -> Result<(Vec<Invitation>, u32), sqlx::Error> {
    let offset = (page.saturating_sub(1)) * page_size;

    let invitations = if let Some(s) = status {
        sqlx::query_as::<_, Invitation>(
            r#"
            SELECT * FROM invitations
            WHERE organization_id = $1 AND status = $4
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(organization_id)
        .bind(page_size as i32)
        .bind(offset as i32)
        .bind(s)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Invitation>(
            r#"
            SELECT * FROM invitations
            WHERE organization_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(organization_id)
        .bind(page_size as i32)
        .bind(offset as i32)
        .fetch_all(pool)
        .await?
    };

    let count: (i64,) = if status.is_some() {
        sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM invitations WHERE organization_id = $1 AND status = $2
            "#,
        )
        .bind(organization_id)
        .bind(status)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM invitations WHERE organization_id = $1
            "#,
        )
        .bind(organization_id)
        .fetch_one(pool)
        .await?
    };

    Ok((invitations, count.0 as u32))
}

// ============================================================================
// Audit Log Queries
// ============================================================================

/// Create audit log entry
pub async fn create_audit_log(
    pool: &PgPool,
    id: &str,
    organization_id: &str,
    user_id: Option<&str>,
    user_email: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    description: &str,
    metadata: &HashMap<String, String>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuditLogEntry, sqlx::Error> {
    sqlx::query_as::<_, AuditLogEntry>(
        r#"
        INSERT INTO audit_logs (id, organization_id, user_id, user_email, action, resource_type, resource_id, description, metadata, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::JSONB, $10, $11)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(organization_id)
    .bind(user_id)
    .bind(user_email)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(description)
    .bind(serde_json::to_value(metadata).unwrap())
    .bind(ip_address)
    .bind(user_agent)
    .fetch_one(pool)
    .await
}

/// List audit logs with filters
pub async fn list_audit_logs(
    pool: &PgPool,
    filter: &AuditLogFilter,
    page: u32,
    page_size: u32,
) -> Result<(Vec<AuditLogEntry>, u32), sqlx::Error> {
    let offset = (page.saturating_sub(1)) * page_size;

    // Build dynamic query based on filters
    let mut query = String::from("SELECT * FROM audit_logs WHERE organization_id = $1");
    let mut count_query =
        String::from("SELECT COUNT(*) FROM audit_logs WHERE organization_id = $1");

    let mut param_idx = 2;
    let mut conditions = Vec::new();

    if filter.user_id.is_some() {
        conditions.push(format!("user_id = ${}", param_idx));
        param_idx += 1;
    }
    if filter.resource_type.is_some() {
        conditions.push(format!("resource_type = ${}", param_idx));
        param_idx += 1;
    }
    if filter.action.is_some() {
        conditions.push(format!("action = ${}", param_idx));
        param_idx += 1;
    }
    if filter.start_time.is_some() {
        conditions.push(format!("timestamp >= ${}", param_idx));
        param_idx += 1;
    }
    if filter.end_time.is_some() {
        conditions.push(format!("timestamp <= ${}", param_idx));
        param_idx += 1;
    }

    for cond in &conditions {
        query.push_str(&format!(" AND {}", cond));
        count_query.push_str(&format!(" AND {}", cond));
    }

    query.push_str(&format!(
        " ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
        param_idx,
        param_idx + 1
    ));

    // For simplicity, we'll use a simpler approach with optional bindings
    let entries = sqlx::query_as::<_, AuditLogEntry>(
        r#"
        SELECT * FROM audit_logs
        WHERE organization_id = $1
        AND ($2::VARCHAR IS NULL OR user_id = $2)
        AND ($3::VARCHAR IS NULL OR resource_type = $3)
        AND ($4::VARCHAR IS NULL OR action = $4)
        AND ($5::TIMESTAMPTZ IS NULL OR timestamp >= $5)
        AND ($6::TIMESTAMPTZ IS NULL OR timestamp <= $6)
        ORDER BY timestamp DESC
        LIMIT $7 OFFSET $8
        "#,
    )
    .bind(&filter.organization_id)
    .bind(&filter.user_id)
    .bind(&filter.resource_type)
    .bind(&filter.action)
    .bind(filter.start_time)
    .bind(filter.end_time)
    .bind(page_size as i32)
    .bind(offset as i32)
    .fetch_all(pool)
    .await?;

    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM audit_logs
        WHERE organization_id = $1
        AND ($2::VARCHAR IS NULL OR user_id = $2)
        AND ($3::VARCHAR IS NULL OR resource_type = $3)
        AND ($4::VARCHAR IS NULL OR action = $4)
        AND ($5::TIMESTAMPTZ IS NULL OR timestamp >= $5)
        AND ($6::TIMESTAMPTZ IS NULL OR timestamp <= $6)
        "#,
    )
    .bind(&filter.organization_id)
    .bind(&filter.user_id)
    .bind(&filter.resource_type)
    .bind(&filter.action)
    .bind(filter.start_time)
    .bind(filter.end_time)
    .fetch_one(pool)
    .await?;

    Ok((entries, count.0 as u32))
}

// ============================================================================
// Organization Limits and Usage Queries
// ============================================================================

/// Create organization limits
pub async fn create_organization_limits(
    pool: &PgPool,
    id: &str,
    organization_id: &str,
) -> Result<OrganizationLimits, sqlx::Error> {
    sqlx::query_as::<_, OrganizationLimits>(
        r#"
        INSERT INTO organization_limits (id, organization_id)
        VALUES ($1, $2)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(organization_id)
    .fetch_one(pool)
    .await
}

/// Get organization limits
pub async fn get_organization_limits(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Option<OrganizationLimits>, sqlx::Error> {
    sqlx::query_as::<_, OrganizationLimits>(
        r#"
        SELECT * FROM organization_limits WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
}

/// Create organization usage
pub async fn create_organization_usage(
    pool: &PgPool,
    id: &str,
    organization_id: &str,
) -> Result<OrganizationUsage, sqlx::Error> {
    sqlx::query_as::<_, OrganizationUsage>(
        r#"
        INSERT INTO organization_usage (id, organization_id)
        VALUES ($1, $2)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(organization_id)
    .fetch_one(pool)
    .await
}

/// Get organization usage
pub async fn get_organization_usage(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Option<OrganizationUsage>, sqlx::Error> {
    sqlx::query_as::<_, OrganizationUsage>(
        r#"
        SELECT * FROM organization_usage WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
}

/// Get organization subscription
pub async fn get_organization_subscription(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Option<Subscription>, sqlx::Error> {
    sqlx::query_as::<_, Subscription>(
        r#"
        SELECT * FROM subscriptions WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
}
