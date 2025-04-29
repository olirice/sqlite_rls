mod policy;
mod error;

pub use error::Error;
pub use policy::{Policy, PolicyManager};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use libsql::Database;
    
    #[tokio::test]
    async fn test_create_policy_parsing() -> Result<()> {
        // Create a temporary in-memory database
        let db = Database::open_in_memory()?;
        let conn = db.connect()?;
        let policy_manager = PolicyManager::new(conn).await?;
        
        // Test a basic CREATE POLICY statement
        let policy_sql = "CREATE POLICY user_policy ON users USING (user_id = current_user_id())";
        let policy = policy_manager.create_policy(policy_sql).await?;
        
        // Verify the parsed policy properties
        assert_eq!(policy.name, "user_policy");
        assert_eq!(policy.table_name, "users");
        assert_eq!(policy.schema_name, None);
        assert_eq!(policy.command, "ALL");
        assert!(policy.using_expr.is_some());
        
        // Test a more complex CREATE POLICY statement
        let policy_sql = "CREATE POLICY admin_policy ON public.documents 
                          FOR SELECT 
                          USING (role = 'admin')
                          WITH CHECK (document_status = 'approved')";
        let policy = policy_manager.create_policy(policy_sql).await?;
        
        // Verify the parsed policy properties
        assert_eq!(policy.name, "admin_policy");
        assert_eq!(policy.table_name, "documents");
        assert_eq!(policy.schema_name, Some("public".to_string()));
        assert_eq!(policy.command, "SELECT");
        assert!(policy.using_expr.is_some());
        assert!(policy.check_expr.is_some());
        
        Ok(())
    }
} 