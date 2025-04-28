use anyhow::Result;
use libsql::Database;
use libsql_rls::prelude::*;
use libsql_rls::parser::RlsOperation;
use libsql_rls::policy::{Policy, PolicyManager};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize in-memory database
    let db = Database::open("file::memory:?mode=memory&cache=shared")?;
    let conn = db.connect()?;
    
    // Initialize RLS extension
    let rls = RlsExtension::new(db.clone());
    rls.initialize().await?;
    
    println!("Creating example schema...");
    
    // Create a simple schema
    conn.execute(
        "CREATE TABLE departments (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )",
        (),
    ).await?;
    
    conn.execute(
        "CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            department_id INTEGER NOT NULL,
            salary INTEGER NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )",
        (),
    ).await?;
    
    // Insert sample data
    conn.execute(
        "INSERT INTO departments (id, name) VALUES
            (1, 'Engineering'),
            (2, 'Marketing'),
            (3, 'HR')",
        (),
    ).await?;
    
    conn.execute(
        "INSERT INTO employees (id, name, department_id, salary) VALUES
            (1, 'Alice', 1, 100000),
            (2, 'Bob', 1, 90000),
            (3, 'Charlie', 2, 80000),
            (4, 'Diana', 2, 85000),
            (5, 'Eve', 3, 75000)",
        (),
    ).await?;
    
    // Set up current user for RLS context
    conn.execute(
        "CREATE TABLE _rls_current_user (
            user_id TEXT NOT NULL,
            department_id INTEGER,
            is_manager BOOLEAN
        )",
        (),
    ).await?;
    
    conn.execute(
        "INSERT INTO _rls_current_user (user_id, department_id, is_manager) 
         VALUES ('alice', 1, true)",
        (),
    ).await?;
    
    // Create helper functions for policies
    conn.execute(
        "CREATE FUNCTION current_user()
         RETURNS TEXT
         AS 'SELECT user_id FROM _rls_current_user LIMIT 1'",
        (),
    ).await?;
    
    conn.execute(
        "CREATE FUNCTION user_department()
         RETURNS INTEGER
         AS 'SELECT department_id FROM _rls_current_user LIMIT 1'",
        (),
    ).await?;
    
    conn.execute(
        "CREATE FUNCTION is_manager()
         RETURNS BOOLEAN
         AS 'SELECT is_manager FROM _rls_current_user LIMIT 1'",
        (),
    ).await?;
    
    // Enable RLS on employees table
    println!("Enabling Row Level Security on employees table...");
    let policy_manager = PolicyManager::new(db.clone());
    policy_manager.set_rls_enabled("employees", true).await?;
    
    // Create a department policy
    println!("Creating department policy: users can only see employees in their department");
    let dept_policy = Policy::new(
        "employees_department_policy",
        "employees",
        RlsOperation::Select,
        Some("department_id = user_department()".to_string()),
        None,
    );
    
    policy_manager.create_policy(&dept_policy).await?;
    
    // Query as Alice (department 1)
    println!("\nQuerying as Alice (Engineering department, manager):");
    let rows = conn.query_all("SELECT id, name, department_id, salary FROM employees", ())
        .await?;
    
    println!("| ID | Name     | Department | Salary  |");
    println!("|----+----------+------------+---------|");
    for row in rows {
        println!("| {} | {} | {} | {} |", 
               row.get::<i64>(0)?, 
               row.get::<String>(1)?, 
               row.get::<i64>(2)?, 
               row.get::<i64>(3)?);
    }
    
    // Change user to Charlie (department 2)
    println!("\nChanging user to Charlie (Marketing department)...");
    conn.execute("DELETE FROM _rls_current_user", ()).await?;
    conn.execute(
        "INSERT INTO _rls_current_user (user_id, department_id, is_manager) 
         VALUES ('charlie', 2, false)",
        (),
    ).await?;
    
    // Query as Charlie
    println!("Querying as Charlie (Marketing department):");
    let rows = conn.query_all("SELECT id, name, department_id, salary FROM employees", ())
        .await?;
    
    println!("| ID | Name     | Department | Salary  |");
    println!("|----+----------+------------+---------|");
    for row in rows {
        println!("| {} | {} | {} | {} |", 
               row.get::<i64>(0)?, 
               row.get::<String>(1)?, 
               row.get::<i64>(2)?, 
               row.get::<i64>(3)?);
    }
    
    // Add a manager policy that allows managers to see all employees
    println!("\nAdding manager policy: managers can see all employees");
    let manager_policy = Policy::new(
        "employees_manager_policy",
        "employees",
        RlsOperation::Select,
        Some("is_manager() = true".to_string()),
        None,
    );
    
    policy_manager.create_policy(&manager_policy).await?;
    
    // Make Charlie a manager and query again
    println!("\nMaking Charlie a manager and querying again...");
    conn.execute("DELETE FROM _rls_current_user", ()).await?;
    conn.execute(
        "INSERT INTO _rls_current_user (user_id, department_id, is_manager) 
         VALUES ('charlie', 2, true)",
        (),
    ).await?;
    
    let rows = conn.query_all("SELECT id, name, department_id, salary FROM employees", ())
        .await?;
    
    println!("| ID | Name     | Department | Salary  |");
    println!("|----+----------+------------+---------|");
    for row in rows {
        println!("| {} | {} | {} | {} |", 
               row.get::<i64>(0)?, 
               row.get::<String>(1)?, 
               row.get::<i64>(2)?, 
               row.get::<i64>(3)?);
    }
    
    // Disable RLS and query again
    println!("\nDisabling RLS and querying again...");
    policy_manager.set_rls_enabled("employees", false).await?;
    
    let rows = conn.query_all("SELECT id, name, department_id, salary FROM employees", ())
        .await?;
    
    println!("| ID | Name     | Department | Salary  |");
    println!("|----+----------+------------+---------|");
    for row in rows {
        println!("| {} | {} | {} | {} |", 
               row.get::<i64>(0)?, 
               row.get::<String>(1)?, 
               row.get::<i64>(2)?, 
               row.get::<i64>(3)?);
    }
    
    println!("\nExample completed successfully!");
    Ok(())
} 