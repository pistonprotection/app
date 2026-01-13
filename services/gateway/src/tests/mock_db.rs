//! Mock database utilities for gateway tests

use pistonprotection_proto::backend::Backend;
use pistonprotection_proto::filter::FilterRule;
use std::collections::HashMap;
use std::sync::RwLock;

/// Mock database error type
#[derive(Debug, Clone)]
pub struct MockDbError {
    pub message: String,
}

impl std::fmt::Display for MockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockDbError: {}", self.message)
    }
}

impl std::error::Error for MockDbError {}

/// In-memory mock database for testing
pub struct MockDatabase {
    pub backends: RwLock<HashMap<String, Backend>>,
    pub filter_rules: RwLock<HashMap<String, FilterRule>>,
    /// Map rule_id to backend_id for filtering
    pub rule_to_backend: RwLock<HashMap<String, String>>,
    pub should_fail: RwLock<bool>,
}

impl MockDatabase {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
            filter_rules: RwLock::new(HashMap::new()),
            rule_to_backend: RwLock::new(HashMap::new()),
            should_fail: RwLock::new(false),
        }
    }

    /// Set the database to fail on next operation
    pub fn set_should_fail(&self, fail: bool) {
        *self.should_fail.write().unwrap() = fail;
    }

    fn check_failure(&self) -> Result<(), MockDbError> {
        if *self.should_fail.read().unwrap() {
            Err(MockDbError {
                message: "Simulated database failure".to_string(),
            })
        } else {
            Ok(())
        }
    }

    // Backend operations
    pub fn insert_backend(&self, backend: Backend) -> Result<(), MockDbError> {
        self.check_failure()?;
        self.backends
            .write()
            .unwrap()
            .insert(backend.id.clone(), backend);
        Ok(())
    }

    pub fn get_backend(&self, id: &str) -> Result<Option<Backend>, MockDbError> {
        self.check_failure()?;
        Ok(self.backends.read().unwrap().get(id).cloned())
    }

    pub fn list_backends(&self, org_id: &str) -> Result<Vec<Backend>, MockDbError> {
        self.check_failure()?;
        Ok(self
            .backends
            .read()
            .unwrap()
            .values()
            .filter(|b| b.organization_id == org_id)
            .cloned()
            .collect())
    }

    pub fn update_backend(&self, backend: Backend) -> Result<Option<Backend>, MockDbError> {
        self.check_failure()?;
        let mut backends = self.backends.write().unwrap();
        if backends.contains_key(&backend.id) {
            backends.insert(backend.id.clone(), backend.clone());
            Ok(Some(backend))
        } else {
            Ok(None)
        }
    }

    pub fn delete_backend(&self, id: &str) -> Result<bool, MockDbError> {
        self.check_failure()?;
        Ok(self.backends.write().unwrap().remove(id).is_some())
    }

    // Filter rule operations
    pub fn insert_filter_rule(
        &self,
        rule: FilterRule,
        backend_id: &str,
    ) -> Result<(), MockDbError> {
        self.check_failure()?;
        self.rule_to_backend
            .write()
            .unwrap()
            .insert(rule.id.clone(), backend_id.to_string());
        self.filter_rules
            .write()
            .unwrap()
            .insert(rule.id.clone(), rule);
        Ok(())
    }

    pub fn get_filter_rule(&self, id: &str) -> Result<Option<FilterRule>, MockDbError> {
        self.check_failure()?;
        Ok(self.filter_rules.read().unwrap().get(id).cloned())
    }

    pub fn list_filter_rules(&self, backend_id: &str) -> Result<Vec<FilterRule>, MockDbError> {
        self.check_failure()?;
        let rules = self.filter_rules.read().unwrap();
        let rule_to_backend = self.rule_to_backend.read().unwrap();

        Ok(rules
            .values()
            .filter(|r| rule_to_backend.get(&r.id).map(|s| s.as_str()) == Some(backend_id))
            .cloned()
            .collect())
    }

    pub fn delete_filter_rule(&self, id: &str) -> Result<bool, MockDbError> {
        self.check_failure()?;
        self.rule_to_backend.write().unwrap().remove(id);
        Ok(self.filter_rules.write().unwrap().remove(id).is_some())
    }

    /// Clear all data
    pub fn clear(&self) {
        self.backends.write().unwrap().clear();
        self.filter_rules.write().unwrap().clear();
        self.rule_to_backend.write().unwrap().clear();
    }
}

impl Default for MockDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock cache service for testing
pub struct MockCache {
    data: RwLock<HashMap<String, Vec<u8>>>,
    should_fail: RwLock<bool>,
}

impl MockCache {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            should_fail: RwLock::new(false),
        }
    }

    pub fn set_should_fail(&self, fail: bool) {
        *self.should_fail.write().unwrap() = fail;
    }

    fn check_failure(&self) -> Result<(), MockDbError> {
        if *self.should_fail.read().unwrap() {
            Err(MockDbError {
                message: "Simulated cache failure".to_string(),
            })
        } else {
            Ok(())
        }
    }

    pub fn set(&self, key: &str, value: &[u8]) -> Result<(), MockDbError> {
        self.check_failure()?;
        self.data
            .write()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MockDbError> {
        self.check_failure()?;
        Ok(self.data.read().unwrap().get(key).cloned())
    }

    pub fn delete(&self, key: &str) -> Result<bool, MockDbError> {
        self.check_failure()?;
        Ok(self.data.write().unwrap().remove(key).is_some())
    }

    pub fn exists(&self, key: &str) -> Result<bool, MockDbError> {
        self.check_failure()?;
        Ok(self.data.read().unwrap().contains_key(key))
    }

    pub fn clear(&self) {
        self.data.write().unwrap().clear();
    }
}

impl Default for MockCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a test backend with default values
pub fn create_test_backend(id: &str, org_id: &str, name: &str) -> Backend {
    Backend {
        id: id.to_string(),
        organization_id: org_id.to_string(),
        name: name.to_string(),
        description: format!("Test backend: {}", name),
        r#type: 1, // TCP
        ..Default::default()
    }
}

/// Create a test filter rule with default values
pub fn create_test_filter_rule(id: &str, name: &str) -> FilterRule {
    FilterRule {
        id: id.to_string(),
        name: name.to_string(),
        description: format!("Test rule: {}", name),
        enabled: true,
        priority: 50,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_database_crud_backends() {
        let db = MockDatabase::new();
        let backend = create_test_backend("b1", "org1", "Test Backend");

        // Insert
        db.insert_backend(backend.clone()).unwrap();

        // Get
        let retrieved = db.get_backend("b1").unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Backend");

        // List
        let list = db.list_backends("org1").unwrap();
        assert_eq!(list.len(), 1);

        // Update
        let mut updated_backend = backend.clone();
        updated_backend.name = "Updated Backend".to_string();
        db.update_backend(updated_backend).unwrap();
        let retrieved = db.get_backend("b1").unwrap().unwrap();
        assert_eq!(retrieved.name, "Updated Backend");

        // Delete
        assert!(db.delete_backend("b1").unwrap());
        assert!(db.get_backend("b1").unwrap().is_none());
    }

    #[test]
    fn test_mock_database_crud_filter_rules() {
        let db = MockDatabase::new();
        let rule = create_test_filter_rule("r1", "Test Rule");

        // Insert
        db.insert_filter_rule(rule.clone(), "backend1").unwrap();

        // Get
        let retrieved = db.get_filter_rule("r1").unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Rule");

        // List by backend
        let list = db.list_filter_rules("backend1").unwrap();
        assert_eq!(list.len(), 1);

        let empty_list = db.list_filter_rules("other-backend").unwrap();
        assert_eq!(empty_list.len(), 0);

        // Delete
        assert!(db.delete_filter_rule("r1").unwrap());
        assert!(db.get_filter_rule("r1").unwrap().is_none());
    }

    #[test]
    fn test_mock_database_failure_simulation() {
        let db = MockDatabase::new();
        db.set_should_fail(true);

        let backend = create_test_backend("b1", "org1", "Test Backend");
        let result = db.insert_backend(backend);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_cache_operations() {
        let cache = MockCache::new();

        // Set
        cache.set("key1", b"value1").unwrap();

        // Get
        let value = cache.get("key1").unwrap().unwrap();
        assert_eq!(value, b"value1");

        // Exists
        assert!(cache.exists("key1").unwrap());
        assert!(!cache.exists("key2").unwrap());

        // Delete
        assert!(cache.delete("key1").unwrap());
        assert!(!cache.exists("key1").unwrap());
    }

    #[test]
    fn test_mock_cache_failure_simulation() {
        let cache = MockCache::new();
        cache.set_should_fail(true);

        let result = cache.set("key1", b"value1");
        assert!(result.is_err());
    }
}
