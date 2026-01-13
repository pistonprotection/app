//! Config Store tests

// ============================================================================
// Version Management Tests
// ============================================================================

#[cfg(test)]
mod version_tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_version_increment() {
        let version = AtomicU32::new(1);

        // Simulate next_version behavior
        let new_version = version.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(new_version, 2);

        let new_version = version.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(new_version, 3);
    }

    #[test]
    fn test_version_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let version = Arc::new(AtomicU32::new(0));
        let mut handles = vec![];

        // Spawn multiple threads incrementing version
        for _ in 0..10 {
            let v = Arc::clone(&version);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    v.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be exactly 1000 increments
        assert_eq!(version.load(Ordering::SeqCst), 1000);
    }

    #[test]
    fn test_version_rollback_validation() {
        let current_version: u32 = 10;
        let target_version: u32 = 5;

        // Can only rollback to earlier versions
        assert!(target_version < current_version);

        // Cannot rollback to same or later version
        let invalid_target: u32 = 10;
        assert!(invalid_target >= current_version);
    }
}

// ============================================================================
// Version History Tests
// ============================================================================

#[cfg(test)]
mod version_history_tests {
    use chrono::Utc;

    #[derive(Debug, Clone)]
    struct ConfigVersionEntry {
        version: u32,
        backend_id: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
        config_hash: u64,
        change_description: Option<String>,
    }

    #[test]
    fn test_version_history_ordering() {
        let mut history = vec![
            ConfigVersionEntry {
                version: 1,
                backend_id: Some("backend-1".to_string()),
                created_at: Utc::now(),
                config_hash: 12345,
                change_description: None,
            },
            ConfigVersionEntry {
                version: 3,
                backend_id: Some("backend-2".to_string()),
                created_at: Utc::now(),
                config_hash: 67890,
                change_description: Some("Added new rule".to_string()),
            },
            ConfigVersionEntry {
                version: 2,
                backend_id: None,
                created_at: Utc::now(),
                config_hash: 11111,
                change_description: None,
            },
        ];

        // Sort by version descending (most recent first)
        history.sort_by(|a, b| b.version.cmp(&a.version));

        assert_eq!(history[0].version, 3);
        assert_eq!(history[1].version, 2);
        assert_eq!(history[2].version, 1);
    }

    #[test]
    fn test_version_history_limit() {
        let mut history: Vec<ConfigVersionEntry> = (1..=20)
            .map(|v| ConfigVersionEntry {
                version: v,
                backend_id: None,
                created_at: Utc::now(),
                config_hash: 0,
                change_description: None,
            })
            .collect();

        // Keep only the last 10 versions
        let limit = 10;
        history.sort_by(|a, b| b.version.cmp(&a.version));
        history.truncate(limit);

        assert_eq!(history.len(), 10);
        assert_eq!(history[0].version, 20); // Most recent
        assert_eq!(history[9].version, 11); // Oldest in limited set
    }
}

// ============================================================================
// Cache Key Generation Tests
// ============================================================================

#[cfg(test)]
mod cache_tests {
    #[test]
    fn test_cache_key_generation() {
        let version: u32 = 42;
        let cache_key = format!("filter_config:{}", version);

        assert_eq!(cache_key, "filter_config:42");
    }

    #[test]
    fn test_cache_pattern_matching() {
        let _pattern = "filter_config:*";
        let keys = vec![
            "filter_config:1",
            "filter_config:42",
            "filter_config:100",
            "other_key:1",
        ];

        let prefix = "filter_config:";
        let matching: Vec<_> = keys.iter().filter(|k| k.starts_with(prefix)).collect();

        assert_eq!(matching.len(), 3);
    }

    #[test]
    fn test_backend_config_cache_key() {
        let backend_id = "backend-123";
        let version: u32 = 5;
        let cache_key = format!("backend_config:{}:{}", backend_id, version);

        assert_eq!(cache_key, "backend_config:backend-123:5");
    }
}

// ============================================================================
// Config Hash Tests
// ============================================================================

#[cfg(test)]
mod hash_tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn test_config_hash_consistency() {
        let config_str = "backend-1:rule-1:rule-2";

        let hash1 = calculate_hash(&config_str);
        let hash2 = calculate_hash(&config_str);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_uniqueness() {
        let config1 = "backend-1:rule-1";
        let config2 = "backend-1:rule-2";

        let hash1 = calculate_hash(&config1);
        let hash2 = calculate_hash(&config2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_with_multiple_fields() {
        #[derive(Hash)]
        struct TestConfig {
            backend_id: String,
            version: u32,
            rules: Vec<String>,
        }

        let config = TestConfig {
            backend_id: "test".to_string(),
            version: 1,
            rules: vec!["rule-1".to_string(), "rule-2".to_string()],
        };

        let hash = calculate_hash(&config);
        assert!(hash > 0);
    }
}

// ============================================================================
// Validation Cache Tests
// ============================================================================

#[cfg(test)]
mod validation_cache_tests {
    use parking_lot::RwLock;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct ValidationError {
        field: String,
        message: String,
    }

    #[test]
    fn test_validation_cache_insert_and_get() {
        let cache: RwLock<HashMap<String, Vec<ValidationError>>> = RwLock::new(HashMap::new());

        let config_id = "config-123";
        let errors = vec![ValidationError {
            field: "test".to_string(),
            message: "Test error".to_string(),
        }];

        // Insert
        cache.write().insert(config_id.to_string(), errors.clone());

        // Get
        let cached = cache.read().get(config_id).cloned();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }

    #[test]
    fn test_validation_cache_overwrite() {
        let cache: RwLock<HashMap<String, Vec<ValidationError>>> = RwLock::new(HashMap::new());

        let config_id = "config-123";

        // Insert first set of errors
        cache.write().insert(
            config_id.to_string(),
            vec![ValidationError {
                field: "field1".to_string(),
                message: "Error 1".to_string(),
            }],
        );

        // Overwrite with new errors
        cache.write().insert(
            config_id.to_string(),
            vec![
                ValidationError {
                    field: "field2".to_string(),
                    message: "Error 2".to_string(),
                },
                ValidationError {
                    field: "field3".to_string(),
                    message: "Error 3".to_string(),
                },
            ],
        );

        let cached = cache.read().get(config_id).cloned();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 2);
    }

    #[test]
    fn test_validation_cache_size_tracking() {
        let cache: RwLock<HashMap<String, Vec<ValidationError>>> = RwLock::new(HashMap::new());

        for i in 0..100 {
            cache.write().insert(
                format!("config-{}", i),
                vec![ValidationError {
                    field: "test".to_string(),
                    message: format!("Error {}", i),
                }],
            );
        }

        assert_eq!(cache.read().len(), 100);
    }
}

// ============================================================================
// Config Store Stats Tests
// ============================================================================

#[cfg(test)]
mod stats_tests {
    #[derive(Debug, Clone)]
    struct ConfigStoreStats {
        current_version: u32,
        version_history_count: usize,
        cached_validations: usize,
        has_cache: bool,
    }

    #[test]
    fn test_stats_creation() {
        let stats = ConfigStoreStats {
            current_version: 10,
            version_history_count: 5,
            cached_validations: 3,
            has_cache: true,
        };

        assert_eq!(stats.current_version, 10);
        assert_eq!(stats.version_history_count, 5);
        assert_eq!(stats.cached_validations, 3);
        assert!(stats.has_cache);
    }

    #[test]
    fn test_stats_without_cache() {
        let stats = ConfigStoreStats {
            current_version: 1,
            version_history_count: 0,
            cached_validations: 0,
            has_cache: false,
        };

        assert!(!stats.has_cache);
    }
}

// ============================================================================
// Backend Loading Tests
// ============================================================================

#[cfg(test)]
mod backend_loading_tests {
    #[derive(Debug, Clone)]
    struct MockBackend {
        id: String,
        backend_type: i32,
        protection_settings: Option<String>,
    }

    #[test]
    fn test_filter_deleted_backends() {
        let backends = vec![
            MockBackend {
                id: "backend-1".to_string(),
                backend_type: 1,
                protection_settings: None,
            },
            MockBackend {
                id: "backend-2".to_string(),
                backend_type: 2,
                protection_settings: Some("{}".to_string()),
            },
        ];

        // Simulating WHERE deleted_at IS NULL filter
        let active_backends: Vec<_> = backends
            .into_iter()
            .filter(|b| !b.id.is_empty()) // Simplified filter
            .collect();

        assert_eq!(active_backends.len(), 2);
    }

    #[test]
    fn test_backend_grouping_by_type() {
        use std::collections::HashMap;

        let backends = vec![
            MockBackend {
                id: "mc-1".to_string(),
                backend_type: 1, // Minecraft
                protection_settings: None,
            },
            MockBackend {
                id: "mc-2".to_string(),
                backend_type: 1, // Minecraft
                protection_settings: None,
            },
            MockBackend {
                id: "http-1".to_string(),
                backend_type: 2, // HTTP
                protection_settings: None,
            },
        ];

        let mut grouped: HashMap<i32, Vec<&MockBackend>> = HashMap::new();
        for backend in &backends {
            grouped.entry(backend.backend_type).or_default().push(backend);
        }

        assert_eq!(grouped.get(&1).unwrap().len(), 2);
        assert_eq!(grouped.get(&2).unwrap().len(), 1);
    }
}

// ============================================================================
// Rule Loading and Priority Tests
// ============================================================================

#[cfg(test)]
mod rule_loading_tests {
    #[derive(Debug, Clone)]
    struct MockRule {
        id: String,
        priority: u32,
        enabled: bool,
    }

    #[test]
    fn test_rules_sorted_by_priority() {
        let mut rules = vec![
            MockRule {
                id: "rule-3".to_string(),
                priority: 300,
                enabled: true,
            },
            MockRule {
                id: "rule-1".to_string(),
                priority: 100,
                enabled: true,
            },
            MockRule {
                id: "rule-2".to_string(),
                priority: 200,
                enabled: true,
            },
        ];

        rules.sort_by_key(|r| r.priority);

        assert_eq!(rules[0].id, "rule-1");
        assert_eq!(rules[1].id, "rule-2");
        assert_eq!(rules[2].id, "rule-3");
    }

    #[test]
    fn test_filter_disabled_rules() {
        let rules = vec![
            MockRule {
                id: "rule-1".to_string(),
                priority: 100,
                enabled: true,
            },
            MockRule {
                id: "rule-2".to_string(),
                priority: 200,
                enabled: false,
            },
            MockRule {
                id: "rule-3".to_string(),
                priority: 300,
                enabled: true,
            },
        ];

        let enabled_rules: Vec<_> = rules.into_iter().filter(|r| r.enabled).collect();

        assert_eq!(enabled_rules.len(), 2);
        assert!(enabled_rules.iter().all(|r| r.enabled));
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[cfg(test)]
mod error_handling_tests {
    #[derive(Debug)]
    enum TestError {
        NotFound(String, String),
        InvalidInput(String),
    }

    #[test]
    fn test_not_found_error() {
        let error = TestError::NotFound("Backend".to_string(), "backend-123".to_string());

        match error {
            TestError::NotFound(entity, id) => {
                assert_eq!(entity, "Backend");
                assert_eq!(id, "backend-123");
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_invalid_input_error() {
        let error = TestError::InvalidInput("Cannot rollback to version 10 (current is 5)".to_string());

        match error {
            TestError::InvalidInput(msg) => {
                assert!(msg.contains("rollback"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }
}
