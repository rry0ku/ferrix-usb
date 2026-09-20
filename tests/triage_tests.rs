use ferrix_usb::core::{Confidence, Finding, Location, MediaPath, Severity};
use ferrix_usb::triage::{Suppression, SuppressionScope, SuppressionStore};

fn make_finding(id: &str, severity: Severity, location: Location) -> Finding {
    Finding {
        id: id.to_string(),
        severity,
        confidence: Confidence::High,
        stage: "test_stage".to_string(),
        location,
        reason: "test reason".to_string(),
        evidence: "test evidence".to_string(),
    }
}

#[test]
fn test_suppression_creation_and_matching() {
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    let sup_hash = Suppression {
        id: "SUP-001".to_string(),
        scope: SuppressionScope::FileHash("abcd1234abcd1234".to_string()),
        reason: "approved internal binary".to_string(),
        author: "sec-admin".to_string(),
        created_at: now,
        expires_at: now + 86400 * 90,
        signature: None,
    };
    store.add_suppression(sup_hash).unwrap();

    let sup_path = Suppression {
        id: "SUP-002".to_string(),
        scope: SuppressionScope::RuleAndPath {
            rule_id: "FX-FILE-003".to_string(),
            path_pattern: "*.log".to_string(),
        },
        reason: "expected log file".to_string(),
        author: "sec-admin".to_string(),
        created_at: now,
        expires_at: now + 86400 * 90,
        signature: None,
    };
    store.add_suppression(sup_path).unwrap();

    let finding_hash = make_finding(
        "FX-FILE-001",
        Severity::High,
        Location::Path(MediaPath::from("app.exe")),
    );
    let matched = store.check_finding(&finding_hash, Some("abcd1234abcd1234"), now + 100);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "SUP-001");

    let finding_path = make_finding(
        "FX-FILE-003",
        Severity::Medium,
        Location::Path(MediaPath::from("debug.log")),
    );
    let matched_path = store.check_finding(&finding_path, None, now + 100);
    assert!(matched_path.is_some());
    assert_eq!(matched_path.unwrap().id, "SUP-002");
}

#[test]
fn test_critical_finding_cannot_be_suppressed() {
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    let sup = Suppression {
        id: "SUP-001".to_string(),
        scope: SuppressionScope::FileHash("hash123".to_string()),
        reason: "test".to_string(),
        author: "admin".to_string(),
        created_at: now,
        expires_at: now + 1000,
        signature: None,
    };
    store.add_suppression(sup).unwrap();

    let critical_finding = make_finding("FX-DEV-001", Severity::Critical, Location::Device);
    assert!(SuppressionStore::is_suppressible(&critical_finding).is_err());
    assert!(store
        .check_finding(&critical_finding, Some("hash123"), now + 10)
        .is_none());
}

#[test]
fn test_structural_ambiguity_cannot_be_suppressed() {
    let part_overlap = make_finding("FX-PART-001", Severity::High, Location::Partition(1));
    assert!(SuppressionStore::is_suppressible(&part_overlap).is_err());

    let gpt_mismatch = make_finding("FX-PART-004", Severity::High, Location::Device);
    assert!(SuppressionStore::is_suppressible(&gpt_mismatch).is_err());

    let polyglot = make_finding("FX-FS-001", Severity::High, Location::Partition(1));
    assert!(SuppressionStore::is_suppressible(&polyglot).is_err());
}

#[test]
fn test_wildcard_scope_rejected() {
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    let wild_star = Suppression {
        id: "SUP-BAD-1".to_string(),
        scope: SuppressionScope::RuleAndPath {
            rule_id: "FX-FILE-001".to_string(),
            path_pattern: "*".to_string(),
        },
        reason: "blanket ignore".to_string(),
        author: "lazy".to_string(),
        created_at: now,
        expires_at: now + 1000,
        signature: None,
    };
    assert!(store.add_suppression(wild_star).is_err());

    let wild_doublestar = Suppression {
        id: "SUP-BAD-2".to_string(),
        scope: SuppressionScope::RuleAndPath {
            rule_id: "FX-FILE-001".to_string(),
            path_pattern: "**".to_string(),
        },
        reason: "blanket ignore".to_string(),
        author: "lazy".to_string(),
        created_at: now,
        expires_at: now + 1000,
        signature: None,
    };
    assert!(store.add_suppression(wild_doublestar).is_err());
}

#[test]
fn test_expired_suppression_inactive() {
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    let sup = Suppression {
        id: "SUP-EXP".to_string(),
        scope: SuppressionScope::FileHash("hash123".to_string()),
        reason: "expired".to_string(),
        author: "admin".to_string(),
        created_at: now - 1000,
        expires_at: now - 10,
        signature: None,
    };
    store.add_suppression(sup).unwrap();

    let finding = make_finding(
        "FX-FILE-001",
        Severity::High,
        Location::Path(MediaPath::from("app.exe")),
    );
    assert!(store
        .check_finding(&finding, Some("hash123"), now)
        .is_none());
    assert!(store.list_active(now).is_empty());
}

#[test]
fn test_suppression_store_save_and_load() {
    let temp_path = std::env::temp_dir().join("ferrix_test_suppressions.json");
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    store
        .add_suppression(Suppression {
            id: "SUP-001".to_string(),
            scope: SuppressionScope::FileHash("hash999".to_string()),
            reason: "testing persist".to_string(),
            author: "dev".to_string(),
            created_at: now,
            expires_at: now + 10000,
            signature: None,
        })
        .unwrap();

    store.save(&temp_path).unwrap();
    let loaded = SuppressionStore::load(&temp_path).unwrap();
    assert_eq!(loaded.suppressions.len(), 1);
    assert_eq!(loaded.suppressions[0].id, "SUP-001");

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_suppression_validation_empty_fields() {
    let mut store = SuppressionStore::default();
    let now = 1700000000;

    let empty_reason = Suppression {
        id: "SUP-ERR-1".to_string(),
        scope: SuppressionScope::FileHash("hash123".to_string()),
        reason: "   ".to_string(),
        author: "admin".to_string(),
        created_at: now,
        expires_at: now + 1000,
        signature: None,
    };
    assert!(store.add_suppression(empty_reason).is_err());

    let empty_author = Suppression {
        id: "SUP-ERR-2".to_string(),
        scope: SuppressionScope::FileHash("hash123".to_string()),
        reason: "valid reason".to_string(),
        author: "   ".to_string(),
        created_at: now,
        expires_at: now + 1000,
        signature: None,
    };
    assert!(store.add_suppression(empty_author).is_err());

    let invalid_expiry = Suppression {
        id: "SUP-ERR-3".to_string(),
        scope: SuppressionScope::FileHash("hash123".to_string()),
        reason: "valid reason".to_string(),
        author: "admin".to_string(),
        created_at: now,
        expires_at: now,
        signature: None,
    };
    assert!(store.add_suppression(invalid_expiry).is_err());
}
