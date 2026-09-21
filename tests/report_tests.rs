use ferrix_usb::core::{Confidence, Finding, Location, Severity, Verdict};
use ferrix_usb::manifest::Manifest;
use ferrix_usb::report::{generate_html_report, generate_json_report, load_scan_manifest};
use std::fs::File;
use std::io::Write;

fn make_sample_manifest(station_id: &str, verdict: Verdict) -> Manifest {
    Manifest {
        version: "0.1.0".to_string(),
        station_id: station_id.to_string(),
        nonce: "1234567890abcdef1234567890abcdef".to_string(),
        issued_at: 1700000000,
        expires_at: 1700086400,
        device_identity: None,
        device_size_bytes: 4096,
        device_hash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234".to_string(),
        partition_layout_hash: "ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01ef01"
            .to_string(),
        files: Vec::new(),
        policy_hash: "9876987698769876987698769876987698769876987698769876987698769876".to_string(),
        stages_required: vec!["partition_scan".to_string()],
        stages_completed: Vec::new(),
        verdict,
        sector_size: 512,
        signature: Some("sig1234".to_string()),
    }
}

fn make_findings() -> Vec<Finding> {
    vec![
        Finding {
            id: "FX-DEV-001".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            stage: "device_scan".to_string(),
            location: Location::Device,
            reason: "BadUSB device detected".to_string(),
            evidence: "composite device contains storage and keyboard descriptors".to_string(),
        },
        Finding {
            id: "FX-PART-001".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Partition(1),
            reason: "overlapping partitions".to_string(),
            evidence: "partition 1 overlaps partition 2".to_string(),
        },
        Finding {
            id: "FX-EGR-003".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "egress_scan".to_string(),
            location: Location::Device,
            reason: "metadata detected".to_string(),
            evidence: "EXIF tags present".to_string(),
        },
        Finding {
            id: "FX-PART-006".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Medium,
            stage: "partition_scan".to_string(),
            location: Location::Partition(1),
            reason: "hidden type".to_string(),
            evidence: "type byte 0x17".to_string(),
        },
        Finding {
            id: "FX-FILE-005".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Low,
            stage: "file_scan".to_string(),
            location: Location::Device,
            reason: "dotfile".to_string(),
            evidence: "hidden .gitignore".to_string(),
        },
    ]
}

#[test]
fn test_json_report_generation() {
    let manifest = make_sample_manifest("station-test-01", Verdict::Fail);
    let findings = make_findings();

    let json_str = generate_json_report(&manifest, &findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["summary"]["verdict"], "FAIL");
    assert_eq!(parsed["summary"]["total"], 5);
    assert_eq!(parsed["summary"]["critical"], 1);
    assert_eq!(parsed["summary"]["high"], 1);
    assert_eq!(parsed["summary"]["medium"], 1);
    assert_eq!(parsed["summary"]["low"], 1);
    assert_eq!(parsed["summary"]["info"], 1);
    assert_eq!(parsed["manifest"]["station_id"], "station-test-01");
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 5);
}

#[test]
fn test_html_report_generation_and_xss_escaping() {
    let manifest = make_sample_manifest("<script>alert('station')</script>", Verdict::Quarantine);
    let hostile_findings = vec![Finding {
        id: "FX-FILE-999".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        stage: "file_scan".to_string(),
        location: Location::Device,
        reason: "<img src=x onerror=alert(1)>".to_string(),
        evidence: "payload & <tag> with \"quotes\" and 'apostrophe'".to_string(),
    }];

    let html_str = generate_html_report(&manifest, &hostile_findings).unwrap();

    assert!(html_str.contains("<!DOCTYPE html>"));
    assert!(html_str.contains("VERDICT: QUARANTINE"));

    assert!(!html_str.contains("<script>"));
    assert!(html_str.contains("&lt;script&gt;alert(&#39;station&#39;)&lt;/script&gt;"));

    assert!(!html_str.contains("<img src=x"));
    assert!(html_str.contains("&lt;img src=x onerror=alert(1)&gt;"));

    assert!(html_str
        .contains("payload &amp; &lt;tag&gt; with &quot;quotes&quot; and &#39;apostrophe&#39;"));
}

#[test]
fn test_load_scan_manifest_resolution() {
    let temp_dir = std::env::temp_dir().join("ferrix_test_report_manifest");
    let _ = std::fs::create_dir_all(&temp_dir);

    let manifest = make_sample_manifest("station-find-me", Verdict::Pass);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();

    let manifest_path = temp_dir.join("scan-abc123-manifest.json");
    let mut file = File::create(&manifest_path).unwrap();
    file.write_all(&manifest_bytes).unwrap();

    let loaded = load_scan_manifest("scan-abc123", &[&temp_dir]).unwrap();
    assert_eq!(loaded.station_id, "station-find-me");
    assert_eq!(loaded.verdict, Verdict::Pass);

    let loaded_direct = load_scan_manifest(manifest_path.to_str().unwrap(), &[]).unwrap();
    assert_eq!(loaded_direct.station_id, "station-find-me");

    assert!(load_scan_manifest("non-existent-scan-id", &[&temp_dir]).is_err());

    let _ = std::fs::remove_dir_all(temp_dir);
}
