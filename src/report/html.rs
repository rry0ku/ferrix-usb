use crate::core::{Finding, Severity, StageError, Verdict};
use crate::manifest::Manifest;

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn generate_html_report(
    manifest: &Manifest,
    findings: &[Finding],
) -> Result<String, StageError> {
    let (verdict_color, verdict_bg) = match manifest.verdict {
        Verdict::Pass => ("#27ae60", "#e8f8f5"),
        Verdict::Quarantine => ("#d35400", "#fef9e7"),
        Verdict::Fail => ("#c0392b", "#fdedec"),
    };

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let mut findings_html = String::new();
    if findings.is_empty() {
        findings_html.push_str("<p class='clean-msg'>No findings detected. Media conforms to policy and safety standards.</p>");
    } else {
        for f in findings {
            let (badge_color, badge_bg) = match f.severity {
                Severity::Critical => ("#c0392b", "#fdedec"),
                Severity::High => ("#e67e22", "#fdf2e9"),
                Severity::Medium => ("#f39c12", "#fef9e7"),
                Severity::Low => ("#2980b9", "#ebf5fb"),
                Severity::Info => ("#7f8c8d", "#f2f4f4"),
            };

            let escaped_id = escape_html(&f.id);
            let escaped_loc = escape_html(&f.location.to_string());
            let escaped_reason = escape_html(&f.reason);
            let escaped_evidence = escape_html(&f.evidence);

            findings_html.push_str(&format!(
                "<div class='finding-card'>
                    <div class='finding-header'>
                        <span class='badge' style='color:{badge_color}; background:{badge_bg};'>{}</span>
                        <span class='finding-id'>{}</span>
                        <span class='finding-loc'>{}</span>
                    </div>
                    <div class='finding-reason'>{}</div>
                    <div class='finding-evidence'><strong>Evidence:</strong> {}</div>
                </div>",
                f.severity, escaped_id, escaped_loc, escaped_reason, escaped_evidence
            ));
        }
    }

    let signature_status = if manifest.signature.is_some() {
        "<span style='color:#27ae60; font-weight:bold;'>Signed (Ed25519)</span>"
    } else {
        "<span style='color:#7f8c8d; font-weight:bold;'>Unsigned</span>"
    };

    let html = format!(
        "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>ferrix-usb Scan Report - {}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 24px; background: #fafafa; color: #2c3e50; line-height: 1.5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        h1 {{ margin-top: 0; font-size: 24px; border-bottom: 2px solid #eaeded; padding-bottom: 12px; }}
        .verdict-banner {{ padding: 18px; border-radius: 6px; text-align: center; font-size: 28px; font-weight: bold; margin: 24px 0; color: {verdict_color}; background: {verdict_bg}; border: 1px solid {verdict_color}; }}
        .summary-bar {{ display: flex; gap: 12px; margin-bottom: 24px; }}
        .summary-item {{ flex: 1; padding: 12px; border-radius: 6px; text-align: center; background: #f8f9fa; border: 1px solid #e9ecef; }}
        .summary-val {{ font-size: 20px; font-weight: bold; }}
        .summary-lbl {{ font-size: 12px; text-transform: uppercase; color: #6c757d; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0 24px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eaeded; font-size: 14px; }}
        th {{ background: #f8f9fa; color: #495057; font-weight: 600; width: 220px; }}
        .hash-code {{ font-family: monospace; font-size: 13px; word-break: break-all; background: #f1f2f6; padding: 2px 6px; border-radius: 4px; }}
        .finding-card {{ border: 1px solid #eaeded; border-radius: 6px; padding: 14px; margin-bottom: 12px; background: #fff; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .badge {{ font-size: 11px; font-weight: bold; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }}
        .finding-id {{ font-family: monospace; font-weight: bold; color: #34495e; }}
        .finding-loc {{ font-family: monospace; color: #7f8c8d; font-size: 13px; margin-left: auto; }}
        .finding-reason {{ font-size: 14px; font-weight: 600; margin-bottom: 6px; }}
        .finding-evidence {{ font-size: 13px; color: #555; background: #fdfefe; padding: 8px; border-left: 3px solid #bdc3c7; }}
        .clean-msg {{ color: #27ae60; font-size: 15px; font-weight: 500; padding: 16px; background: #e8f8f5; border-radius: 6px; }}
        .footer {{ margin-top: 32px; font-size: 12px; color: #95a5a6; text-align: center; border-top: 1px solid #eaeded; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>ferrix-usb Scan &amp; Verification Report</h1>
        
        <div class='verdict-banner'>VERDICT: {}</div>

        <div class='summary-bar'>
            <div class='summary-item'><div class='summary-val'>{}</div><div class='summary-lbl'>Total</div></div>
            <div class='summary-item'><div class='summary-val' style='color:#c0392b;'>{}</div><div class='summary-lbl'>Critical</div></div>
            <div class='summary-item'><div class='summary-val' style='color:#e67e22;'>{}</div><div class='summary-lbl'>High</div></div>
            <div class='summary-item'><div class='summary-val' style='color:#f39c12;'>{}</div><div class='summary-lbl'>Medium</div></div>
            <div class='summary-item'><div class='summary-val' style='color:#2980b9;'>{}</div><div class='summary-lbl'>Low</div></div>
            <div class='summary-item'><div class='summary-val' style='color:#7f8c8d;'>{}</div><div class='summary-lbl'>Info</div></div>
        </div>

        <h2>Inspection Details</h2>
        <table>
            <tr><th>Station ID</th><td>{}</td></tr>
            <tr><th>Nonce</th><td class='hash-code'>{}</td></tr>
            <tr><th>Issued Timestamp</th><td>{}</td></tr>
            <tr><th>Device Size</th><td>{} bytes ({:.2} MB)</td></tr>
            <tr><th>Device Hash (BLAKE3)</th><td class='hash-code'>{}</td></tr>
            <tr><th>Partition Layout Hash</th><td class='hash-code'>{}</td></tr>
            <tr><th>Policy Hash</th><td class='hash-code'>{}</td></tr>
            <tr><th>Signature Status</th><td>{}</td></tr>
        </table>

        <h2>Findings ({})</h2>
        {}

        <div class='footer'>
            Generated by ferrix-usb v{} &bull; Offline Hardware Security Inspection Tool
        </div>
    </div>
</body>
</html>",
        escape_html(&manifest.station_id),
        manifest.verdict,
        findings.len(),
        critical,
        high,
        medium,
        low,
        info,
        escape_html(&manifest.station_id),
        escape_html(&manifest.nonce),
        manifest.issued_at,
        manifest.device_size_bytes,
        manifest.device_size_bytes as f64 / (1024.0 * 1024.0),
        escape_html(&manifest.device_hash),
        escape_html(&manifest.partition_layout_hash),
        escape_html(&manifest.policy_hash),
        signature_status,
        findings.len(),
        findings_html,
        escape_html(&manifest.version)
    );

    Ok(html)
}
