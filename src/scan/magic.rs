use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    Executable,
    Document,
    Image,
    Archive,
    Text,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedType {
    Pe,
    Elf,
    MachO,
    ShellScript,
    WindowsScript,
    Pdf,
    ZipOrOffice,
    Jpeg,
    Png,
    Gif,
    PlainText,
    Unknown,
}

impl DetectedType {
    pub fn risk_class(&self) -> RiskClass {
        match self {
            DetectedType::Pe
            | DetectedType::Elf
            | DetectedType::MachO
            | DetectedType::ShellScript
            | DetectedType::WindowsScript => RiskClass::Executable,
            DetectedType::Pdf => RiskClass::Document,
            DetectedType::ZipOrOffice => RiskClass::Archive,
            DetectedType::Jpeg | DetectedType::Png | DetectedType::Gif => RiskClass::Image,
            DetectedType::PlainText => RiskClass::Text,
            DetectedType::Unknown => RiskClass::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DetectedType::Pe => "Windows PE Executable",
            DetectedType::Elf => "Linux ELF Executable",
            DetectedType::MachO => "Mach-O Executable",
            DetectedType::ShellScript => "Shell Script",
            DetectedType::WindowsScript => "Windows Script",
            DetectedType::Pdf => "PDF Document",
            DetectedType::ZipOrOffice => "ZIP/Office Archive",
            DetectedType::Jpeg => "JPEG Image",
            DetectedType::Png => "PNG Image",
            DetectedType::Gif => "GIF Image",
            DetectedType::PlainText => "Plain Text",
            DetectedType::Unknown => "Unknown Binary Data",
        }
    }
}

pub fn detect_content_type(data: &[u8]) -> DetectedType {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        return DetectedType::Pe;
    }

    if data.len() >= 4 && &data[0..4] == b"\x7FELF" {
        return DetectedType::Elf;
    }

    if data.len() >= 4 {
        let magic = &data[0..4];
        if magic == b"\xFE\xED\xFA\xCE"
            || magic == b"\xFE\xED\xFA\xCF"
            || magic == b"\xCE\xFA\xED\xFE"
            || magic == b"\xCF\xFA\xED\xFE"
        {
            return DetectedType::MachO;
        }
    }

    if data.len() >= 2 && data[0] == b'#' && data[1] == b'!' {
        return DetectedType::ShellScript;
    }

    if data.len() >= 4 && &data[0..4] == b"%PDF" {
        return DetectedType::Pdf;
    }

    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        return DetectedType::ZipOrOffice;
    }

    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return DetectedType::Jpeg;
    }

    if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
        return DetectedType::Png;
    }

    if data.len() >= 4 && (&data[0..4] == b"GIF8" || &data[0..4] == b"GIF7") {
        return DetectedType::Gif;
    }

    if !data.is_empty()
        && data
            .iter()
            .all(|&b| b == b'\t' || b == b'\r' || b == b'\n' || (0x20..=0x7E).contains(&b))
    {
        return DetectedType::PlainText;
    }

    DetectedType::Unknown
}

pub fn expected_risk_class_from_extension(ext: &str) -> RiskClass {
    match ext.to_lowercase().as_str() {
        "exe" | "dll" | "sys" | "scr" | "bin" | "elf" | "so" | "sh" | "bash" | "bat" | "cmd"
        | "vbs" | "ps1" | "wsf" | "pif" | "com" => RiskClass::Executable,
        "pdf" => RiskClass::Document,
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" => RiskClass::Document,
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => RiskClass::Archive,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "svg" | "ico" => RiskClass::Image,
        "txt" | "csv" | "tsv" | "log" | "json" | "xml" | "yaml" | "yml" | "md" => RiskClass::Text,
        _ => RiskClass::Unknown,
    }
}

pub fn check_extension_content_mismatch(
    filename: &str,
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
) {
    let extension = filename.rsplit('.').next().unwrap_or("");
    if extension.is_empty() || extension == filename {
        return;
    }

    let detected = detect_content_type(data);
    let detected_class = detected.risk_class();
    let expected_class = expected_risk_class_from_extension(extension);

    if detected_class == RiskClass::Executable
        && expected_class != RiskClass::Executable
        && expected_class != RiskClass::Unknown
    {
        findings.push(Finding {
            id: "FX-FILE-001".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "executable disguised as non-executable file".to_string(),
            evidence: format!(
                "file extension is '.{extension}' but content is {}",
                detected.name()
            ),
        });
    } else if detected_class != expected_class
        && expected_class != RiskClass::Unknown
        && detected_class != RiskClass::Unknown
    {
        findings.push(Finding {
            id: "FX-FILE-001".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Medium,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "file extension differs from detected content type".to_string(),
            evidence: format!(
                "file extension is '.{extension}' but content matches {}",
                detected.name()
            ),
        });
    }
}
