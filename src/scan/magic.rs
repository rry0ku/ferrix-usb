use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    Executable,
    Document,
    Image,
    Archive,
    Audio,
    Video,
    Text,
    Data,
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
    SevenZip,
    Gzip,
    Tar,
    Bzip2,
    Xz,
    Rar,
    Jpeg,
    Png,
    Gif,
    Bmp,
    Webp,
    Svg,
    Mp3,
    Flac,
    Wav,
    Ogg,
    Mp4,
    Mkv,
    Avi,
    Sqlite,
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
            DetectedType::ZipOrOffice
            | DetectedType::SevenZip
            | DetectedType::Gzip
            | DetectedType::Tar
            | DetectedType::Bzip2
            | DetectedType::Xz
            | DetectedType::Rar => RiskClass::Archive,
            DetectedType::Jpeg
            | DetectedType::Png
            | DetectedType::Gif
            | DetectedType::Bmp
            | DetectedType::Webp
            | DetectedType::Svg => RiskClass::Image,
            DetectedType::Mp3 | DetectedType::Flac | DetectedType::Wav | DetectedType::Ogg => {
                RiskClass::Audio
            }
            DetectedType::Mp4 | DetectedType::Mkv | DetectedType::Avi => RiskClass::Video,
            DetectedType::Sqlite => RiskClass::Data,
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
            DetectedType::SevenZip => "7-Zip Archive",
            DetectedType::Gzip => "Gzip Archive",
            DetectedType::Tar => "Tar Archive",
            DetectedType::Bzip2 => "Bzip2 Archive",
            DetectedType::Xz => "XZ Archive",
            DetectedType::Rar => "RAR Archive",
            DetectedType::Jpeg => "JPEG Image",
            DetectedType::Png => "PNG Image",
            DetectedType::Gif => "GIF Image",
            DetectedType::Bmp => "BMP Image",
            DetectedType::Webp => "WebP Image",
            DetectedType::Svg => "SVG Image",
            DetectedType::Mp3 => "MP3 Audio",
            DetectedType::Flac => "FLAC Audio",
            DetectedType::Wav => "WAV Audio",
            DetectedType::Ogg => "OGG Media",
            DetectedType::Mp4 => "MP4/M4A Media",
            DetectedType::Mkv => "Matroska/WebM Media",
            DetectedType::Avi => "AVI Video",
            DetectedType::Sqlite => "SQLite Database",
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
            || magic == b"\xCA\xFE\xBA\xBE"
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

    if data.len() >= 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return DetectedType::SevenZip;
    }

    if data.len() >= 3 && &data[0..3] == b"\x1F\x8B\x08" {
        return DetectedType::Gzip;
    }

    if data.len() >= 3 && &data[0..3] == b"BZh" {
        return DetectedType::Bzip2;
    }

    if data.len() >= 6 && &data[0..6] == b"\xFD7zXZ\x00" {
        return DetectedType::Xz;
    }

    if data.len() >= 7 && (&data[0..7] == b"Rar!\x1A\x07\x00" || &data[0..7] == b"Rar!\x1A\x07\x01")
    {
        return DetectedType::Rar;
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

    if data.len() >= 2 && &data[0..2] == b"BM" {
        return DetectedType::Bmp;
    }

    if data.len() >= 12 && &data[0..4] == b"RIFF" {
        if &data[8..12] == b"WAVE" {
            return DetectedType::Wav;
        }
        if &data[8..12] == b"AVI " {
            return DetectedType::Avi;
        }
        if &data[8..12] == b"WEBP" {
            return DetectedType::Webp;
        }
    }

    if data.len() >= 3 && &data[0..3] == b"ID3" {
        return DetectedType::Mp3;
    }

    if data.len() >= 2
        && data[0] == 0xFF
        && (data[1] & 0xE0) == 0xE0
        && (data[1] & 0x18) != 0x08
        && (data[1] & 0x06) != 0x00
    {
        return DetectedType::Mp3;
    }

    if data.len() >= 4 && &data[0..4] == b"fLaC" {
        return DetectedType::Flac;
    }

    if data.len() >= 4 && &data[0..4] == b"OggS" {
        return DetectedType::Ogg;
    }

    if data.len() >= 8 && (&data[4..8] == b"ftyp" || &data[4..8] == b"moov") {
        return DetectedType::Mp4;
    }

    if data.len() >= 4 && &data[0..4] == b"\x1A\x45\xDF\xA3" {
        return DetectedType::Mkv;
    }

    if data.len() >= 16 && &data[0..16] == b"SQLite format 3\0" {
        return DetectedType::Sqlite;
    }

    if data.len() >= 262 && &data[257..262] == b"ustar" {
        return DetectedType::Tar;
    }

    if data.len() >= 4
        && (data.starts_with(b"<?xml") || data.starts_with(b"<svg"))
        && data.windows(4).any(|w| w == b"<svg")
    {
        return DetectedType::Svg;
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
        | "vbs" | "ps1" | "wsf" | "pif" | "com" | "cpl" | "msi" | "msp" | "gadget" | "hta"
        | "jar" => RiskClass::Executable,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
        | "rtf" | "epub" | "mobi" | "azw3" | "djvu" | "pages" | "numbers" | "key" | "wps"
        | "oxps" | "xps" | "tex" | "bib" => RiskClass::Document,
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" | "tgz" | "tbz2" | "txz" | "zst"
        | "lz4" | "lzma" | "cab" | "iso" | "img" | "cpio" | "ar" => RiskClass::Archive,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tiff" | "tif"
        | "psd" | "ai" | "raw" | "cr2" | "nef" | "heic" | "heif" | "avif" | "xcf" | "indd"
        | "eps" | "cdr" | "dcm" | "dwg" | "dxf" => RiskClass::Image,
        "mp3" | "flac" | "wav" | "ogg" | "m4a" | "aac" | "wma" | "opus" | "mid" | "midi"
        | "alac" | "aiff" | "ape" | "ac3" | "dts" | "amr" | "mka" => RiskClass::Audio,
        "mp4" | "mkv" | "avi" | "mov" | "webm" | "wmv" | "flv" | "m4v" | "3gp" | "3g2" | "mpg"
        | "mpeg" | "ts" | "vob" | "ogv" => RiskClass::Video,
        "txt" | "csv" | "tsv" | "log" | "json" | "xml" | "yaml" | "yml" | "md" | "markdown"
        | "ini" | "conf" | "cfg" | "toml" | "properties" | "html" | "htm" | "css" | "scss"
        | "sass" | "less" | "js" | "jsx" | "ts" | "tsx" | "rs" | "py" | "c" | "cpp" | "cxx"
        | "cc" | "h" | "hpp" | "hxx" | "go" | "java" | "kt" | "kts" | "cs" | "swift" | "rb"
        | "php" | "lua" | "sql" | "r" | "scala" | "pl" | "pm" | "diff" | "patch" | "env" => {
            RiskClass::Text
        }
        "db" | "sqlite" | "sqlite3" | "parquet" | "arrow" | "dat" | "hex" | "dump" | "ttf"
        | "otf" | "woff" | "woff2" | "eot" | "stl" | "obj" | "fbx" | "blend" | "step" | "stp"
        | "iges" | "mat" | "hdf5" | "h5" | "nc" | "fits" => RiskClass::Data,
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

    let is_media_cross = (detected_class == RiskClass::Audio || detected_class == RiskClass::Video)
        && (expected_class == RiskClass::Audio || expected_class == RiskClass::Video);

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
        && !is_media_cross
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
