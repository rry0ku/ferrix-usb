use crate::core::StageError;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DisposableEnvironment {
    pub workspace_dir: PathBuf,
    pub cleaned_up: bool,
}

impl DisposableEnvironment {
    pub fn create(prefix: &str) -> Result<Self, StageError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();

        let base = if let Ok(env_dir) = std::env::var("FERRIX_TMPDIR") {
            if !env_dir.is_empty() && Path::new(&env_dir).is_dir() {
                PathBuf::from(env_dir)
            } else if Path::new("/dev/shm").is_dir() {
                PathBuf::from("/dev/shm")
            } else {
                std::env::temp_dir()
            }
        } else if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };

        let workspace_dir = base.join(format!("ferrix-{prefix}-{pid}-{now:x}"));
        fs::create_dir_all(&workspace_dir).map_err(|e| {
            StageError::Io(format!(
                "failed to create disposable workspace at {}: {e}",
                workspace_dir.display()
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&workspace_dir, fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            workspace_dir,
            cleaned_up: false,
        })
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.workspace_dir.join("snapshot.raw")
    }

    pub fn cleanup(&mut self) -> Result<(), StageError> {
        if self.cleaned_up {
            return Ok(());
        }

        if self.workspace_dir.exists() {
            if let Ok(entries) = fs::read_dir(&self.workspace_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let _ = secure_wipe_file(&p);
                        let _ = fs::remove_file(&p);
                    }
                }
            }
            let _ = fs::remove_dir_all(&self.workspace_dir);
        }

        self.cleaned_up = true;
        Ok(())
    }
}

impl Drop for DisposableEnvironment {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn secure_wipe_file(path: &Path) -> Result<(), StageError> {
    if let Ok(meta) = fs::metadata(path) {
        let len = meta.len();
        if len > 0 {
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                let zero_chunk = vec![0u8; 64 * 1024];
                let mut remaining = len;
                while remaining > 0 {
                    let to_write = (remaining as usize).min(zero_chunk.len());
                    if file.write_all(&zero_chunk[..to_write]).is_err() {
                        break;
                    }
                    remaining -= to_write as u64;
                }
                let _ = file.sync_all();
            }
        }
    }
    Ok(())
}
