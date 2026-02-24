use std::fs;
use std::path::PathBuf;

use tokio::sync::Mutex;
use zpaq_rs::{ArchiveEntry, archive_append_entries_file, archive_read_file_bytes, zpaq_list};

use crate::app::AppError;

pub struct StorageManager {
    path: PathBuf,
    write_lock: Mutex<()>,
    max_restore_bytes: u64,
}

impl StorageManager {
    pub fn new(path: impl Into<PathBuf>, max_restore_bytes: u64) -> Result<Self, AppError> {
        let path = path.into();

        if path.as_os_str().is_empty() {
            return Err(AppError::Runtime(
                "storage path is empty (set storage.path to an absolute path)".to_owned(),
            ));
        }

        if !path.is_absolute() {
            return Err(AppError::Runtime(
                "storage path must be absolute".to_owned(),
            ));
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            let _ = fs::create_dir_all(parent);
        }
        Ok(Self {
            path,
            write_lock: Mutex::new(()),
            max_restore_bytes,
        })
    }

    pub async fn save_message(&self, message_bytes: Vec<u8>) -> Result<(), AppError> {
        let _guard = self.write_lock.lock().await;
        let path = self.path.clone();

        tokio::task::spawn_blocking(move || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let filename = format!("msg_{}_{:08x}", now.as_nanos(), rand::random::<u32>());

            let entry = ArchiveEntry {
                path: &filename,
                data: &message_bytes,
                comment: None,
            };

            // Use method "3" as requested (default).
            let archive_path_str = path
                .to_str()
                .ok_or_else(|| AppError::Runtime("invalid storage path encoding".to_owned()))?;

            archive_append_entries_file(archive_path_str, &[entry], "3")
                .map_err(|e| AppError::Runtime(format!("zpaq save failed: {e}")))
        })
        .await
        .map_err(|e| AppError::Runtime(format!("storage worker join error: {e}")))?
    }

    pub async fn load_all_messages(&self) -> Result<Vec<Vec<u8>>, AppError> {
        let path = self.path.clone();
        let max_restore_bytes = self.max_restore_bytes;

        tokio::task::spawn_blocking(move || {
            if !path.exists() {
                return Ok(Vec::new());
            }

            let archive_path_str = path
                .to_str()
                .ok_or_else(|| AppError::Runtime("invalid storage path encoding".to_owned()))?;

            let metadata = fs::metadata(&path)
                .map_err(|e| AppError::Runtime(format!("failed to read archive metadata: {e}")))?;
            if metadata.len() > max_restore_bytes {
                return Err(AppError::Runtime(format!(
                    "archive size {} exceeds restore limit {}",
                    metadata.len(),
                    max_restore_bytes
                )));
            }

            // List files in the archive to avoid temporary directory and disk I/O.
            let list_out = zpaq_list(archive_path_str, &[])
                .map_err(|e| AppError::Runtime(format!("zpaq list failed: {e}")))?;

            let mut filenames = Vec::new();
            for line in list_out.stdout.lines() {
                // zpaq-rs list output for segments usually starts with "- "
                if line.starts_with("- ")
                    && let Some(filename) = line.split_whitespace().last()
                    && filename.starts_with("msg_")
                {
                    filenames.push(filename.to_owned());
                }
            }

            if filenames.is_empty() {
                return Ok(Vec::new());
            }

            // Read the archive once into memory.
            let archive_bytes = fs::read(&path)
                .map_err(|e| AppError::Runtime(format!("failed to read archive file: {e}")))?;

            let mut messages = Vec::new();
            for name in filenames {
                match archive_read_file_bytes(&archive_bytes, &name) {
                    Ok(data) => messages.push(data),
                    Err(e) => {
                        eprintln!(
                            "warning: failed to read message {} from archive: {}",
                            name, e
                        );
                    }
                }
            }

            Ok(messages)
        })
        .await
        .map_err(|e| AppError::Runtime(format!("storage worker join error: {e}")))?
    }
}
