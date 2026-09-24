//! Writing reports.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Writes the report to stdout, or to a new file.
///
/// Files are created with mode `0600` on Unix (reports may contain sensitive
/// incident data) and are never overwritten: an existing path, including a
/// symlink, is an error.
pub(crate) fn write_report(report: &str, path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(report.as_bytes())
            .context("could not write to stdout")?;
        return stdout.flush().context("could not write to stdout");
    };

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            bail!("refusing to overwrite existing file {}", path.display())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("could not create {}", path.display()));
        }
    };
    file.write_all(report.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "sentinel-osint-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn creates_private_files_and_never_overwrites() {
        let path = temp_path("report.txt");
        write_report("first\n", Some(&path)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let err = write_report("second\n", Some(&path)).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");
        std::fs::remove_file(&path).unwrap();
    }
}
