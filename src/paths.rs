use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn join_rel_path(parent: &str, child: &str) -> String {
    let child = child.trim_start_matches('/');
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

pub fn sanitize_segment(name: &str) -> String {
    let trimmed = name.trim();
    let sanitized = trimmed.replace('\0', "").replace(['/', '\\'], "_");
    match sanitized.as_str() {
        "" | "." | ".." => "_".to_owned(),
        _ => sanitized,
    }
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

pub fn disambiguated_name(seen: &mut HashMap<String, usize>, name: &str, id: &str) -> String {
    let mut base = sanitize_segment(name);
    if base == "_" && !id.is_empty() {
        base = format!("file_{}", short_id(id));
    }

    let key = base.to_lowercase();
    let count = seen.entry(key).and_modify(|value| *value += 1).or_insert(1);
    if *count == 1 {
        return base;
    }

    if id.is_empty() {
        format!("{base}_{count}")
    } else {
        format!("{base}_{}", short_id(id))
    }
}

pub fn local_path(root: &Path, rel_path: &str) -> PathBuf {
    if rel_path.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_path)
    }
}

pub fn launch_dir() -> Result<PathBuf> {
    env::current_dir().context("determine current working directory")
}

pub fn default_accounts_dir() -> Result<PathBuf> {
    launch_dir()
}

pub fn default_account_dir(email: &str) -> Result<PathBuf> {
    Ok(default_accounts_dir()?.join(sanitize_segment(email.trim())))
}

pub fn account_file_name(email: &str) -> String {
    let _ = email;
    "session.json".to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::path::Path;

    use super::{
        account_file_name, default_account_dir, default_accounts_dir, disambiguated_name,
        join_rel_path, local_path, sanitize_segment,
    };

    #[test]
    fn sanitize_segment_replaces_path_separators() {
        assert_eq!(sanitize_segment(" a/b\\c "), "a_b_c");
    }

    #[test]
    fn join_rel_path_keeps_relative_form() {
        assert_eq!(join_rel_path("", "child"), "child");
        assert_eq!(join_rel_path("parent", "/child"), "parent/child");
        assert_eq!(join_rel_path("parent", "child"), "parent/child");
    }

    #[test]
    fn disambiguated_name_uses_id_for_duplicates() {
        let mut seen = HashMap::new();
        assert_eq!(
            disambiguated_name(&mut seen, "photo.jpg", "abcdef012345"),
            "photo.jpg"
        );
        assert_eq!(
            disambiguated_name(&mut seen, "photo.jpg", "1234567890ab"),
            "photo.jpg_12345678"
        );
    }

    #[test]
    fn disambiguated_name_handles_blank_names_and_duplicates_without_ids() {
        let mut seen = HashMap::new();
        assert_eq!(
            disambiguated_name(&mut seen, " .. ", "abcdef012345"),
            "file_abcdef01"
        );
        assert_eq!(disambiguated_name(&mut seen, ".", ""), "_");
        assert_eq!(disambiguated_name(&mut seen, ".", ""), "__2");
    }

    #[test]
    fn local_path_returns_root_for_empty_relative_path() {
        let root = Path::new("/tmp/photos");
        assert_eq!(local_path(root, ""), root);
        assert_eq!(
            local_path(root, "2026/photo.jpg"),
            root.join("2026/photo.jpg")
        );
    }

    #[test]
    fn account_file_name_uses_session_json() {
        assert_eq!(account_file_name("user@example.com"), "session.json");
        assert_eq!(account_file_name(" user/example.com "), "session.json");
    }

    #[test]
    fn default_accounts_dir_uses_current_directory() {
        assert_eq!(
            default_accounts_dir().expect("accounts dir"),
            env::current_dir().expect("cwd")
        );
    }

    #[test]
    fn default_account_dir_uses_email_folder() {
        let path = default_account_dir("user@example.com").expect("account dir");
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("user@example.com")
        );
    }
}
