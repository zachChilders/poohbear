//! An in-memory filesystem for one session.
//!
//! It is seeded from the host spec, then mutated by whatever the attacker
//! does (downloads, `echo > file`, `rm`). Every session gets its own copy, so
//! nothing an attacker does can affect another session.
//!
//! Ownership and permission bits are tracked so `ls -l` looks right and
//! writing somewhere an unprivileged user could not gives "Permission denied".
//! Size limits keep a hostile session from growing memory without bound.

use std::collections::BTreeMap;

/// Largest single file.
pub const MAX_FILE_BYTES: usize = 1 << 20;
/// Total bytes of file content in one session.
pub const MAX_TOTAL_BYTES: usize = 8 << 20;
/// Files plus directories in one session.
pub const MAX_NODES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub mode: u32,
    pub owner: String,
    pub group: String,
    /// Seconds since the Unix epoch.
    pub mtime: i64,
}

#[derive(Debug, Clone)]
pub enum Kind {
    Dir(BTreeMap<String, Node>),
    File(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: Kind,
    pub meta: Meta,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Dir(_))
    }

    pub fn size(&self) -> usize {
        match &self.kind {
            Kind::File(data) => data.len(),
            Kind::Dir(_) => 4096,
        }
    }

    fn count(&self) -> (usize, usize) {
        match &self.kind {
            Kind::File(d) => (1, d.len()),
            Kind::Dir(c) => c.values().fold((1, 0), |(n, b), c| {
                let (cn, cb) = c.count();
                (n + cn, b + cb)
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotADirectory,
    IsADirectory,
    Exists,
    NotEmpty,
    Denied,
    NoSpace,
}

impl FsError {
    /// The message coreutils prints for this error.
    pub fn message(self) -> &'static str {
        match self {
            FsError::NotFound => "No such file or directory",
            FsError::NotADirectory => "Not a directory",
            FsError::IsADirectory => "Is a directory",
            FsError::Exists => "File exists",
            FsError::NotEmpty => "Directory not empty",
            FsError::Denied => "Permission denied",
            FsError::NoSpace => "No space left on device",
        }
    }
}

/// Who is acting, for permission checks.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub name: &'a str,
}

impl Actor<'_> {
    fn is_root(&self) -> bool {
        self.name == "root"
    }
}

#[derive(Debug, Clone)]
pub struct Fs {
    root: Node,
}

/// Turn `path` (relative to `cwd`, or absolute) into a normalized absolute
/// path: no `.`, `..`, empty or trailing components.
pub fn normalize(cwd: &str, path: &str) -> String {
    let joined;
    let full = if path.starts_with('/') {
        path
    } else {
        joined = format!("{cwd}/{path}");
        &joined
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Split a normalized absolute path into (parent, name). `/` has no parent.
pub fn split(abs: &str) -> Option<(&str, &str)> {
    if abs == "/" {
        return None;
    }
    let i = abs.rfind('/')?;
    Some((if i == 0 { "/" } else { &abs[..i] }, &abs[i + 1..]))
}

impl Fs {
    pub fn new(root_meta: Meta) -> Fs {
        Fs {
            root: Node {
                kind: Kind::Dir(BTreeMap::new()),
                meta: root_meta,
            },
        }
    }

    fn components(abs: &str) -> impl Iterator<Item = &str> {
        abs.split('/').filter(|c| !c.is_empty())
    }

    pub fn node(&self, abs: &str) -> Option<&Node> {
        let mut cur = &self.root;
        for c in Self::components(abs) {
            match &cur.kind {
                Kind::Dir(children) => cur = children.get(c)?,
                Kind::File(_) => return None,
            }
        }
        Some(cur)
    }

    fn node_mut(&mut self, abs: &str) -> Option<&mut Node> {
        let mut cur = &mut self.root;
        for c in Self::components(abs) {
            match &mut cur.kind {
                Kind::Dir(children) => cur = children.get_mut(c)?,
                Kind::File(_) => return None,
            }
        }
        Some(cur)
    }

    pub fn exists(&self, abs: &str) -> bool {
        self.node(abs).is_some()
    }

    pub fn is_dir(&self, abs: &str) -> bool {
        self.node(abs).is_some_and(Node::is_dir)
    }

    pub fn read(&self, abs: &str) -> Result<&[u8], FsError> {
        match &self.node(abs).ok_or(FsError::NotFound)?.kind {
            Kind::File(data) => Ok(data),
            Kind::Dir(_) => Err(FsError::IsADirectory),
        }
    }

    pub fn list(&self, abs: &str) -> Result<Vec<(&str, &Node)>, FsError> {
        match &self.node(abs).ok_or(FsError::NotFound)?.kind {
            Kind::Dir(children) => Ok(children.iter().map(|(n, c)| (n.as_str(), c)).collect()),
            Kind::File(_) => Err(FsError::NotADirectory),
        }
    }

    /// (nodes, content bytes) currently stored.
    pub fn usage(&self) -> (usize, usize) {
        self.root.count()
    }

    // ---- permission checks -------------------------------------------------

    fn allowed(meta: &Meta, who: Actor, bit: u32) -> bool {
        who.is_root() || {
            let shift = if meta.owner == who.name { 6 } else { 0 };
            meta.mode & (bit << shift) != 0
        }
    }

    /// Can `who` reach `abs` at all? Every directory on the way needs search
    /// (`x`) permission, which is how a 0700 `/root` hides everything in it.
    pub fn can_traverse(&self, abs: &str, who: Actor) -> bool {
        if who.is_root() {
            return true;
        }
        let mut comps: Vec<&str> = Self::components(abs).collect();
        comps.pop(); // the target itself is checked by the caller
        let mut path = String::new();
        Self::allowed(&self.root.meta, who, 0o1)
            && comps.into_iter().all(|c| {
                path.push('/');
                path.push_str(c);
                self.node(&path)
                    .is_none_or(|n| Self::allowed(&n.meta, who, 0o1))
            })
    }

    pub fn can_read(&self, abs: &str, who: Actor) -> bool {
        self.can_traverse(abs, who)
            && self
                .node(abs)
                .is_some_and(|n| Self::allowed(&n.meta, who, 0o4))
    }

    /// Can an entry be created at `abs`? Its parent must exist and be a
    /// directory, which is reported before any permission question, as the
    /// kernel does.
    pub fn parent_ok(&self, abs: &str) -> Result<(), FsError> {
        let (parent, _) = split(abs).ok_or(FsError::Exists)?;
        match self.node(parent) {
            None => Err(FsError::NotFound),
            Some(n) if !n.is_dir() => Err(FsError::NotADirectory),
            Some(_) => Ok(()),
        }
    }

    /// May `who` create, modify or delete the entry at `abs`? Creating or
    /// deleting needs write access to the parent directory; modifying an
    /// existing file needs write access to it.
    pub fn can_write(&self, abs: &str, who: Actor) -> bool {
        if who.is_root() {
            return true;
        }
        if !self.can_traverse(abs, who) {
            return false;
        }
        match self.node(abs) {
            Some(n) if !n.is_dir() => Self::allowed(&n.meta, who, 0o2),
            _ => split(abs)
                .and_then(|(parent, _)| self.node(parent))
                .is_some_and(|p| Self::allowed(&p.meta, who, 0o2)),
        }
    }

    // ---- mutation ----------------------------------------------------------

    fn check_room(&self, adding_nodes: usize, adding_bytes: usize) -> Result<(), FsError> {
        let (nodes, bytes) = self.usage();
        if nodes + adding_nodes > MAX_NODES || bytes + adding_bytes > MAX_TOTAL_BYTES {
            return Err(FsError::NoSpace);
        }
        Ok(())
    }

    fn parent_dir_mut(
        &mut self,
        abs: &str,
    ) -> Result<(&mut BTreeMap<String, Node>, String), FsError> {
        let (parent, name) = split(abs).ok_or(FsError::Exists)?;
        let name = name.to_string();
        match &mut self.node_mut(parent).ok_or(FsError::NotFound)?.kind {
            Kind::Dir(children) => Ok((children, name)),
            Kind::File(_) => Err(FsError::NotADirectory),
        }
    }

    pub fn mkdir(&mut self, abs: &str, meta: Meta) -> Result<(), FsError> {
        self.check_room(1, 0)?;
        let (children, name) = self.parent_dir_mut(abs)?;
        if children.contains_key(&name) {
            return Err(FsError::Exists);
        }
        children.insert(
            name,
            Node {
                kind: Kind::Dir(BTreeMap::new()),
                meta,
            },
        );
        Ok(())
    }

    /// Create `abs` and any missing parents; existing directories are kept.
    pub fn mkdir_p(&mut self, abs: &str, meta: &Meta) -> Result<(), FsError> {
        let mut path = String::new();
        for c in Self::components(abs) {
            path.push('/');
            path.push_str(c);
            match self.node(&path) {
                Some(n) if n.is_dir() => {}
                Some(_) => return Err(FsError::NotADirectory),
                None => self.mkdir(&path, meta.clone())?,
            }
        }
        Ok(())
    }

    /// Write `data` to the file at `abs`, creating it with `meta` if needed.
    /// The parent directory must exist.
    pub fn write(
        &mut self,
        abs: &str,
        data: &[u8],
        append: bool,
        meta: Meta,
    ) -> Result<(), FsError> {
        let existing = match self.node(abs) {
            Some(n) if n.is_dir() => return Err(FsError::IsADirectory),
            Some(n) => n.size(),
            None => 0,
        };
        let new_len = if append {
            existing + data.len()
        } else {
            data.len()
        };
        if new_len > MAX_FILE_BYTES {
            return Err(FsError::NoSpace);
        }
        let adding_nodes = usize::from(!self.exists(abs));
        self.check_room(adding_nodes, new_len.saturating_sub(existing))?;
        let (children, name) = self.parent_dir_mut(abs)?;
        match children.get_mut(&name) {
            Some(Node {
                kind: Kind::File(bytes),
                meta: m,
            }) => {
                if !append {
                    bytes.clear();
                }
                bytes.extend_from_slice(data);
                m.mtime = meta.mtime;
            }
            _ => {
                children.insert(
                    name,
                    Node {
                        kind: Kind::File(data.to_vec()),
                        meta,
                    },
                );
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, abs: &str, recursive: bool) -> Result<(), FsError> {
        match self.node(abs) {
            None => return Err(FsError::NotFound),
            Some(Node {
                kind: Kind::Dir(c), ..
            }) if !recursive && !c.is_empty() => return Err(FsError::NotEmpty),
            Some(n) if n.is_dir() && !recursive => return Err(FsError::IsADirectory),
            Some(_) => {}
        }
        let (children, name) = self.parent_dir_mut(abs)?;
        children.remove(&name);
        Ok(())
    }

    /// Move `from` to `to`. If `to` is an existing directory the entry goes
    /// inside it; the caller resolves that before calling.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        if from == "/" || to == from || to.starts_with(&format!("{from}/")) {
            return Err(FsError::Denied);
        }
        let node = self.node(from).ok_or(FsError::NotFound)?.clone();
        if self.exists(to) {
            self.remove(to, true)?;
        }
        self.insert(to, node)?;
        self.remove(from, true)
    }

    /// Copy a file or directory tree to `to` (which must not exist).
    pub fn copy(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let node = self.node(from).ok_or(FsError::NotFound)?.clone();
        let (nodes, bytes) = node.count();
        self.check_room(nodes, bytes)?;
        self.insert(to, node)
    }

    fn insert(&mut self, abs: &str, node: Node) -> Result<(), FsError> {
        let (children, name) = self.parent_dir_mut(abs)?;
        children.insert(name, node);
        Ok(())
    }

    pub fn set_mode(&mut self, abs: &str, mode: u32) -> Result<(), FsError> {
        self.node_mut(abs).ok_or(FsError::NotFound)?.meta.mode = mode & 0o7777;
        Ok(())
    }

    pub fn set_owner(&mut self, abs: &str, owner: &str, group: &str) -> Result<(), FsError> {
        let meta = &mut self.node_mut(abs).ok_or(FsError::NotFound)?.meta;
        meta.owner = owner.into();
        meta.group = group.into();
        Ok(())
    }

    pub fn set_mtime(&mut self, abs: &str, mtime: i64) -> Result<(), FsError> {
        self.node_mut(abs).ok_or(FsError::NotFound)?.meta.mtime = mtime;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(owner: &str, mode: u32) -> Meta {
        Meta {
            mode,
            owner: owner.into(),
            group: owner.into(),
            mtime: 0,
        }
    }
    fn fs() -> Fs {
        let mut fs = Fs::new(meta("root", 0o755));
        fs.mkdir_p("/home/admin", &meta("admin", 0o755)).unwrap();
        fs.mkdir_p("/etc", &meta("root", 0o755)).unwrap();
        fs.mkdir_p("/tmp", &meta("root", 0o1777)).unwrap();
        fs.write("/etc/passwd", b"root:x:0:0\n", false, meta("root", 0o644))
            .unwrap();
        fs
    }
    const ADMIN: Actor = Actor { name: "admin" };
    const ROOT: Actor = Actor { name: "root" };

    #[test]
    fn normalize_resolves_relative_dots_and_slashes() {
        assert_eq!(normalize("/home/admin", "x"), "/home/admin/x");
        assert_eq!(normalize("/home/admin", "../x/./y//"), "/home/x/y");
        assert_eq!(normalize("/a", "/b/../../.."), "/");
        assert_eq!(normalize("/", ""), "/");
    }

    #[test]
    fn split_paths() {
        assert_eq!(split("/a/b"), Some(("/a", "b")));
        assert_eq!(split("/a"), Some(("/", "a")));
        assert_eq!(split("/"), None);
    }

    #[test]
    fn write_read_append_and_list() {
        let mut fs = fs();
        fs.write("/tmp/a", b"hi", false, meta("admin", 0o644))
            .unwrap();
        fs.write("/tmp/a", b" there", true, meta("admin", 0o644))
            .unwrap();
        assert_eq!(fs.read("/tmp/a").unwrap(), b"hi there");
        fs.write("/tmp/a", b"x", false, meta("admin", 0o644))
            .unwrap();
        assert_eq!(fs.read("/tmp/a").unwrap(), b"x", "truncate");
        let names: Vec<_> = fs
            .list("/tmp")
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["a"]);
    }

    #[test]
    fn errors_match_what_coreutils_would_say() {
        let mut fs = fs();
        assert_eq!(fs.read("/nope"), Err(FsError::NotFound));
        assert_eq!(fs.read("/etc"), Err(FsError::IsADirectory));
        assert_eq!(fs.list("/etc/passwd").unwrap_err(), FsError::NotADirectory);
        assert_eq!(fs.mkdir("/etc", meta("root", 0o755)), Err(FsError::Exists));
        assert_eq!(
            fs.mkdir("/nope/x", meta("root", 0o755)),
            Err(FsError::NotFound)
        );
        assert_eq!(
            fs.write("/etc/passwd/x", b"", false, meta("root", 0o644)),
            Err(FsError::NotADirectory)
        );
        assert_eq!(
            fs.write("/etc", b"", false, meta("root", 0o644)),
            Err(FsError::IsADirectory)
        );
        assert_eq!(fs.remove("/etc", false), Err(FsError::NotEmpty));
        assert_eq!(fs.remove("/nope", false), Err(FsError::NotFound));
        assert_eq!(FsError::Denied.message(), "Permission denied");
    }

    #[test]
    fn permissions_follow_owner_and_mode() {
        let fs = fs();
        assert!(fs.can_write("/home/admin/new", ADMIN), "own home");
        assert!(fs.can_write("/tmp/x", ADMIN), "world-writable /tmp");
        assert!(!fs.can_write("/etc/passwd", ADMIN), "root-owned 0644");
        assert!(!fs.can_write("/etc/new", ADMIN), "root-owned dir");
        assert!(fs.can_write("/etc/passwd", ROOT));
        assert!(fs.can_read("/etc/passwd", ADMIN));
        let mut fs = fs;
        fs.write("/etc/shadow", b"x", false, meta("root", 0o640))
            .unwrap();
        assert!(!fs.can_read("/etc/shadow", ADMIN));
        assert!(fs.can_read("/etc/shadow", ROOT));
    }

    #[test]
    fn a_directory_you_cannot_search_hides_everything_inside_it() {
        let mut fs = fs();
        fs.mkdir_p("/secret", &meta("root", 0o700)).unwrap();
        fs.write("/secret/key", b"k", false, meta("root", 0o644))
            .unwrap();
        fs.mkdir_p("/open", &meta("root", 0o755)).unwrap();
        fs.write("/open/a", b"a", false, meta("root", 0o644))
            .unwrap();
        assert!(!fs.can_traverse("/secret/key", ADMIN));
        assert!(
            !fs.can_read("/secret/key", ADMIN),
            "file is world-readable but its directory is not searchable"
        );
        assert!(!fs.can_write("/secret/new", ADMIN));
        assert!(fs.can_read("/open/a", ADMIN));
        assert!(fs.can_traverse("/secret/key", ROOT));
        // the directory itself can still be named; only its contents are hidden
        assert!(fs.can_traverse("/secret", ADMIN));
    }

    #[test]
    fn parent_ok_reports_missing_and_non_directory_parents() {
        let fs = fs();
        assert_eq!(fs.parent_ok("/tmp/new"), Ok(()));
        assert_eq!(fs.parent_ok("/nope/new"), Err(FsError::NotFound));
        assert_eq!(fs.parent_ok("/etc/passwd/new"), Err(FsError::NotADirectory));
        assert_eq!(fs.parent_ok("/"), Err(FsError::Exists));
    }

    #[test]
    fn mkdir_p_creates_parents_and_refuses_to_replace_files() {
        let mut fs = fs();
        fs.mkdir_p("/var/log/app", &meta("root", 0o755)).unwrap();
        assert!(fs.is_dir("/var/log/app"));
        fs.mkdir_p("/var/log/app", &meta("root", 0o755)).unwrap();
        assert_eq!(
            fs.mkdir_p("/etc/passwd/sub", &meta("root", 0o755)),
            Err(FsError::NotADirectory)
        );
    }

    #[test]
    fn remove_recursive_rename_and_copy() {
        let mut fs = fs();
        fs.write("/tmp/a", b"1", false, meta("admin", 0o644))
            .unwrap();
        fs.rename("/tmp/a", "/tmp/b").unwrap();
        assert!(!fs.exists("/tmp/a") && fs.exists("/tmp/b"));
        fs.copy("/tmp/b", "/tmp/c").unwrap();
        assert_eq!(fs.read("/tmp/c").unwrap(), b"1");
        fs.mkdir("/tmp/d", meta("admin", 0o755)).unwrap();
        fs.write("/tmp/d/e", b"2", false, meta("admin", 0o644))
            .unwrap();
        assert_eq!(fs.remove("/tmp/d", false), Err(FsError::NotEmpty));
        fs.remove("/tmp/d", true).unwrap();
        assert!(!fs.exists("/tmp/d"));
        assert_eq!(fs.rename("/", "/x"), Err(FsError::Denied));
        assert_eq!(
            fs.rename("/tmp", "/tmp/inside"),
            Err(FsError::Denied),
            "no moving a dir into itself"
        );
    }

    #[test]
    fn modes_and_times_can_be_changed() {
        let mut fs = fs();
        fs.write("/tmp/a", b"1", false, meta("admin", 0o644))
            .unwrap();
        fs.set_mode("/tmp/a", 0o755).unwrap();
        fs.set_mtime("/tmp/a", 42).unwrap();
        let m = &fs.node("/tmp/a").unwrap().meta;
        assert_eq!((m.mode, m.mtime), (0o755, 42));
        assert_eq!(fs.set_mode("/nope", 0o777), Err(FsError::NotFound));
    }

    #[test]
    fn size_limits_stop_a_hostile_session_from_growing_memory() {
        let mut fs = fs();
        let big = vec![0u8; MAX_FILE_BYTES + 1];
        assert_eq!(
            fs.write("/tmp/big", &big, false, meta("admin", 0o644)),
            Err(FsError::NoSpace)
        );
        // appending cannot sneak past the per-file cap either
        let chunk = vec![0u8; MAX_FILE_BYTES];
        fs.write("/tmp/f", &chunk, false, meta("admin", 0o644))
            .unwrap();
        assert_eq!(
            fs.write("/tmp/f", b"x", true, meta("admin", 0o644)),
            Err(FsError::NoSpace)
        );
        // many files hit the total cap
        let mut hit = false;
        for i in 0..20 {
            if fs
                .write(&format!("/tmp/g{i}"), &chunk, false, meta("admin", 0o644))
                .is_err()
            {
                hit = true;
                break;
            }
        }
        assert!(hit, "total cap must trigger");
        assert!(fs.usage().1 <= MAX_TOTAL_BYTES);
        // node cap
        let mut fs2 = Fs::new(meta("root", 0o755));
        let mut hit = false;
        for i in 0..MAX_NODES + 5 {
            if fs2.mkdir(&format!("/d{i}"), meta("root", 0o755)).is_err() {
                hit = true;
                break;
            }
        }
        assert!(hit, "node cap must trigger");
    }

    #[test]
    fn copy_respects_the_cap_too() {
        let mut fs = fs();
        let chunk = vec![1u8; MAX_FILE_BYTES];
        fs.write("/tmp/f", &chunk, false, meta("admin", 0o644))
            .unwrap();
        let mut failed = false;
        for i in 0..20 {
            if fs.copy("/tmp/f", &format!("/tmp/c{i}")).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
    }
}
