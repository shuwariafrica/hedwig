//! Readiness: what the core learns from a remote before the channel, and what
//! it has the remote's own tools do there.
//!
//! A survey is one run of the route's client, in the connection's job, that
//! hands a script to a shell of the remote's own on its standard input and
//! reads a report from its output. The script asks the remote's tools where
//! each capability goes, makes the folder a socket needs, removes a socket
//! nothing answers at, and reports the rest. It never stops, removes or
//! rewrites anything that answers.
//!
//! Everything here is a plain function: the script from a plan, the report
//! from what the remote printed, and what each capability's far end is from
//! the report. The performer that runs it is in [`crate::channel`].

use std::collections::BTreeMap;
use std::fmt::Write as _;

use hedwig_model::capability::{AGENT_VARIABLE, Form, Query, ServicePort};
use hedwig_model::platform::{Platform, Sockets};
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{
    Fingerprint, Kernel, Mark, Name, Port, RemotePath, Template, Variable, Words,
};
use hedwig_model::trail::{Asking, Binding, Finding, Prepared, Readiness, Serving, Write};

/// The shell a survey's script is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dialect {
    /// `/bin/sh`, which every Unix remote has whatever the person's login
    /// shell is.
    Posix,
    /// Windows PowerShell, which every Windows remote has whatever its
    /// `sshd`'s `DefaultShell` is.
    PowerShell,
}

impl Dialect {
    const fn word(self) -> &'static str {
        match self {
            Dialect::Posix => "posix",
            Dialect::PowerShell => "powershell",
        }
    }

    /// The dialect a remote is surveyed in first: the one its last observed
    /// platform takes, and POSIX for a remote never reached. A remote whose
    /// POSIX survey finds no POSIX shell is surveyed again in PowerShell.
    pub fn first(last: Option<&Platform>) -> Dialect {
        match last.map(|platform| platform.sockets) {
            Some(Sockets::Emulated) => Dialect::PowerShell,
            Some(Sockets::Unix { .. }) | None => Dialect::Posix,
        }
    }
}

/// One thing readiness asks about a capability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Question {
    /// Where the remote's `gpgconf` puts one of gpg-agent's sockets. On a
    /// Unix remote that is the socket the forward binds; on a Windows remote,
    /// the file that names the forward's port.
    Socket(Query),
    /// A socket in a folder private to the remote user, which the tool is
    /// pointed at through its variable.
    Private { variable: Variable, value: Template },
    /// A port on the remote's loopback.
    Port(Port),
    /// A socket in a folder private to the remote user, which the remote's
    /// openers reach through its own `curl`, named in `BROWSER` and
    /// `GH_BROWSER`.
    Opener,
    /// A socket in a folder private to the remote user, which the remote's
    /// own `git` asks through its own `cache` helper, named in its global
    /// configuration.
    Helper,
    /// A socket in a folder private to the remote user, which the remote's
    /// own hooks reach through its own `curl`, named in `HEDWIG_NOTIFY`.
    Notifier,
}

impl Question {
    /// The questions a capability's forms raise, one per distinct question.
    pub fn of(forms: &[Form]) -> Vec<Question> {
        let mut questions: Vec<Question> = forms
            .iter()
            .filter_map(|form| match form {
                Form::SocketAt(query) | Form::SocketFileAt(query) => Some(Question::Socket(*query)),
                Form::PrivateSocket { variable, value } => Some(Question::Private {
                    variable: variable.clone(),
                    value: value.clone(),
                }),
                Form::Port(ServicePort::Fixed(port)) => Some(Question::Port(*port)),
                Form::Opener => Some(Question::Opener),
                Form::Helper => Some(Question::Helper),
                Form::Notifier => Some(Question::Notifier),
                Form::Port(ServicePort::Unstated) => None,
            })
            .collect();
        questions.sort();
        questions.dedup();
        questions
    }
}

/// What readiness asks about one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub capability: Name,
    pub questions: Vec<Question>,
    /// The program whose own server the capability's tool starts where it
    /// finds none - `adb` for ADB - so readiness names one it finds holding
    /// the binding.
    pub server: Option<Name>,
}

/// The program whose own server `capability`'s tool starts where it finds
/// none, which readiness names where it finds one holding the binding.
pub fn server(capability: &hedwig_model::capability::Capability) -> Option<Name> {
    match capability.dialect() {
        hedwig_model::capability::Dialect::Adb => Name::try_from("adb").ok(),
        hedwig_model::capability::Dialect::Assuan(_)
        | hedwig_model::capability::Dialect::SshAgent
        | hedwig_model::capability::Dialect::Opaque
        | hedwig_model::capability::Dialect::Browser
        | hedwig_model::capability::Dialect::Serial
        | hedwig_model::capability::Dialect::Credential
        | hedwig_model::capability::Dialect::Notice => None,
    }
}

/// Everything a survey asks, as the deciding thread made it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub asks: Vec<Asked>,
    /// The far ends a live forward of this connection holds. They are never
    /// probed: a probe would reach the core through its own forward.
    pub ours: Vec<RemotePath>,
    /// The keys the workstation offers, whose public halves the remote's
    /// keyring should hold.
    pub keys: Vec<Fingerprint>,
    /// What the grants' consent has Hedwig write for each capability, where
    /// the remote lacks it.
    pub writes: Vec<(Name, Write)>,
    /// What Hedwig wrote before and no consent covers any more: it is taken
    /// back.
    pub undo: Vec<Undo>,
    /// The public keys, armoured, that a [`Write::PublicKey`] imports.
    pub armoured: BTreeMap<Fingerprint, String>,
    /// The sixteen bytes a Windows remote's socket file is written with,
    /// drawn by the performer for this survey.
    pub issued: Option<[u8; 16]>,
}

impl Plan {
    fn writes(&self, capability: &str) -> impl Iterator<Item = &Write> {
        self.writes
            .iter()
            .filter(move |(of, _)| of.as_str() == capability)
            .map(|(_, write)| write)
    }
}

/// A write Hedwig made on a remote, which a survey takes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undo {
    pub capability: Name,
    pub write: Write,
    /// The file, keyring or unit the write is.
    pub place: RemotePath,
    /// What the write made: the outermost folder, taken back with it while
    /// empty; or for a key, the keybox its import made, taken back once no
    /// key is left in it.
    pub made: Option<RemotePath>,
}

/// A write as a report names it.
pub fn write_word(write: &Write) -> String {
    match write {
        Write::NoAutostart => "no-autostart".to_owned(),
        Write::SocketFile => "socket-file".to_owned(),
        Write::Masked => "masked".to_owned(),
        Write::PublicKey(key) => format!("public-key:{key}"),
        Write::SigningKey(key) => format!("signing-key:{key}"),
        Write::Variable(variable) => format!("variable:{variable}"),
        Write::Helper => "credential-helper".to_owned(),
    }
}

fn written_as(word: &str) -> Option<Write> {
    match word.split_once(':') {
        None if word == "no-autostart" => Some(Write::NoAutostart),
        None if word == "credential-helper" => Some(Write::Helper),
        None if word == "socket-file" => Some(Write::SocketFile),
        None if word == "masked" => Some(Write::Masked),
        Some(("public-key", key)) => Fingerprint::try_from(key).ok().map(Write::PublicKey),
        Some(("signing-key", key)) => Mark::try_from(key).ok().map(Write::SigningKey),
        Some(("variable", variable)) => Variable::try_from(variable).ok().map(Write::Variable),
        _ => None,
    }
}

/// The name Hedwig's lines for a write carry in the file they are in, so it
/// finds them again, and the person can tell them from their own.
fn block(capability: &str, write: &Write) -> String {
    match write {
        Write::NoAutostart => format!("{capability} no-autostart"),
        Write::SigningKey(_) => format!("{capability} signing-key"),
        Write::Variable(variable) => format!("{capability} {variable}"),
        Write::PublicKey(key) => format!("{capability} public-key {key}"),
        Write::SocketFile => format!("{capability} socket-file"),
        Write::Masked => format!("{capability} masked"),
        Write::Helper => format!("{capability} credential-helper"),
    }
}

/// The word that begins every line of a report, before the survey's nonce.
const MARK: &str = "hedwig";

/// What every `gpg` a survey runs on a remote is given: it reads and writes
/// the keyring and never makes a trust database the home did not have.
const TRUST: &str = "--trust-model always --no-auto-check-trustdb";

/// The keybox a key's import makes where the home has no keyring.
const KEYBOX: &str = "pubring.kbx";

/// How long a probe waits for anything at a socket to answer, in seconds.
/// Invariant: an agent on the same host answers at once and a forward's far
/// end within one round trip of the link the channel keeps alive; three
/// seconds is the least that covers a slow link and costs a survey little.
pub const PROBE: u32 = 3;

/// The options a survey's connection is started with, between what the
/// route's entry puts before and after them. It opens a session with no
/// terminal and runs a command, whatever the person's configuration says for
/// the host, and asks for none of the forwards that configuration declares:
/// they are the channel's to ask for.
pub fn options(asking: Asking, keepalive: Keepalive) -> Vec<String> {
    let batch = match asking {
        Asking::Person => "BatchMode=no",
        Asking::Nobody => "BatchMode=yes",
    };
    let set = [
        batch,
        "LogLevel=INFO",
        "Tag=hedwig",
        "ForwardAgent=no",
        "ForwardX11=no",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "ControlPath=none",
        // The person's own forwards are the channel's; a survey that asked
        // for them would hold their ports while the channel starts.
        "ClearAllForwardings=yes",
        // The command is the survey's, and it reads the script from its
        // input: nothing the person's configuration says for the host may
        // replace the one or close the other.
        "RemoteCommand=none",
        "SessionType=default",
        "StdinNull=no",
        "ForkAfterAuthentication=no",
        "EscapeChar=none",
    ];
    let mut options = vec!["-T".to_owned()];
    for option in set {
        options.extend(["-o".to_owned(), option.to_owned()]);
    }
    options.extend([
        "-o".to_owned(),
        format!("ServerAliveInterval={}", keepalive.every),
        "-o".to_owned(),
        format!("ServerAliveCountMax={}", keepalive.missed),
    ]);
    options
}

/// The command the remote runs: a shell of its own that reads the script
/// from its input. Each is one program and plain words, which every shell a
/// remote may start it from - sh, bash, zsh, fish, csh, cmd, PowerShell -
/// reads the same way.
pub fn command(dialect: Dialect) -> Vec<String> {
    match dialect {
        Dialect::Posix => vec!["/bin/sh".to_owned(), "-s".to_owned()],
        Dialect::PowerShell => vec![
            "powershell".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-EncodedCommand".to_owned(),
            encoded(BOOTSTRAP),
        ],
    }
}

/// What Windows PowerShell is started with: read the script from the input to
/// its end, and run it. The script itself never appears on a command line,
/// where another user of a Windows remote could read it.
const BOOTSTRAP: &str = "$s = [Console]::In.ReadToEnd(); Invoke-Expression $s";

/// `text` as PowerShell's `-EncodedCommand` takes it: UTF-16LE in base64.
fn encoded(text: &str) -> String {
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    hedwig_model::text::to_base64(&bytes)
}

/// `text` as one word of a POSIX shell script, quoted so nothing in it is
/// read by the shell.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// `text` as one PowerShell string literal.
fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The script a POSIX shell runs. `nonce` begins every line it reports, so
/// nothing a login script prints can be read as the report.
#[allow(
    clippy::too_many_lines,
    reason = "the script's own functions are one text, read as the remote reads it"
)]
pub fn posix(plan: &Plan, nonce: &str) -> String {
    let mut script = String::new();
    let _ = write!(
        script,
        r##"LC_ALL=C
export LC_ALL
n={nonce}
say() {{ printf '{MARK} %s %s\n' "$n" "$*"; }}
hex() {{ h=$(printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'); printf '%s' "${{h:--}}"; }}
ours() {{ case $1 in {ours}) return 0 ;; esac; return 1; }}
bounded() {{
  "$@" </dev/null 2>&1 &
  p=$!
  ( sleep {PROBE}; kill "$p" ) </dev/null >/dev/null 2>&1 &
  k=$!
  wait "$p"
  s=$?
  kill "$k" 2>/dev/null
  printf '\nstatus %s\n' "$s"
}}
served() {{
  case $2 in assuan|other) return 1 ;; esac
  command -v ss >/dev/null 2>&1 || return 1
  case $1 in
    /*) ss -Hxlp src "$1" 2>/dev/null | grep -qF "((\"$2\"," ;;
    *) ss -Hltpn "sport = :$1" 2>/dev/null | grep -qF "((\"$2\"," ;;
  esac
}}
probe() {{
  if served "$1" "$2"; then echo "server $2"; return; fi
  if [ "$2" = assuan ] && command -v gpg-connect-agent >/dev/null 2>&1; then
    o=$(bounded gpg-connect-agent -S "$1" 'GETINFO pid' /bye)
    case $o in
      *'status 0') i=$(printf '%s\n' "$o" | sed -n 's/^D //p')
        if [ -n "$i" ] && kill -0 "$i" 2>/dev/null; then echo agent; else echo answers; fi ;;
      *'IPC connect call failed'*) echo refused ;;
      *'End of file'*) echo closed ;;
      *'status 0'|*'status 1') echo "unprobed $(hex "$o")" ;;
      *) echo silent ;;
    esac
  elif command -v ssh-add >/dev/null 2>&1; then
    o=$(SSH_AUTH_SOCK=$1 bounded ssh-add -l)
    case $o in
      *'Connection refused'*) echo refused ;;
      *'communication with agent failed'*) echo closed ;;
      *'status 0'|*'status 1') echo answers ;;
      *'status 2') echo "unprobed $(hex "$o")" ;;
      *) echo silent ;;
    esac
  elif command -v gpg-connect-agent >/dev/null 2>&1; then
    probe "$1" assuan
  else
    echo unprobed
  fi
}}
held() {{
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl --user list-sockets --no-legend --no-pager 2>/dev/null | while IFS= read -r l; do
    case $l in "$1 "*) r=${{l#"$1"}}; set -- $r; printf '%s %s\n' "$1" "${{2%,}}"; break ;; esac
  done
}}
outermost() {{ od=$1 om=; while [ ! -e "$od" ] && [ ! -L "$od" ]; do om=$od; od=$(dirname -- "$od"); done; printf '%s' "$om"; }}
keyring() {{ [ -e "$1/pubring.kbx" ] || [ -e "$1/pubring.gpg" ] || [ -e "$1/public-keys.d" ]; }}
unmade() {{
  [ -n "$2" ] || return 0
  ud=$(dirname -- "$1")
  while :; do
    case $ud in "$2"|"$2"/*) ;; *) return 0 ;; esac
    rmdir -- "$ud" 2>/dev/null || return 0
    [ "$ud" = "$2" ] && return 0
    ud=$(dirname -- "$ud")
  done
}}
noted() {{ if [ -n "$5" ]; then say "$1" "$2" "$3" "$(hex "$4")" "$(hex "$5")"; else say "$1" "$2" "$3" "$(hex "$4")"; fi; }}
mask() {{
  mu=$2 ms=$3 md=${{XDG_CONFIG_HOME:-$HOME/.config}}/systemd/user
  mm=$(outermost "$md")
  if me=$(systemctl --user mask --now -- "$mu" 2>&1); then
    [ -z "$ms" ] || systemctl --user stop -- "$ms" >/dev/null 2>&1
    [ -d "$mm" ] || mm=
    noted wrote "$1" masked "$md/$mu" "$mm"
  else
    say unwritten "$1" masked "$(hex "$me")"
  fi
}}
place() {{
  c=$1 p=$2
  say path "$c" "$(hex "$p")"
  case $p in /*) ;; *) return ;; esac
  d=$(dirname -- "$p")
  if [ ! -d "$d" ]; then
    if e=$( (umask 077 && mkdir -p -- "$d") 2>&1 ); then
      say created "$c" "$(hex "$d")"
    else
      say uncreatable "$c" "$(hex "$e")"
      return
    fi
  fi
  case $d in "$HOME"/*|"$HOME")
    f=$(stat -f -c %T -- "$d" 2>/dev/null) && say filesystem "$c" "$(hex "$f")" ;;
  esac
  if ours "$p"; then
    say at "$c" ours
    return
  fi
  u=$(held "$p")
  if [ -n "$u" ] && [ "${{4:-}}" = mask ]; then
    mask "$c" $u
    u=$(held "$p")
  fi
  if [ -n "$u" ]; then
    say at "$c" held "$(hex "${{u%% *}}")"
  elif [ -S "$p" ]; then
    a=$(probe "$p" "$3")
    case $a in silent|closed) a=$(probe "$p" "$3") ;; esac
    case $a in
      refused)
        if e=$(rm -f -- "$p" 2>&1); then say at "$c" removed; else say at "$c" uncleared "$(hex "$e")"; fi ;;
      closed) say at "$c" silent ;;
      unprobed\ *) say at "$c" unprobed ;;
      server\ *) say at "$c" $a ;;
      *) say at "$c" "$a" ;;
    esac
  elif [ -e "$p" ] || [ -L "$p" ]; then
    say at "$c" occupied
  else
    say at "$c" free
  fi
}}
mark() {{ printf '# hedwig %s: written by Hedwig with your consent; Hedwig removes it when that ends' "$1"; }}
earlier() {{ printf '# hedwig %s: written by hedwig with your consent; hedwig removes it when that ends' "$1"; }}
present() {{ [ -f "$1" ] && {{ grep -qxF "$(mark "$2")" "$1" || grep -qxF "$(earlier "$2")" "$1"; }}; }}
inside() {{ awk -v b="$(mark "$2")" -v o="$(earlier "$2")" -v e="# hedwig $2: end" '$0 == e {{ k = 0 }} k {{ print }} $0 == b || $0 == o {{ k = 1 }}' "$1"; }}
unblock() {{
  present "$1" "$2" || return 0
  b=$(mark "$2") o=$(earlier "$2")
  e="# hedwig $2: end"
  [ $(( $(grep -cxF "$b" "$1") + $(grep -cxF "$o" "$1") )) = 1 ] && [ "$(grep -cxF "$e" "$1")" = 1 ] || return 1
  (umask 077 && awk -v b="$b" -v o="$o" -v e="$e" '$0 == b || $0 == o {{ k = 1; next }} k && $0 == e {{ k = 0; next }} !k' "$1" > "$1.hedwig") &&
    cat "$1.hedwig" > "$1" && rm -f -- "$1.hedwig" || return 1
  [ -s "$1" ] || rm -f -- "$1"
}}
ensure() {{
  if present "$1" "$2"; then
    if [ "$(inside "$1" "$2")" = "$3" ] && grep -qxF "$(mark "$2")" "$1"; then echo kept; return; fi
    unblock "$1" "$2" || {{ echo "failed $(hex "Hedwig's lines in $1 were changed by hand")"; return; }}
  fi
  d=$(dirname -- "$1") m=
  if [ ! -d "$d" ]; then
    m=$(outermost "$d")
    e=$( (umask 077 && mkdir -p -- "$d") 2>&1 ) || {{ echo "failed $(hex "$e")"; return; }}
  fi
  if [ "${{4:-}}" = first ] && [ -s "$1" ]; then
    e=$( (umask 077 && {{ mark "$2"; printf '\n%s\n# hedwig %s: end\n' "$3" "$2"; cat -- "$1"; }} > "$1.hedwig") 2>&1 ) &&
      e=$(cat -- "$1.hedwig" 2>&1 > "$1") || {{ rm -f -- "$1.hedwig"; echo "failed $(hex "$e")"; return; }}
    rm -f -- "$1.hedwig"
  else
    if [ -s "$1" ] && [ -n "$(tail -c 1 "$1")" ]; then printf '\n' >> "$1"; fi
    e=$( {{ mark "$2"; printf '\n%s\n# hedwig %s: end\n' "$3" "$2"; }} 2>&1 >> "$1" ) || {{ echo "failed $(hex "$e")"; return; }}
  fi
  echo "wrote $(hex "$m")"
}}
put() {{
  r=$(ensure "$3" "$4" "$5" "${{6:-}}")
  case $r in
    'wrote -') say wrote "$1" "$2" "$(hex "$3")" ;;
    wrote\ *) say wrote "$1" "$2" "$(hex "$3")" "${{r#wrote }}" ;;
    kept) say kept "$1" "$2" "$(hex "$3")" ;;
    failed\ *) say unwritten "$1" "$2" "${{r#failed }}" ;;
  esac
}}
quote() {{ printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }}
fishquote() {{ printf "'%s'" "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g")"; }}
fishwords() ( set -f; o=; for w in $1; do o="$o $(fishquote "$w")"; done; printf '%s' "${{o# }}" )
cquote() {{ printf "'%s'" "$(printf '%s' "$1" | sed -e "s/'/'\\\\''/g" -e 's/!/\\!/g')"; }}
nuquote() {{ printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }}
login() {{
  for f in .bash_profile .bash_login .profile; do
    if [ -f "$HOME/$f" ]; then echo "$HOME/$f"; return; fi
  done
  echo "$HOME/.profile"
}}
setvar() {{
  case ${{SHELL##*/}} in
    bash)
      l="export $2=$(quote "$3")"
      put "$1" "variable:$2" "$HOME/.bashrc" "$1 $2" "$l" first
      put "$1" "variable:$2" "$(login)" "$1 $2" "$l" first ;;
    zsh) put "$1" "variable:$2" "${{ZDOTDIR:-$HOME}}/.zshenv" "$1 $2" "export $2=$(quote "$3")" first ;;
    fish)
      if [ "${{4:-}}" = words ]; then v=$(fishwords "$3"); else v=$(fishquote "$3"); fi
      put "$1" "variable:$2" "${{XDG_CONFIG_HOME:-$HOME/.config}}/fish/config.fish" "$1 $2" "set -gx $2 $v" first ;;
    tcsh)
      if [ -f "$HOME/.tcshrc" ]; then f=$HOME/.tcshrc; else f=$HOME/.cshrc; fi
      put "$1" "variable:$2" "$f" "$1 $2" "setenv $2 $(cquote "$3")" first ;;
    csh) put "$1" "variable:$2" "$HOME/.cshrc" "$1 $2" "setenv $2 $(cquote "$3")" first ;;
    sh|dash|ksh|ksh93|mksh) put "$1" "variable:$2" "$HOME/.profile" "$1 $2" "export $2=$(quote "$3")" first ;;
    nu)
      f=$(nu -n -c '$nu.default-config-dir' 2>/dev/null)
      put "$1" "variable:$2" "${{f:-${{XDG_CONFIG_HOME:-$HOME/.config}}/nushell}}/config.nu" "$1 $2" "\$env.$2 = $(nuquote "$3")" first ;;
    *) say unwritten "$1" "variable:$2" "$(hex "${{SHELL:-the login shell}} reads its startup from files Hedwig does not know")" ;;
  esac
}}
gitconfig() {{
  if [ -n "${{GIT_CONFIG_GLOBAL:-}}" ]; then echo "$GIT_CONFIG_GLOBAL"
  elif [ -f "$HOME/.gitconfig" ]; then echo "$HOME/.gitconfig"
  elif [ -f "${{XDG_CONFIG_HOME:-$HOME/.config}}/git/config" ]; then echo "${{XDG_CONFIG_HOME:-$HOME/.config}}/git/config"
  else echo "$HOME/.gitconfig"
  fi
}}
listening() {{
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p "$" {{ f = 1 }} END {{ exit !f }}'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | awk -v p="$1" '/LISTEN/ {{ for (i = 1; i <= NF; i++) if ($i ~ "[.:]" p "$") f = 1 }} END {{ exit !f }}'
  else
    return 2
  fi
}}
say begin posix
say kernel "$(hex "$(uname -s)")"
say shell "$(hex "${{SHELL:-}}")"
{seen}{undo}"##,
        seen = posix_seen(plan),
        undo = posix_undo(plan),
        ours = if plan.ours.is_empty() {
            "''".to_owned()
        } else {
            plan.ours
                .iter()
                .map(|path| quoted(path.as_str()))
                .collect::<Vec<_>>()
                .join("|")
        },
    );
    for asked in &plan.asks {
        let capability = asked.capability.as_str();
        for question in &asked.questions {
            match question {
                Question::Socket(query) => {
                    let (list, kind) = match query {
                        Query::AgentSocket => ("agent-socket", "assuan"),
                        Query::AgentSshSocket => ("agent-ssh-socket", "other"),
                    };
                    let _ = write!(
                        script,
                        r#"if command -v gpgconf >/dev/null 2>&1; then
  place {capability} "$(gpgconf --list-dirs {list})" {kind} {mask}
  h=$(gpgconf --list-dirs homedir)
"#,
                        mask = if plan.writes(capability).any(|write| *write == Write::Masked) {
                            "mask"
                        } else {
                            "keep"
                        },
                    );
                    if *query == Query::AgentSshSocket {
                        let _ =
                            writeln!(script, "  {}", sees(capability, "SSH_AUTH_SOCK", "\"$p\""));
                    }
                    if *query == Query::AgentSocket {
                        posix_gnupg_writes(&mut script, plan, capability);
                    } else if let Some(Write::Variable(variable)) = plan
                        .writes(capability)
                        .find(|write| matches!(write, Write::Variable(_)))
                    {
                        let _ = writeln!(script, r#"  setvar {capability} {variable} "$p""#);
                    }
                    let _ = write!(
                        script,
                        r#"  if grep -qs '^[[:space:]]*no-autostart' "$h/common.conf" "$h/gpg.conf"; then say autostart {capability} off; else say autostart {capability} on; fi
  if grep -qs '^[[:space:]]*use-keyboxd' "$h/common.conf"; then say keyboxd {capability} on; else say keyboxd {capability} off; fi
"#
                    );
                    if *query == Query::AgentSocket {
                        for key in &plan.keys {
                            let _ = writeln!(
                                script,
                                "  if keyring \"$h\" && gpg --no-autostart --batch {TRUST} --list-keys --with-colons -- {key} >/dev/null 2>&1; then say key {capability} {key} present; else say key {capability} {key} absent; fi",
                                key = quoted(key.as_str()),
                            );
                        }
                        let _ = write!(
                            script,
                            r#"  if command -v git >/dev/null 2>&1; then
    v=$(git config --global --get user.signingkey)
    if [ -n "$v" ]; then say signing {capability} "$(hex "$v")"; else say signing {capability} unset; fi
    say format {capability} "$(hex "$(git config --global --get gpg.format)")"
  fi
"#
                        );
                    }
                    let fallback = *query == Query::AgentSshSocket
                        && plan.writes(capability).any(|write| {
                            matches!(write, Write::Variable(variable) if variable.as_str() == AGENT_VARIABLE)
                        });
                    if fallback {
                        // An SSH client needs no GnuPG: where the remote has
                        // none, the agent's socket is Hedwig's own, and
                        // `SSH_AUTH_SOCK` names it.
                        let _ = write!(
                            script,
                            r#"else
  if [ -n "${{XDG_RUNTIME_DIR:-}}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then r=$XDG_RUNTIME_DIR/hedwig; else r=$HOME/.hedwig; fi
  hedwig=$r
  [ -d "$r" ] && chmod u+w "$r"
  place {capability} "$r/{capability}" other
  {sees}
  setvar {capability} {AGENT_VARIABLE} "$r/{capability}"
fi
"#,
                            sees =
                                sees(capability, AGENT_VARIABLE, &format!(r#""$r/{capability}""#)),
                        );
                    } else {
                        let _ = write!(script, "else\n  say absent {capability} gpgconf\nfi\n");
                    }
                }
                Question::Private { variable, value } => {
                    let _ = write!(
                        script,
                        r#"if [ -n "${{XDG_RUNTIME_DIR:-}}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then r=$XDG_RUNTIME_DIR/hedwig; else r=$HOME/.hedwig; fi
hedwig=$r
[ -d "$r" ] && chmod u+w "$r"
place {capability} "$r/{capability}" {kind}
"#,
                        kind = asked.server.as_ref().map_or("other", Name::as_str),
                    );
                    let (before, after) = value
                        .as_str()
                        .split_once("{}")
                        .unwrap_or((value.as_str(), ""));
                    let expected = format!(r#""{before}$r/{capability}{after}""#);
                    let _ = writeln!(script, "{}", sees(capability, variable.as_str(), &expected));
                    if plan
                        .writes(capability)
                        .any(|write| *write == Write::Variable(variable.clone()))
                    {
                        let _ = writeln!(
                            script,
                            r#"setvar {capability} {variable} "{before}$r/{capability}{after}""#
                        );
                    }
                }
                Question::Opener => posix_commands(&mut script, plan, capability, &OPENERS),
                Question::Notifier => posix_commands(&mut script, plan, capability, &NOTIFIER),
                Question::Helper => posix_helper(&mut script, plan, capability),
                Question::Port(port) => {
                    let present = match &asked.server {
                        Some(server) => format!(
                            "if served {port} {server}; then say listener {capability} {port} server {server}; else say listener {capability} {port} present; fi"
                        ),
                        None => format!("say listener {capability} {port} present"),
                    };
                    let _ = write!(
                        script,
                        r"listening {port}
case $? in 0) {present} ;; 1) say listener {capability} {port} absent ;; esac
"
                    );
                }
            }
        }
    }
    script.push_str("say end\n");
    if seals(plan) {
        script.push_str(SEAL);
    }
    script
}

/// What a survey's shell does once its report is read, where the plan has a
/// private socket: it waits for the core's word, and on [`SEALING`] makes
/// Hedwig's private folder unwritable, so nothing of the remote's can unlink
/// the channel's socket there and put another in its place - a client of
/// another version starting its own server, as ADB's does. Anything else, or
/// the end of its input, leaves the folder as it is.
const SEAL: &str = "IFS= read -r w || exit 0\n[ \"$w\" = seal ] && [ -n \"${hedwig:-}\" ] && chmod a-w \"$hedwig\"\n";

/// The word that has a survey's shell seal Hedwig's private folder.
pub const SEALING: &[u8] = b"seal\n";

/// Whether a survey of `plan` waits, after its report, to seal Hedwig's
/// private folder.
pub fn seals(plan: &Plan) -> bool {
    plan.asks.iter().any(|asked| {
        asked.questions.iter().any(|question| {
            match question {
            Question::Private { .. }
            | Question::Opener
            | Question::Notifier
            | Question::Helper => true,
            // The agent's socket goes in Hedwig's folder where the remote has
            // no `gpgconf`, which the survey alone finds out.
            Question::Socket(Query::AgentSshSocket) => plan.writes(asked.capability.as_str()).any(|write| {
                matches!(write, Write::Variable(variable) if variable.as_str() == AGENT_VARIABLE)
            }),
            Question::Socket(Query::AgentSocket) | Question::Port(_) => false,
        }
        })
    })
}

/// What each variable a capability's tool finds its forward by holds in the
/// command the survey is: a command the remote's SSH server ran through the
/// person's login shell, before anything here could set one.
fn posix_seen(plan: &Plan) -> String {
    let mut variables = std::collections::BTreeSet::new();
    for asked in &plan.asks {
        for question in &asked.questions {
            match question {
                Question::Socket(Query::AgentSshSocket) => {
                    variables.insert("SSH_AUTH_SOCK".to_owned());
                }
                Question::Private { variable, .. } => {
                    variables.insert(variable.as_str().to_owned());
                }
                Question::Opener => {
                    variables.extend(OPENERS.map(|(variable, _)| variable.to_owned()));
                }
                Question::Notifier => {
                    variables.extend(NOTIFIER.map(|(variable, _)| variable.to_owned()));
                }
                Question::Socket(Query::AgentSocket) | Question::Port(_) | Question::Helper => {}
            }
        }
    }
    let mut script = String::new();
    for variable in variables {
        let _ = writeln!(script, "seen_{variable}=${{{variable}-}}");
    }
    script
}

/// Each variable the remote's openers read, and the command it holds for a
/// socket at `{}`: the remote's own `curl`, posting the URL there. Invariant:
/// the only command lines every traced opener runs as meant. Python's
/// `webbrowser` and `xdg-open` cut `BROWSER` at every `:`, so the URL `curl`
/// is given has no scheme, which `curl` then takes to be `http`; `-q` keeps
/// the person's `.curlrc` out, `--noproxy` their proxy, and `-f` makes a
/// refusal a failed command, so the opener prints the URL instead.
pub const OPENERS: [(&str, &str); 2] = [
    (
        "BROWSER",
        "curl -q -fsS --noproxy hedwig --unix-socket {} --data-raw %s hedwig/",
    ),
    (
        "GH_BROWSER",
        "curl -q -fsS --noproxy hedwig --unix-socket {} hedwig/ --data-raw",
    ),
];

/// The variable a remote's own hooks tell the person through, and the command
/// it holds for a socket at `{}`: the remote's own `curl`, posting what the
/// hook gives it last, as `GH_BROWSER`'s command does a URL. Invariant: every
/// word an argument of `curl`, so a POSIX shell's
/// `$HEDWIG_NOTIFY "build finished"` runs it as written.
pub const NOTIFIER: [(&str, &str); 1] = [(
    hedwig_model::capability::NOTIFY_VARIABLE,
    "curl -q -fsS --noproxy hedwig --unix-socket {} hedwig/ --data-raw",
)];

/// What a POSIX survey does for a socket the remote's `curl` posts to through
/// a command in a variable - an opener's, a notifier's: asks for `curl`,
/// places the socket in Hedwig's private folder, and writes each variable
/// where the grant consents and the socket's path holds nothing a shell or
/// an opener would split or expand, naming it unwritten otherwise.
fn posix_commands(script: &mut String, plan: &Plan, capability: &str, commands: &[(&str, &str)]) {
    let _ = write!(
        script,
        r#"if [ -n "${{XDG_RUNTIME_DIR:-}}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then r=$XDG_RUNTIME_DIR/hedwig; else r=$HOME/.hedwig; fi
hedwig=$r
[ -d "$r" ] && chmod u+w "$r"
command -v curl >/dev/null 2>&1 || say absent {capability} curl
hedwig_socket=$r/{capability}
place {capability} "$hedwig_socket" other
"#
    );
    // The script's own functions set `r`, so the socket's path is kept apart.
    for (variable, command) in commands {
        let (before, after) = command.split_once("{}").unwrap_or((command, ""));
        let expected = format!(r#""{before}$hedwig_socket{after}""#);
        let _ = writeln!(script, "{}", sees(capability, variable, &expected));
        let consented = plan.writes(capability).any(
            |write| matches!(write, Write::Variable(written) if written.as_str() == *variable),
        );
        if consented {
            let _ = writeln!(
                script,
                r#"case $hedwig_socket in
  *[!A-Za-z0-9/._-]*) say unwritten {capability} variable:{variable} "$(hex "the socket's path $hedwig_socket holds a character an opener would split or expand")" ;;
  *) setvar {capability} {variable} {expected} words ;;
esac"#
            );
        }
    }
}

/// What a POSIX survey does for a credential's socket: asks for `git`, places
/// the socket in Hedwig's private folder - naming `git`'s own credential
/// cache where one listens there - names every credential helper of the
/// person's that `git` would give what Hedwig releases, and, where the grant
/// consents, writes `git`'s own `cache` helper at the socket into `git`'s
/// global configuration after the person's own lines.
fn posix_helper(script: &mut String, plan: &Plan, capability: &str) {
    let _ = write!(
        script,
        r#"if [ -n "${{XDG_RUNTIME_DIR:-}}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then r=$XDG_RUNTIME_DIR/hedwig; else r=$HOME/.hedwig; fi
hedwig=$r
[ -d "$r" ] && chmod u+w "$r"
hedwig_socket=$r/{capability}
if command -v git >/dev/null 2>&1; then
  place {capability} "$hedwig_socket" git
  git config --get-regexp '^credential\..*helper$' 2>/dev/null | while IFS= read -r l; do
    case $l in *" cache --socket $hedwig_socket") ;; *) say helper {capability} "$(hex "$l")" ;; esac
  done
"#
    );
    if plan.writes(capability).any(|write| *write == Write::Helper) {
        let id = quoted(&block(capability, &Write::Helper));
        let word = write_word(&Write::Helper);
        let _ = write!(
            script,
            r#"  case $hedwig_socket in
    *[!A-Za-z0-9/._-]*) say unwritten {capability} {word} "$(hex "the socket's path $hedwig_socket holds a character git would read as more than a path")" ;;
    *) put {capability} {word} "$(gitconfig)" {id} "$(printf '[credential]\n\thelper = cache --socket %s' "$hedwig_socket")" ;;
  esac
"#
        );
    }
    let _ = write!(script, "else\n  say absent {capability} git\nfi\n");
}

/// The line that reports whether the command the survey is had `variable` at
/// `expected`, a word of the script.
fn sees(capability: &str, variable: &str, expected: &str) -> String {
    format!(
        "if [ \"$seen_{variable}\" = {expected} ]; then say command {capability} {variable} present; else say command {capability} {variable} absent; fi"
    )
}

/// What Hedwig takes back on a Unix remote: its lines in a file, or a key it
/// imported.
fn posix_undo(plan: &Plan) -> String {
    let mut script = String::new();
    for undo in &plan.undo {
        let capability = undo.capability.as_str();
        let word = write_word(&undo.write);
        let place = quoted(undo.place.as_str());
        match &undo.write {
            Write::PublicKey(key) => {
                let key = quoted(key.as_str());
                let keybox = quoted(&format!("{}/{KEYBOX}", undo.place.as_str()));
                let made = if undo.made.is_some() {
                    format!(
                        r#"  if keyring {place} && [ -z "$(gpg --no-autostart --batch {TRUST} --list-keys --with-colons 2>/dev/null | grep '^pub')" ]; then rm -f -- {keybox} {keybox}~; fi
"#
                    )
                } else {
                    String::new()
                };
                let _ = writeln!(
                    script,
                    r#"if ! keyring {place} || ! gpg --no-autostart --batch {TRUST} --list-keys -- {key} >/dev/null 2>&1 || gpg --no-autostart --batch {TRUST} --yes --expert --delete-keys -- {key} >/dev/null 2>&1; then
{made}  say unwrote {capability} {word} "$(hex {place})"
fi"#
                );
            }
            Write::SocketFile => {}
            // The unit was listening when Hedwig masked it, so it listens
            // again; a mask the person replaced is theirs, and stays listed.
            Write::Masked => {
                let _ = writeln!(
                    script,
                    r#"if [ -L {place} ] && [ "$(readlink -- {place})" = /dev/null ]; then
  if systemctl --user unmask -- "$(basename -- {place})" >/dev/null 2>&1; then
    systemctl --user start -- "$(basename -- {place})" >/dev/null 2>&1
    say unwrote {capability} {word} "$(hex {place})"
  fi
elif [ ! -e {place} ] && [ ! -L {place} ]; then
  say unwrote {capability} {word} "$(hex {place})"
fi"#
                );
            }
            Write::NoAutostart | Write::SigningKey(_) | Write::Variable(_) | Write::Helper => {
                let id = quoted(&block(capability, &undo.write));
                let _ = writeln!(
                    script,
                    r#"if unblock {place} {id}; then say unwrote {capability} {word} "$(hex {place})"; fi"#
                );
            }
        }
    }
    for (place, made) in made_folders(plan, '/') {
        let _ = writeln!(
            script,
            "unmade {} {}",
            quoted(&place),
            quoted(made.as_str())
        );
    }
    script
}

/// Each write's place and the folder it made, the deepest folder first, so a
/// folder two writes made within one another is taken back whole once both
/// are; a folder still holding anything is left. A key's place is its home,
/// so its keybox there, joined by `separator`, stands for it; a keybox the
/// key's import made is the key's own reversal's.
fn made_folders(plan: &Plan, separator: char) -> Vec<(String, &RemotePath)> {
    let mut folders: Vec<(String, &RemotePath)> = plan
        .undo
        .iter()
        .filter_map(|undo| {
            let made = undo.made.as_ref()?;
            match undo.write {
                Write::PublicKey(_) => {
                    let keybox = format!("{}{separator}{KEYBOX}", undo.place.as_str());
                    (made.as_str() != keybox).then_some((keybox, made))
                }
                _ => Some((undo.place.as_str().to_owned(), made)),
            }
        })
        .collect();
    folders.sort_by(|(_, one), (_, other)| {
        other
            .as_str()
            .len()
            .cmp(&one.as_str().len())
            .then_with(|| one.as_str().cmp(other.as_str()))
    });
    folders
}

/// What Hedwig writes to a Unix remote's `GnuPG` and `git`, inside the gpg
/// question, with `$h` its home: `no-autostart`, the public keys and the
/// signing key the grant consents to, each only where the remote lacks it.
fn posix_gnupg_writes(script: &mut String, plan: &Plan, capability: &str) {
    for write in plan.writes(capability) {
        let word = write_word(write);
        let id = quoted(&block(capability, write));
        match write {
            Write::NoAutostart => {
                let _ = write!(
                    script,
                    r#"  if grep -qs '^[[:space:]]*use-keyboxd' "$h/common.conf"; then
    say unwritten {capability} {word} "$(hex 'its keys are in keyboxd, which gpg could no longer start')"
  elif present "$h/common.conf" {id} || present "$h/gpg.conf" {id} || ! grep -qs '^[[:space:]]*no-autostart' "$h/common.conf" "$h/gpg.conf"; then
    v=$(gpgconf --version | sed -n '1s/.* //p')
    case $v in 1.*|2.0*|2.1*|2.2*|2.3.[0-7]) f=$h/gpg.conf ;; *) f=$h/common.conf ;; esac
    put {capability} {word} "$f" {id} no-autostart
  fi
"#
                );
            }
            Write::PublicKey(key) => {
                let mark = quoted(key.as_str());
                match plan.armoured.get(key) {
                    Some(armoured) => {
                        let armoured = quoted(armoured);
                        let _ = write!(
                            script,
                            r#"  if ! {{ keyring "$h" && gpg --no-autostart --batch {TRUST} --list-keys -- {mark} >/dev/null 2>&1; }}; then
    if [ ! -d "$h" ]; then k=$(outermost "$h"); elif keyring "$h"; then k=; else k=$h/{KEYBOX}; fi
    if e=$(printf '%s\n' {armoured} | gpg --no-autostart --batch {TRUST} --import 2>&1); then
      noted wrote {capability} {word} "$h" "$k"
    else
      if [ -n "$k" ]; then rm -f -- "$h/{KEYBOX}" "$h/{KEYBOX}~"; unmade "$h/{KEYBOX}" "$k"; fi
      say unwritten {capability} {word} "$(hex "$e")"
    fi
  fi
"#
                        );
                    }
                    None => {
                        let _ = writeln!(
                            script,
                            r#"  say unwritten {capability} {word} "$(hex 'the workstation did not give its public key')""#
                        );
                    }
                }
            }
            Write::SigningKey(key) => {
                let _ = write!(
                    script,
                    r#"  if command -v git >/dev/null 2>&1; then
    g=$(gitconfig)
    if present "$g" {id} || [ -z "$(git config --global --get user.signingkey)" ]; then
      put {capability} {word} "$g" {id} "$(printf '[user]\n\tsigningkey = %s' {key})"
    fi
  fi
"#,
                    key = quoted(key.as_str()),
                );
            }
            // Each is written where its far end is surveyed.
            Write::Variable(_) | Write::SocketFile | Write::Masked | Write::Helper => {}
        }
    }
}

/// The script Windows PowerShell runs, for a remote whose `sshd` binds no
/// Unix socket. `gpg` is the one `git`'s `gpg.program` names where `git`
/// names one, since several `GnuPG` installations can sit side by side there.
#[allow(
    clippy::too_many_lines,
    reason = "the script's own functions are one text, read as the remote reads it"
)]
pub fn powershell(plan: &Plan, nonce: &str) -> String {
    let mut script = String::new();
    let ours: Vec<String> = plan
        .ours
        .iter()
        .map(|path| literal(path.as_str()))
        .collect();
    let _ = write!(
        script,
        r##"$ErrorActionPreference = 'Continue'
$n = '{nonce}'
$ours = @({ours})
function Say([string[]]$f) {{ [Console]::Out.Write("{MARK} $n " + ($f -join ' ') + "`n") }}
function Hex([string]$t) {{ if (-not $t) {{ return '-' }}; -join ([Text.Encoding]::UTF8.GetBytes($t) | ForEach-Object {{ $_.ToString('x2') }}) }}
function Answers([string]$file) {{
  $text = [IO.File]::ReadAllText($file)
  if ($text -notmatch '^(\d+)\n') {{ return 'occupied' }}
  $port = [int]$Matches[1]
  $client = [Net.Sockets.TcpClient]::new()
  try {{ $client.Connect('127.0.0.1', $port) }} catch {{ return 'refused' }} finally {{ $client.Dispose() }}
  $owner = (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess
  if ($owner -and (Get-Process -Id $owner -ErrorAction SilentlyContinue).ProcessName -eq 'gpg-agent') {{ 'agent' }} else {{ 'answers' }}
}}
$utf8 = [Text.UTF8Encoding]::new($false)
function Mark([string]$id) {{ "# hedwig ${{id}}: written by Hedwig with your consent; Hedwig removes it when that ends" }}
function Earlier([string]$id) {{ "# hedwig ${{id}}: written by hedwig with your consent; hedwig removes it when that ends" }}
function Begins([string]$l, [string]$id) {{ $l -ceq (Mark $id) -or $l -ceq (Earlier $id) }}
function Present([string]$f, [string]$id) {{ (Test-Path -LiteralPath $f) -and @([IO.File]::ReadAllLines($f) | Where-Object {{ Begins $_ $id }}).Count -gt 0 }}
function Inside([string]$f, [string]$id) {{
  $in = $false
  $lines = foreach ($l in [IO.File]::ReadAllLines($f)) {{ if ($l -eq "# hedwig ${{id}}: end") {{ $in = $false }}; if ($in) {{ $l }}; if (Begins $l $id) {{ $in = $true }} }}
  @($lines) -join "`n"
}}
function Unblock([string]$f, [string]$id) {{
  if (-not (Present $f $id)) {{ return $true }}
  $e = "# hedwig ${{id}}: end"
  $lines = [IO.File]::ReadAllText($f) -split "`n"
  if (@($lines | Where-Object {{ Begins $_.TrimEnd("`r") $id }}).Count -ne 1 -or @($lines | Where-Object {{ $_.TrimEnd("`r") -eq $e }}).Count -ne 1) {{ return $false }}
  $in = $false
  $kept = foreach ($l in $lines) {{ $t = $l.TrimEnd("`r"); if (Begins $t $id) {{ $in = $true; continue }}; if ($in -and $t -eq $e) {{ $in = $false; continue }}; if (-not $in) {{ $l }} }}
  $text = @($kept) -join "`n"
  if ($text.Trim().Length -eq 0) {{ Remove-Item -LiteralPath $f }} else {{ [IO.File]::WriteAllText($f, $text, $utf8) }}
  $true
}}
function Ensure([string]$f, [string]$id, [string]$text) {{
  if (Present $f $id) {{
    if ((Inside $f $id) -eq $text -and @([IO.File]::ReadAllLines($f)) -ccontains (Mark $id)) {{ return 'kept' }}
    if (-not (Unblock $f $id)) {{ return 'failed ' + (Hex "Hedwig's lines in $f were changed by hand") }}
  }}
  try {{
    $d = Split-Path $f
    $m = Outermost $d
    if (-not (Test-Path $d)) {{ New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null }}
    $old = if (Test-Path -LiteralPath $f) {{ [IO.File]::ReadAllText($f) }} else {{ '' }}
    if ($old.Length -gt 0 -and -not $old.EndsWith("`n")) {{ $old += "`n" }}
    [IO.File]::WriteAllText($f, $old + (Mark $id) + "`n" + $text + "`n# hedwig ${{id}}: end`n", $utf8)
    'wrote ' + (Hex $m)
  }} catch {{ 'failed ' + (Hex $_.Exception.Message) }}
}}
function Outermost([string]$d) {{ $m = $null; while ($d -and -not (Test-Path -LiteralPath $d)) {{ $m = $d; $d = Split-Path $d }}; $m }}
function Keyring([string]$h) {{ @('pubring.kbx', 'pubring.gpg', 'public-keys.d') | Where-Object {{ Test-Path -LiteralPath (Join-Path $h $_) }} | Select-Object -First 1 }}
function Keybox([string]$h) {{ @('pubring.kbx', 'pubring.kb_', 'pubring.kbx.lock') | ForEach-Object {{ Join-Path $h $_ }} }}
function Unmade([string]$f, [string]$m) {{
  if (-not $m) {{ return }}
  $d = Split-Path $f
  while ($d -and ($d -eq $m -or $d.StartsWith($m + '\'))) {{
    if (@(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue).Count -gt 0) {{ return }}
    Remove-Item -LiteralPath $d -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $d) -or $d -eq $m) {{ return }}
    $d = Split-Path $d
  }}
}}
function Put([string]$c, [string]$w, [string]$f, [string]$id, [string]$text) {{
  $r = Ensure $f $id $text
  if ($r -eq 'wrote -') {{ Say wrote, $c, $w, (Hex $f) }}
  elseif ($r -like 'wrote *') {{ Say wrote, $c, $w, (Hex $f), ($r -replace '^wrote ', '') }}
  elseif ($r -eq 'kept') {{ Say kept, $c, $w, (Hex $f) }} else {{ Say unwritten, $c, $w, ($r -replace '^failed ', '') }}
}}
function GitConfig {{
  if ($env:GIT_CONFIG_GLOBAL) {{ return $env:GIT_CONFIG_GLOBAL }}
  $home_ = if ($env:HOME) {{ $env:HOME }} else {{ $env:USERPROFILE }}
  $xdg = if ($env:XDG_CONFIG_HOME) {{ Join-Path $env:XDG_CONFIG_HOME 'git\config' }} else {{ Join-Path $home_ '.config\git\config' }}
  if (Test-Path (Join-Path $home_ '.gitconfig')) {{ Join-Path $home_ '.gitconfig' }} elseif (Test-Path $xdg) {{ $xdg }} else {{ Join-Path $home_ '.gitconfig' }}
}}
Say begin, powershell
Say kernel, (Hex $env:OS)
Say shell, (Hex (Get-ItemProperty HKLM:\SOFTWARE\OpenSSH -ErrorAction SilentlyContinue).DefaultShell)
$git = Get-Command git -ErrorAction SilentlyContinue
$gpg = $null
if ($git) {{ $gpg = & git config --get gpg.program }}
if (-not $gpg) {{ $gpg = (Get-Command gpg -ErrorAction SilentlyContinue).Source }}
$gpgconf = if ($gpg) {{ Join-Path (Split-Path $gpg) 'gpgconf.exe' }}
{undo}"##,
        undo = powershell_undo(plan),
        ours = ours.join(", "),
    );
    for asked in &plan.asks {
        let capability = asked.capability.as_str();
        for question in &asked.questions {
            match question {
                Question::Socket(query) => {
                    powershell_socket(&mut script, capability, *query, plan);
                }
                // A Windows remote's SSH server binds no Unix socket, so no
                // private socket is asked about there.
                Question::Private { .. }
                | Question::Opener
                | Question::Helper
                | Question::Notifier => {}
                Question::Port(port) => {
                    let present = match &asked.server {
                        Some(server) => format!(
                            "if ((Get-Process -Id @($l)[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq '{server}') {{ Say listener, {capability}, {port}, server, {server} }} else {{ Say listener, {capability}, {port}, present }}"
                        ),
                        None => format!("Say listener, {capability}, {port}, present"),
                    };
                    let _ = write!(
                        script,
                        r"$l = Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue
if ($l) {{ {present} }} else {{ Say listener, {capability}, {port}, absent }}
"
                    );
                }
            }
        }
    }
    script.push_str("Say end\n");
    script
}

/// The PowerShell that asks a Windows remote's `GnuPG` where one of its sockets
/// goes, what stands between it and the key, and writes what the grant
/// consents to.
fn powershell_socket(script: &mut String, capability: &str, query: Query, plan: &Plan) {
    let list = match query {
        Query::AgentSocket => "agent-socket",
        Query::AgentSshSocket => "agent-ssh-socket",
    };
    let _ = write!(
        script,
        r"if ($gpgconf -and (Test-Path $gpgconf)) {{
  $p = (& $gpgconf --list-dirs {list}) -join ''
  Say path, {capability}, (Hex $p)
  $d = Split-Path $p
  if (-not (Test-Path $d)) {{
    try {{ New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null; Say created, {capability}, (Hex $d) }}
    catch {{ Say uncreatable, {capability}, (Hex $_.Exception.Message) }}
  }}
  $at = 'free'
  if ($ours -contains $p) {{ $at = 'ours' }}
  elseif (Test-Path -LiteralPath $p -PathType Leaf) {{
    $at = Answers $p
    if ($at -eq 'refused') {{
      try {{ Remove-Item -LiteralPath $p -ErrorAction Stop; $at = 'removed' }}
      catch {{ $at = 'uncleared ' + (Hex $_.Exception.Message) }}
    }}
  }} elseif (Test-Path -LiteralPath $p) {{ $at = 'occupied' }}
  Say at, {capability}, $at
  $h = (& $gpgconf --list-dirs homedir) -join ''
  $common = Join-Path $h 'common.conf'
"
    );
    if query == Query::AgentSocket {
        powershell_gnupg_writes(script, plan, capability);
    }
    let _ = write!(
        script,
        r"  $conf = @($common, (Join-Path $h 'gpg.conf')) | Where-Object {{ Test-Path $_ }}
  if ($conf -and (Select-String -Path $conf -Pattern '^\s*no-autostart' -Quiet)) {{ Say autostart, {capability}, off }} else {{ Say autostart, {capability}, on }}
  if ((Test-Path $common) -and (Select-String -Path $common -Pattern '^\s*use-keyboxd' -Quiet)) {{ Say keyboxd, {capability}, on }} else {{ Say keyboxd, {capability}, off }}
"
    );
    if query == Query::AgentSocket {
        for key in &plan.keys {
            let _ = writeln!(
                script,
                "  $held = $false; if (Keyring $h) {{ & $gpg --no-autostart --batch {TRUST} --list-keys --with-colons -- {key} *> $null; $held = $LASTEXITCODE -eq 0 }}; if ($held) {{ Say key, {capability}, {key}, present }} else {{ Say key, {capability}, {key}, absent }}",
                key = literal(key.as_str()),
            );
        }
        let _ = write!(
            script,
            r"  if ($git) {{
    $v = & git config --global --get user.signingkey
    if ($v) {{ Say signing, {capability}, (Hex $v) }} else {{ Say signing, {capability}, unset }}
    Say format, {capability}, (Hex (& git config --global --get gpg.format))
  }}
"
        );
    }
    let _ = writeln!(script, "}} else {{ Say absent, {capability}, gpgconf }}");
}

/// What Hedwig writes to a Windows remote's Gpg4win and `git`, with `$h` its
/// `GnuPG` home and `$at` what stood at the socket file's path: the socket
/// file only where nothing answers there, the rest only where the remote
/// lacks it.
fn powershell_gnupg_writes(script: &mut String, plan: &Plan, capability: &str) {
    for write in plan.writes(capability) {
        let word = write_word(write);
        let id = literal(&block(capability, write));
        match write {
            Write::SocketFile => {
                let Some(issued) = plan.issued else {
                    continue;
                };
                let bytes: Vec<String> = issued.iter().map(u8::to_string).collect();
                let _ = write!(
                    script,
                    r#"  if (@('free', 'removed', 'ours') -contains $at) {{
    if ($at -eq 'ours') {{ $port = [int]([regex]::Match([IO.File]::ReadAllText($p), '^\d+').Value) }}
    else {{
      try {{
        $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
        [IO.File]::WriteAllBytes($p, [Text.Encoding]::ASCII.GetBytes("$port`n") + [byte[]]@({bytes}))
        Say wrote, {capability}, {word}, (Hex $p)
      }} catch {{ Say unwritten, {capability}, {word}, (Hex $_.Exception.Message); $port = $null }}
    }}
    if ($port) {{ Say socketfile, {capability}, $port }}
  }}
"#,
                    bytes = bytes.join(", "),
                );
            }
            Write::NoAutostart => {
                let _ = write!(
                    script,
                    r"  if ((Test-Path $common) -and (Select-String -Path $common -Pattern '^\s*use-keyboxd' -Quiet)) {{
    Say unwritten, {capability}, {word}, (Hex 'its keys are in keyboxd, which gpg could no longer start')
  }} elseif ((Present $common {id}) -or (Present (Join-Path $h 'gpg.conf') {id}) -or -not (@($common, (Join-Path $h 'gpg.conf')) | Where-Object {{ Test-Path $_ }} | Select-String -Pattern '^\s*no-autostart' -Quiet)) {{
    $v = [version](((& $gpgconf --version | Select-Object -First 1) -split ' ')[-1])
    $f = if ($v -lt [version]'2.3.8') {{ Join-Path $h 'gpg.conf' }} else {{ $common }}
    Put {capability} {word} $f {id} 'no-autostart'
  }}
"
                );
            }
            Write::PublicKey(key) => {
                let mark = literal(key.as_str());
                match plan.armoured.get(key) {
                    Some(armoured) => {
                        let armoured = literal(armoured);
                        let _ = write!(
                            script,
                            r#"  $held = $false
  if (Keyring $h) {{ & $gpg --no-autostart --batch {TRUST} --list-keys -- {mark} *> $null; $held = $LASTEXITCODE -eq 0 }}
  if (-not $held) {{
    $k = if (-not (Test-Path -LiteralPath $h)) {{ Outermost $h }} elseif (Keyring $h) {{ $null }} else {{ Join-Path $h '{KEYBOX}' }}
    $t = [IO.Path]::GetTempFileName()
    try {{ [IO.File]::WriteAllText($t, {armoured}); $e = & $gpg --no-autostart --batch {TRUST} --import $t 2>&1; $imported = $LASTEXITCODE -eq 0 }}
    finally {{ Remove-Item -LiteralPath $t -ErrorAction SilentlyContinue }}
    if ($imported) {{
      if ($k) {{ Say wrote, {capability}, {word}, (Hex $h), (Hex $k) }} else {{ Say wrote, {capability}, {word}, (Hex $h) }}
    }} else {{
      if ($k) {{ Remove-Item -LiteralPath (Keybox $h) -Force -ErrorAction SilentlyContinue; Unmade (Join-Path $h '{KEYBOX}') $k }}
      Say unwritten, {capability}, {word}, (Hex "$e")
    }}
  }}
"#
                        );
                    }
                    None => {
                        let _ = writeln!(
                            script,
                            "  Say unwritten, {capability}, {word}, (Hex 'the workstation did not give its public key')"
                        );
                    }
                }
            }
            Write::SigningKey(key) => {
                let _ = write!(
                    script,
                    r#"  if ($git) {{
    $g = GitConfig
    if ((Present $g {id}) -or -not (& git config --global --get user.signingkey)) {{
      Put {capability} {word} $g {id} ("[user]`n`tsigningkey = " + {key})
    }}
  }}
"#,
                    key = literal(key.as_str()),
                );
            }
            Write::Variable(_) | Write::Masked | Write::Helper => {}
        }
    }
}

/// What Hedwig takes back on a Windows remote.
fn powershell_undo(plan: &Plan) -> String {
    let mut script = String::new();
    for undo in &plan.undo {
        let capability = undo.capability.as_str();
        let word = write_word(&undo.write);
        let place = literal(undo.place.as_str());
        match &undo.write {
            Write::PublicKey(key) => {
                let key = literal(key.as_str());
                let made = if undo.made.is_some() {
                    format!(
                        "if ((Keyring {place}) -and -not @(& $gpg --no-autostart --batch {TRUST} --list-keys --with-colons 2>$null | Where-Object {{ $_ -like 'pub:*' }}).Count) {{ Remove-Item -LiteralPath (Keybox {place}) -Force -ErrorAction SilentlyContinue }}; "
                    )
                } else {
                    String::new()
                };
                let _ = writeln!(
                    script,
                    "$gone = $true; if (Keyring {place}) {{ & $gpg --no-autostart --batch {TRUST} --list-keys -- {key} *> $null; if ($LASTEXITCODE -eq 0) {{ & $gpg --no-autostart --batch {TRUST} --yes --expert --delete-keys -- {key} *> $null; $gone = $LASTEXITCODE -eq 0 }} }}; if ($gone) {{ {made}Say unwrote, {capability}, {word}, (Hex {place}) }}"
                );
            }
            Write::SocketFile => {
                let _ = writeln!(
                    script,
                    r"if (-not (Test-Path -LiteralPath {place}) -or ([IO.File]::ReadAllText({place}) -match '^\d+\n')) {{ Remove-Item -LiteralPath {place} -ErrorAction SilentlyContinue; Say unwrote, {capability}, {word}, (Hex {place}) }}"
                );
            }
            // A Windows remote has no service manager unit at a socket file's
            // path, so nothing is masked there.
            Write::Masked => {}
            Write::NoAutostart | Write::SigningKey(_) | Write::Variable(_) | Write::Helper => {
                let id = literal(&block(capability, &undo.write));
                let _ = writeln!(
                    script,
                    "if (Unblock {place} {id}) {{ Say unwrote, {capability}, {word}, (Hex {place}) }}"
                );
            }
        }
    }
    for (place, made) in made_folders(plan, '\\') {
        let _ = writeln!(
            script,
            "Unmade {} {}",
            literal(&place),
            literal(made.as_str())
        );
    }
    script
}

/// How what was at a socket's path stood when readiness looked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At {
    /// Nothing is there.
    Free,
    /// This connection's own forward holds it.
    Ours,
    /// A socket nothing answered at was there, and readiness removed it.
    Removed,
    /// Something that is not a socket is there.
    Occupied,
    /// The remote's own agent answers there.
    Agent,
    /// A unit of the remote's service manager listens there, as the manager
    /// names it; nothing connected to it.
    Held(Vec<u8>),
    /// The capability's own tool's server, the remote's, listens there.
    Server(Name),
    /// Something else answers there.
    Answers,
    /// Something accepts there and says nothing, twice.
    Silent,
    /// No tool on the remote could say.
    Unprobed,
    /// Nothing answered and the socket could not be removed: the remote's
    /// words.
    Uncleared(Vec<u8>),
}

/// What the remote said about one capability's socket.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Place {
    /// The path, as the remote's tool gave it: bytes, not yet a path the
    /// model admits.
    pub path: Vec<u8>,
    pub created: Option<Vec<u8>>,
    /// The remote's words when the folder could not be made.
    pub uncreatable: Option<Vec<u8>>,
    /// The file system's name for itself, where the folder is under the home.
    pub filesystem: Option<Vec<u8>>,
    pub at: Option<At>,
}

/// A write Hedwig made, the place it went as the remote named it, and what
/// it made for it.
pub type Made = (Write, Vec<u8>, Option<Vec<u8>>);

/// What the remote said about one capability.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    /// A tool readiness needed and the remote lacks.
    pub absent: Option<Name>,
    pub place: Option<Place>,
    /// Whether the remote's `GnuPG` starts its own agent, where it said.
    pub autostart: Option<bool>,
    pub keyboxd: Option<bool>,
    pub keys: BTreeMap<Fingerprint, bool>,
    /// `git`'s signing key: `Some(None)` when it names none.
    pub signing: Option<Option<Vec<u8>>>,
    pub format: Option<Vec<u8>>,
    pub listeners: BTreeMap<Port, bool>,
    /// The ports among `listeners` where the capability's own tool's server,
    /// the remote's, listens.
    pub servers: BTreeMap<Port, Name>,
    /// Whether the command the survey is had each variable pointing at the
    /// forward: what any command the remote's SSH server runs would have.
    pub commands: BTreeMap<Variable, bool>,
    pub wrote: Vec<Made>,
    /// What Hedwig had written and found still there, and where.
    pub kept: Vec<(Write, Vec<u8>)>,
    /// What Hedwig took back, and where from.
    pub unwrote: Vec<(Write, Vec<u8>)>,
    /// What Hedwig was to write and did not, with why.
    pub unwritten: Vec<(Write, Vec<u8>)>,
    /// The port a Windows remote's socket file was written with.
    pub socket_port: Option<Port>,
    /// Each credential helper `git` names besides Hedwig's, as `git config`
    /// lists it.
    pub helpers: Vec<Vec<u8>>,
}

/// A remote's whole report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub dialect: Dialect,
    pub kernel: Kernel,
    /// The person's shell on the remote, where the remote said.
    pub shell: Vec<u8>,
    pub answers: BTreeMap<Name, Answer>,
    /// The bytes the performer wrote a Windows socket file with, for this
    /// survey: never from the remote.
    pub issued: Option<[u8; 16]>,
}

/// Why a report could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// Nothing of the survey ran: no line began it.
    NotBegun,
    /// It began and did not reach its end.
    Unfinished,
    /// A line of the survey's own says something the core did not ask for.
    Malformed(String),
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text == "-" {
        return Some(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn on(word: &str) -> Option<bool> {
    match word {
        "on" | "present" => Some(true),
        "off" | "absent" => Some(false),
        _ => None,
    }
}

/// Records one line of a report's about a capability in `answer`; `None`
/// for a line the survey was not written to print.
fn answered(answer: &mut Answer, word: &str, rest: &[&str]) -> Option<()> {
    match (word, rest) {
        ("absent", [tool]) => {
            answer.absent = Some(Name::try_from(*tool).ok()?);
        }
        ("path", [path]) => {
            answer.place.get_or_insert_with(Place::default).path = unhex(path)?;
        }
        ("created", [path]) => {
            answer.place.get_or_insert_with(Place::default).created = Some(unhex(path)?);
        }
        ("uncreatable", [account]) => {
            answer.place.get_or_insert_with(Place::default).uncreatable = Some(unhex(account)?);
        }
        ("filesystem", [name]) => {
            answer.place.get_or_insert_with(Place::default).filesystem = Some(unhex(name)?);
        }
        ("at", [state, extra @ ..]) => {
            let at = match (*state, extra) {
                ("free", []) => At::Free,
                ("ours", []) => At::Ours,
                ("removed", []) => At::Removed,
                ("occupied", []) => At::Occupied,
                ("agent", []) => At::Agent,
                ("answers", []) => At::Answers,
                ("silent", []) => At::Silent,
                ("unprobed", []) => At::Unprobed,
                ("held", [unit]) => At::Held(unhex(unit)?),
                ("server", [program]) => At::Server(Name::try_from(*program).ok()?),
                ("uncleared", [account]) => At::Uncleared(unhex(account)?),
                _ => return None,
            };
            answer.place.get_or_insert_with(Place::default).at = Some(at);
        }
        ("autostart", [state]) => answer.autostart = Some(on(state)?),
        ("keyboxd", [state]) => answer.keyboxd = Some(on(state)?),
        ("key", [key, state]) => {
            let key = Fingerprint::try_from(*key).ok()?;
            answer.keys.insert(key, on(state)?);
        }
        ("signing", ["unset"]) => answer.signing = Some(None),
        ("signing", [value]) => {
            answer.signing = Some(Some(unhex(value)?));
        }
        ("format", [value]) => answer.format = Some(unhex(value)?),
        ("wrote", [write, place]) => answer.wrote.push((written_as(write)?, unhex(place)?, None)),
        ("wrote", [write, place, made]) => {
            answer
                .wrote
                .push((written_as(write)?, unhex(place)?, Some(unhex(made)?)));
        }
        ("command", [variable, state]) => {
            answer
                .commands
                .insert(Variable::try_from(*variable).ok()?, on(state)?);
        }
        ("kept", [write, place]) => answer.kept.push((written_as(write)?, unhex(place)?)),
        ("unwrote", [write, place]) => answer.unwrote.push((written_as(write)?, unhex(place)?)),
        ("unwritten", [write, why]) => answer.unwritten.push((written_as(write)?, unhex(why)?)),
        ("helper", [line]) => answer.helpers.push(unhex(line)?),
        ("socketfile", [port]) => {
            answer.socket_port = Some(
                port.parse::<u16>()
                    .ok()
                    .and_then(|port| Port::try_from(port).ok())?,
            );
        }
        ("listener", [port, state]) => {
            let port = port
                .parse::<u16>()
                .ok()
                .and_then(|port| Port::try_from(port).ok())?;
            answer.listeners.insert(port, on(state)?);
        }
        ("listener", [port, "server", program]) => {
            let port = port
                .parse::<u16>()
                .ok()
                .and_then(|port| Port::try_from(port).ok())?;
            answer.listeners.insert(port, true);
            answer.servers.insert(port, Name::try_from(*program).ok()?);
        }
        _ => return None,
    }
    Some(())
}

/// Reads a report. Lines that do not begin with the survey's mark and nonce
/// are what the remote's login scripts printed, and are passed over.
///
/// # Errors
///
/// [`Unread`] when the survey did not begin, did not finish, or said
/// something it was not asked.
pub fn read(output: &str, nonce: &str) -> Result<Report, Unread> {
    let head = format!("{MARK} {nonce} ");
    let mut dialect = None;
    let mut kernel = None;
    let mut shell = Vec::new();
    let mut answers: BTreeMap<Name, Answer> = BTreeMap::new();
    let mut ended = false;
    for line in output.lines() {
        let Some(said) = line.trim_end_matches('\r').strip_prefix(&head) else {
            continue;
        };
        let malformed = || Unread::Malformed(said.to_owned());
        let words: Vec<&str> = said.split(' ').collect();
        match words.as_slice() {
            ["begin", word] => {
                dialect = [Dialect::Posix, Dialect::PowerShell]
                    .into_iter()
                    .find(|dialect| dialect.word() == *word);
            }
            ["end"] => ended = true,
            ["kernel", name] => {
                let name = unhex(name).ok_or_else(malformed)?;
                kernel = Kernel::try_from(String::from_utf8_lossy(&name).as_ref()).ok();
            }
            ["shell", name] => shell = unhex(name).ok_or_else(malformed)?,
            [word, capability, rest @ ..] => {
                let capability = Name::try_from(*capability).map_err(|_| malformed())?;
                let answer = answers.entry(capability).or_default();
                if answered(answer, word, rest).is_none() {
                    return Err(malformed());
                }
            }
            _ => return Err(malformed()),
        }
    }
    let dialect = dialect.ok_or(Unread::NotBegun)?;
    if !ended {
        return Err(Unread::Unfinished);
    }
    let kernel = kernel.ok_or_else(|| Unread::Malformed("no kernel was named".to_owned()))?;
    Ok(Report {
        dialect,
        kernel,
        shell,
        answers,
        issued: None,
    })
}

/// The forwards the person's own configuration declares for the host, as the
/// route's client states them with `-G`: each binds for as long as any
/// connection to the host that does not scope them away.
pub fn theirs(stated: &str) -> Vec<Words> {
    stated
        .lines()
        .filter(|line| {
            ["localforward ", "remoteforward ", "dynamicforward "]
                .iter()
                .any(|kind| line.starts_with(kind))
        })
        .filter_map(crate::channel::words)
        .collect()
}

/// The names file systems that other hosts share give themselves, as GNU
/// `stat -f -c %T` prints them. Invariant: a socket forwarded into one of
/// them can be another host's socket at the same path, which readiness would
/// then take for stale.
const SHARED: [&str; 10] = [
    "nfs",
    "nfs4",
    "cifs",
    "smb2",
    "smb3",
    "smbfs",
    "afs",
    "fuse.sshfs",
    "ceph",
    "glusterfs",
];

/// What readiness makes of one capability's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub readiness: Readiness,
    /// Where the forward goes, when the capability can be carried.
    pub serving: Option<Serving>,
    /// What readiness changed on the remote for it.
    pub prepared: Vec<Prepared>,
}

/// What the remote said, as words a surface can show.
fn said(bytes: &[u8]) -> Words {
    crate::channel::words(&String::from_utf8_lossy(bytes))
        .unwrap_or_else(|| unaccounted("the remote gave no account"))
}

/// Fixed words of the core's own.
fn unaccounted(text: &str) -> Words {
    Words::try_from(text).unwrap_or_else(|_| unreachable!("fixed words are valid words"))
}

fn remote_path(bytes: &[u8]) -> Option<RemotePath> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.starts_with('/') && !text.contains(":\\") {
        return None;
    }
    RemotePath::try_from(text).ok()
}

/// What readiness makes of `answer` for `capability`, whose far end on
/// `platform` takes `form`. `keys` are those the workstation offers;
/// `theirs` the person's own forwards for the host.
pub fn place(
    capability: &Name,
    form: &Form,
    platform: &Platform,
    answer: &Answer,
    keys: &[Fingerprint],
    theirs: &[Words],
) -> Placed {
    let mut findings: Vec<Finding> = theirs.iter().cloned().map(Finding::TheirForward).collect();
    let mut prepared = Vec::new();
    let mut serving = None;
    if let Some(tool) = &answer.absent {
        findings.push(Finding::ToolAbsent(tool.clone()));
    }
    match form {
        Form::SocketAt(_)
        | Form::PrivateSocket { .. }
        | Form::SocketFileAt(_)
        | Form::Opener
        | Form::Helper
        | Form::Notifier => {
            match &answer.place {
                Some(place) => {
                    let bound = placed_socket(place, platform, &mut findings, &mut prepared);
                    serving = bound.map(|path| Serving {
                        capability: capability.clone(),
                        binding: Binding::Socket(path),
                    });
                }
                // The script answers every socket it is asked about, so a
                // report without one did not run as written.
                None if answer.absent.is_none() => {
                    findings.push(Finding::Unsurveyed(unaccounted(
                        "the remote said nothing of it",
                    )));
                }
                None => {}
            }
        }
        Form::Port(ServicePort::Fixed(port)) => {
            if let Some(program) = answer.servers.get(port) {
                findings.push(Finding::ServerLive {
                    program: program.clone(),
                    at: Binding::Port(*port),
                });
            } else if answer.listeners.get(port) == Some(&true) {
                findings.push(Finding::ListenerPresent(*port));
            } else {
                serving = Some(Serving {
                    capability: capability.clone(),
                    binding: Binding::Port(*port),
                });
            }
        }
        Form::Port(ServicePort::Unstated) => {}
    }
    if let Form::SocketAt(Query::AgentSocket) | Form::SocketFileAt(Query::AgentSocket) = form {
        cautions(answer, keys, &mut findings);
    }
    if *form == Form::Helper {
        helpers(answer, &mut findings);
    }
    for (write, why) in &answer.unwritten {
        findings.push(Finding::Unwritten {
            write: write.clone(),
            why: said(why),
        });
    }
    // The command saw the remote as it was before this survey wrote, so a
    // variable written or left unwritten now is judged by the next survey.
    for (variable, seen) in &answer.commands {
        let write = Write::Variable(variable.clone());
        let now = answer.wrote.iter().any(|(wrote, ..)| *wrote == write)
            || answer
                .unwritten
                .iter()
                .any(|(unwritten, _)| *unwritten == write);
        if !seen && !now {
            findings.push(Finding::VariableUnset(variable.clone()));
        }
    }
    // A socket file is carried on the port the consented write put in it.
    if matches!(form, Form::SocketFileAt(_)) {
        serving = match (serving, answer.socket_port) {
            (
                Some(Serving {
                    binding: Binding::Socket(file),
                    ..
                }),
                Some(port),
            ) => Some(Serving {
                capability: capability.clone(),
                binding: Binding::SocketFile { file, port },
            }),
            _ => None,
        };
    }
    if findings.iter().any(Finding::blocks) {
        serving = None;
    }
    Placed {
        readiness: if findings.is_empty() {
            Readiness::Ready
        } else {
            Readiness::Unready(findings)
        },
        serving,
        prepared,
    }
}

/// What readiness names for a credential: `git`'s own cache where it holds
/// the path - started by a `git` that found the forward down and the folder
/// open - and each helper of the person's that `git` gives what succeeds.
fn helpers(answer: &Answer, findings: &mut Vec<Finding>) {
    for finding in findings.iter_mut() {
        if let Finding::ServerLive {
            program,
            at: Binding::Socket(path),
        } = finding
            && program.as_str() == "git"
        {
            *finding = Finding::CacheLive(path.clone());
        }
    }
    findings.extend(
        answer
            .helpers
            .iter()
            .map(|helper| Finding::HelperBeside(said(helper))),
    );
}

/// The path a socket's forward binds, or the findings that keep it from
/// binding.
fn placed_socket(
    place: &Place,
    platform: &Platform,
    findings: &mut Vec<Finding>,
    prepared: &mut Vec<Prepared>,
) -> Option<RemotePath> {
    let Some(path) = remote_path(&place.path) else {
        findings.push(Finding::PathUnusable);
        return None;
    };
    if let Some(created) = place.created.as_deref().and_then(remote_path) {
        prepared.push(Prepared::Created(created));
    }
    if let Some(account) = &place.uncreatable {
        findings.push(Finding::ParentUncreatable(said(account)));
        return None;
    }
    if let Err(hedwig_model::refusal::Refusal::SocketPathTooLong { usable, length }) =
        platform.admits(&path)
    {
        findings.push(Finding::PathTooLong { usable, length });
    }
    if let Some(system) = &place.filesystem
        && SHARED.contains(&String::from_utf8_lossy(system).as_ref())
    {
        findings.push(Finding::SharedHome(said(system)));
    }
    match &place.at {
        Some(At::Free | At::Ours) => {}
        Some(At::Removed) => prepared.push(Prepared::Removed(path.clone())),
        Some(At::Occupied) => findings.push(Finding::Occupied(path.clone())),
        Some(At::Agent) => findings.push(Finding::AgentLive(path.clone())),
        Some(At::Server(program)) => findings.push(Finding::ServerLive {
            program: program.clone(),
            at: Binding::Socket(path.clone()),
        }),
        Some(At::Held(unit)) => findings.push(Finding::UnitListens {
            unit: said(unit),
            path: path.clone(),
        }),
        Some(At::Answers) => findings.push(Finding::Answers(path.clone())),
        Some(At::Silent) => findings.push(Finding::Silent(path.clone())),
        Some(At::Unprobed) | None => findings.push(Finding::Unprobed(path.clone())),
        Some(At::Uncleared(account)) => findings.push(Finding::Uncleared(said(account))),
    }
    Some(path)
}

/// What stands between the remote's `gpg` and the key, though the socket can
/// be carried.
fn cautions(answer: &Answer, keys: &[Fingerprint], findings: &mut Vec<Finding>) {
    if answer.autostart == Some(true) {
        findings.push(Finding::AgentAutostarts);
    }
    if answer.keyboxd == Some(true) && answer.autostart == Some(false) {
        findings.push(Finding::KeyboxdStopped);
    }
    for (key, present) in &answer.keys {
        if !present {
            findings.push(Finding::PublicKeyAbsent(key.clone()));
        }
    }
    let openpgp = answer
        .format
        .as_deref()
        .is_none_or(|format| format.is_empty() || format == b"openpgp");
    if openpgp {
        match &answer.signing {
            Some(None) => findings.push(Finding::SigningKeyUnset),
            Some(Some(value)) if !keys.is_empty() => {
                let named = String::from_utf8_lossy(value)
                    .trim_end_matches('!')
                    .trim_start_matches("0x")
                    .to_ascii_uppercase();
                let offered = keys
                    .iter()
                    .any(|key| key.as_str().to_ascii_uppercase().ends_with(&named));
                if named.is_empty() || !offered {
                    findings.push(Finding::SigningKeyOther(said(value)));
                }
            }
            _ => {}
        }
    }
}

/// The script that has the remote's own tool use a capability once through
/// its forward, in `dialect`. A signing capability signs, because that is
/// the use the person is proving - only where the remote's `GnuPG` home has a
/// keyring, and under a trust model that reads no trust database, so the
/// signature makes nothing the home did not have; anything else is connected
/// to. Nothing here is bounded in time: the request it makes can wait for the
/// person.
pub fn exercise(dialect: Dialect, query: Option<Query>, binding: &Binding, nonce: &str) -> String {
    match dialect {
        Dialect::Posix => posix_exercise(query, binding, nonce),
        Dialect::PowerShell => powershell_exercise(query, binding, nonce),
    }
}

fn posix_exercise(query: Option<Query>, binding: &Binding, nonce: &str) -> String {
    let mut script = format!(
        r#"LC_ALL=C
export LC_ALL
n={nonce}
say() {{ printf '{MARK} %s %s\n' "$n" "$*"; }}
hex() {{ h=$(printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'); printf '%s' "${{h:--}}"; }}
ran() {{ say ran "$1" "$(hex "$(printf '%s\n' "$2" | sed '/^$/d' | tail -n 1)")"; }}
say begin posix
"#
    );
    let body = match (query, binding) {
        (Some(Query::AgentSocket), _) => r#"if ! command -v gpg >/dev/null 2>&1; then
  say absent gpg
elif ! command -v gpgconf >/dev/null 2>&1; then
  say absent gpgconf
else
  h=$(gpgconf --list-dirs homedir)
  if [ -e "$h/pubring.kbx" ] || [ -e "$h/pubring.gpg" ] || [ -e "$h/public-keys.d" ]; then
    k=$(git config --global --get user.signingkey 2>/dev/null)
    if [ -n "$k" ]; then
      o=$(printf 'hedwig\n' | gpg --batch --no-tty --trust-model always --no-auto-check-trustdb --clearsign --local-user "$k" 2>&1 >/dev/null)
    else
      o=$(printf 'hedwig\n' | gpg --batch --no-tty --trust-model always --no-auto-check-trustdb --clearsign 2>&1 >/dev/null)
    fi
    ran $? "$o"
  else
    say unkeyed
  fi
fi
"#
        .to_owned(),
        (Some(Query::AgentSshSocket), Binding::Socket(path)) => format!(
            r#"if command -v ssh-add >/dev/null 2>&1; then
  o=$(SSH_AUTH_SOCK={path} ssh-add -l 2>&1)
  ran $? "$o"
else
  say absent ssh-add
fi
"#,
            path = quoted(path.as_str()),
        ),
        (_, Binding::Socket(path) | Binding::SocketFile { file: path, .. }) => format!(
            r#"if command -v ssh-add >/dev/null 2>&1; then
  o=$(SSH_AUTH_SOCK={path} ssh-add -l 2>&1)
  ran $? "$o"
elif command -v gpg-connect-agent >/dev/null 2>&1; then
  o=$(gpg-connect-agent -S {path} /bye 2>&1)
  ran $? "$o"
else
  say absent ssh-add
fi
"#,
            path = quoted(path.as_str()),
        ),
        (_, Binding::Port(port)) => format!(
            r#"if command -v nc >/dev/null 2>&1; then
  o=$(nc -z 127.0.0.1 {port} 2>&1)
  ran $? "$o"
elif command -v python3 >/dev/null 2>&1; then
  o=$(python3 -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1]))).close()' {port} 2>&1)
  ran $? "$o"
elif command -v perl >/dev/null 2>&1; then
  o=$(perl -MIO::Socket::INET -e 'IO::Socket::INET->new(PeerAddr => "127.0.0.1:$ARGV[0]") or die "$!\n"' {port} 2>&1)
  ran $? "$o"
else
  say absent nc
fi
"#
        ),
    };
    script.push_str(&body);
    script.push_str("say end\n");
    script
}

fn powershell_exercise(query: Option<Query>, binding: &Binding, nonce: &str) -> String {
    let mut script = format!(
        r#"$ErrorActionPreference = 'Continue'
$n = '{nonce}'
function Say([string[]]$f) {{ [Console]::Out.Write("{MARK} $n " + ($f -join ' ') + "`n") }}
function Hex([string]$t) {{ if (-not $t) {{ return '-' }}; -join ([Text.Encoding]::UTF8.GetBytes($t) | ForEach-Object {{ $_.ToString('x2') }}) }}
Say begin, powershell
"#
    );
    let body = match (query, binding) {
        (Some(Query::AgentSocket), _) => r#"$gpg = $null
if (Get-Command git -ErrorAction SilentlyContinue) { $gpg = & git config --get gpg.program; $k = & git config --global --get user.signingkey }
if (-not $gpg) { $gpg = (Get-Command gpg -ErrorAction SilentlyContinue).Source }
$gpgconf = if ($gpg) { Join-Path (Split-Path $gpg) 'gpgconf.exe' }
if (-not $gpg) { Say absent, gpg }
elseif (-not (Test-Path -LiteralPath $gpgconf)) { Say absent, gpgconf }
else {
  $h = (& $gpgconf --list-dirs homedir) -join ''
  if (@('pubring.kbx', 'pubring.gpg', 'public-keys.d') | Where-Object { Test-Path -LiteralPath (Join-Path $h $_) }) {
    $arguments = @('--batch', '--no-tty', '--trust-model', 'always', '--no-auto-check-trustdb', '--clearsign')
    if ($k) { $arguments += @('--local-user', $k) }
    $o = 'hedwig' | & $gpg @arguments 2>&1 | Where-Object { $_ -is [Management.Automation.ErrorRecord] } | Select-Object -Last 1
    Say ran, $LASTEXITCODE, (Hex "$o")
  } else { Say unkeyed }
}
"#
        .to_owned(),
        (_, Binding::Port(port) | Binding::SocketFile { port, .. }) => format!(
            r"$client = [Net.Sockets.TcpClient]::new()
try {{ $client.Connect('127.0.0.1', {port}); Say ran, 0, - }} catch {{ Say ran, 1, (Hex $_.Exception.Message) }} finally {{ $client.Dispose() }}
"
        ),
        // A Windows remote's SSH server binds no Unix socket.
        (_, Binding::Socket(_)) => "Say absent, ssh-add\n".to_owned(),
    };
    script.push_str(&body);
    script.push_str("Say end\n");
    script
}

/// Reads what an exercise reported: the tool's last words, the tool the
/// remote lacks, or the keyring it lacks.
///
/// # Errors
///
/// [`Unread`] as for a survey's report.
pub fn exercised(output: &str, nonce: &str) -> Result<Result<Option<Words>, Finding>, Unread> {
    let head = format!("{MARK} {nonce} ");
    let (mut begun, mut ended, mut ran) = (false, false, None);
    for line in output.lines() {
        let Some(said) = line.trim_end_matches('\r').strip_prefix(&head) else {
            continue;
        };
        let malformed = || Unread::Malformed(said.to_owned());
        match said.split(' ').collect::<Vec<_>>().as_slice() {
            ["begin", _] => begun = true,
            ["end"] => ended = true,
            ["ran", _, last] => {
                let last = unhex(last).ok_or_else(malformed)?;
                ran = Some(Ok(crate::channel::words(&String::from_utf8_lossy(&last))));
            }
            ["absent", tool] => {
                ran = Some(Err(Finding::ToolAbsent(
                    Name::try_from(*tool).map_err(|_| malformed())?,
                )));
            }
            ["unkeyed"] => ran = Some(Err(Finding::KeyringAbsent)),
            _ => return Err(malformed()),
        }
    }
    if !begun {
        return Err(Unread::NotBegun);
    }
    match (ended, ran) {
        (true, Some(ran)) => Ok(ran),
        _ => Err(Unread::Unfinished),
    }
}
