//! Le client SSH du morph : joindre une machine, y exécuter une commande,
//! sonder ce qu'elle permet. Bâti sur `russh`, une pile SSH asynchrone en Rust
//! pur — aucun `ssh` externe n'est appelé.
//!
//! Deux règles de sécurité tenues ici :
//!
//! * **La clé d'hôte est épinglée.** Au premier contact son empreinte est
//!   capturée pour que la personne la confirme ; ensuite, une empreinte qui
//!   diffère fait échouer la connexion sans appel — c'est le seul moyen de
//!   voir passer un homme du milieu. La comparaison est à temps constant.
//! * **Les secrets vivent en `Zeroizing`** et ne sont jamais journalisés.

use anyhow::{anyhow, Context, Result};
use russh::client::{self, AuthResult, Handle};
use russh::keys::PrivateKeyWithHashAlg;
use russh::ChannelMsg;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

// Re-export so callers can build `SshAuth` secrets without a direct zeroize dep.
pub use zeroize::Zeroizing as SecretString;

/// How to authenticate to a host.
///
/// `Debug` est écrit à la main : le dérivé imprimerait le mot de passe et la
/// phrase de passe. Une trace de débogage finit dans un journal, et un journal
/// se partage.
pub enum SshAuth {
    Password(Zeroizing<String>),
    Key {
        /// Path to an on-disk OpenSSH private key.
        path: String,
        passphrase: Option<Zeroizing<String>>,
    },
    /// SSH agent (not yet wired — reserved).
    Agent,
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(masqué)"),
            Self::Key { path, passphrase } => f
                .debug_struct("Key")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "masquée"))
                .finish(),
            Self::Agent => f.write_str("Agent"),
        }
    }
}

/// A connection target, optionally reached through a jump host.
#[derive(Debug)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub jump: Option<Box<SshTarget>>,
}

/// Result of a lightweight, self-cleaning capability probe.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub reachable: bool,
    pub os: Option<String>,
    pub whoami: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub is_sudoer: bool,
    pub host_key_algo: String,
    pub host_key_sha256: String,
}

/// The host-key handler: captures the presented key's fingerprint and, when a
/// pin is supplied, enforces it in constant time (hard-fail on mismatch).
struct HostKeyHandler {
    pinned: Option<String>,
    captured: Arc<Mutex<Option<(String, String)>>>, // (algo, "SHA256:…")
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key
            .fingerprint(Default::default())
            .to_string();
        let algo = server_public_key.algorithm().to_string();
        *self.captured.lock().unwrap() = Some((algo, fp.clone()));
        match &self.pinned {
            Some(expected) => Ok(constant_time_eq(expected.as_bytes(), fp.as_bytes())),
            None => Ok(true), // TOFU: capture; caller must confirm before saving.
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    })
}

/// A live SSH connection.
pub struct SshClient {
    handle: Handle<HostKeyHandler>,
    /// When connected through a jump host, its handle is kept alive here so the
    /// tunnel stays open; dropping `SshClient` closes both connections.
    _jump: Option<Handle<HostKeyHandler>>,
    pub host_key_algo: String,
    pub host_key_sha256: String,
}

impl SshClient {
    /// Connect + authenticate. `pinned` is the expected `SHA256:…` host-key
    /// fingerprint (None on first contact / test flow).
    pub async fn connect(target: &SshTarget, pinned: Option<&str>) -> Result<Self> {
        let captured = Arc::new(Mutex::new(None));
        let handler = HostKeyHandler {
            pinned: pinned.map(str::to_string),
            captured: captured.clone(),
        };

        let (mut handle, jump_handle) = match &target.jump {
            None => {
                let connect =
                    client::connect(config(), (target.host.as_str(), target.port), handler);
                let handle = tokio::time::timeout(Duration::from_secs(15), connect)
                    .await
                    .map_err(|_| {
                        anyhow!("connection to {}:{} timed out", target.host, target.port)
                    })?
                    .with_context(|| format!("connecting to {}:{}", target.host, target.port))?;
                (handle, None)
            }
            Some(jump) => {
                let (h, j) = connect_via_jump(jump, target, handler).await?;
                (h, Some(j))
            }
        };

        authenticate(&mut handle, &target.username, &target.auth).await?;

        let (algo, fp) = captured.lock().unwrap().clone().unwrap_or_default();
        Ok(Self {
            handle,
            _jump: jump_handle,
            host_key_algo: algo,
            host_key_sha256: fp,
        })
    }

    /// Run a command, returning (combined stdout+stderr, exit code).
    pub async fn run(&self, command: &str) -> Result<(String, i32)> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command.as_bytes()).await?;

        let mut out: Vec<u8> = Vec::new();
        let mut code: i32 = -1;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                ChannelMsg::ExtendedData { ref data, .. } => out.extend_from_slice(data),
                ChannelMsg::ExitStatus { exit_status } => {
                    code = exit_status as i32;
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok((String::from_utf8_lossy(&out).into_owned(), code))
    }

    /// Read-mostly, self-cleaning capability probe.
    pub async fn probe(&self) -> Result<ProbeResult> {
        let mut r = ProbeResult {
            reachable: true,
            host_key_algo: self.host_key_algo.clone(),
            host_key_sha256: self.host_key_sha256.clone(),
            ..Default::default()
        };

        if let Ok((who, 0)) = self.run("whoami").await {
            let who = who.trim().to_string();
            if !who.is_empty() {
                r.whoami = Some(who);
            }
        }
        if let Ok((os, 0)) = self
            .run("uname -a 2>/dev/null || (head -n1 /etc/os-release 2>/dev/null)")
            .await
        {
            let os = os.trim().to_string();
            if !os.is_empty() {
                r.os = Some(os);
            }
        }
        if let Ok((o, _)) = self
            .run("sudo -n true 2>/dev/null && echo yes || echo no")
            .await
        {
            r.is_sudoer = o.trim() == "yes";
        }
        if let Ok((o, _)) = self
            .run("ls -la \"$HOME\" >/dev/null 2>&1 && echo ok || echo no")
            .await
        {
            r.can_read = o.trim() == "ok";
        }
        // Write probe confined to $HOME, always cleans up after itself.
        if let Ok((o, _)) = self
            .run("t=\"$HOME/.syncho_probe.$$\"; (printf probe > \"$t\" && rm -f \"$t\" && echo ok) || echo no")
            .await
        {
            r.can_write = o.trim() == "ok";
        }
        Ok(r)
    }
}

/// Authenticate an open handle with the given method.
async fn authenticate(
    handle: &mut Handle<HostKeyHandler>,
    username: &str,
    auth: &SshAuth,
) -> Result<()> {
    let result = match auth {
        SshAuth::Password(pw) => handle
            .authenticate_password(username, pw.as_str())
            .await
            .context("password authentication")?,
        SshAuth::Key { path, passphrase } => {
            let key = russh::keys::load_secret_key(path, passphrase.as_deref().map(|z| z.as_str()))
                .with_context(|| format!("loading private key {path}"))?;
            let kwh = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            handle
                .authenticate_publickey(username, kwh)
                .await
                .context("public-key authentication")?
        }
        SshAuth::Agent => {
            return Err(anyhow!("SSH agent authentication is not wired yet"));
        }
    };
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::Failure { .. } => Err(anyhow!("authentication failed (check credentials)")),
    }
}

/// Connect to `target` through a `jump` host (ProxyJump). The jump host is
/// authenticated with key/agent only; passwords on the jump are not supported.
#[allow(clippy::type_complexity)]
async fn connect_via_jump(
    jump: &SshTarget,
    target: &SshTarget,
    handler: HostKeyHandler,
) -> Result<(Handle<HostKeyHandler>, Handle<HostKeyHandler>)> {
    // The jump host gets its own throwaway handler (TOFU, not pinned here).
    let jump_handler = HostKeyHandler {
        pinned: None,
        captured: Arc::new(Mutex::new(None)),
    };
    let mut jump_handle = client::connect(config(), (jump.host.as_str(), jump.port), jump_handler)
        .await
        .with_context(|| format!("connecting to jump host {}:{}", jump.host, jump.port))?;
    authenticate(&mut jump_handle, &jump.username, &jump.auth)
        .await
        .context("authenticating to jump host")?;

    let channel = jump_handle
        .channel_open_direct_tcpip(target.host.as_str(), target.port as u32, "127.0.0.1", 0)
        .await
        .context("opening tunnel through jump host")?;

    let stream = channel.into_stream();
    let handle = client::connect_stream(config(), stream, handler)
        .await
        .with_context(|| format!("connecting to {}:{} through jump", target.host, target.port))?;
    Ok((handle, jump_handle))
}
