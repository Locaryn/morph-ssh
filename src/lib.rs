//! Exécution de commandes sur une machine distante, par SSH.
//!
//! Le morph tient son propre **registre de serveurs**, dans son dossier privé.
//! C'est délibéré : les outils exposés au modèle ne prennent qu'un `server_id`,
//! jamais un mot de passe ni un chemin de clé. Un secret passé en argument
//! d'outil finirait dans la conversation, donc dans l'historique, donc dans le
//! contexte de tous les échanges suivants. Il reste sur le disque, à côté du
//! morph, et n'en sort pas.
//!
//! L'empreinte de la clé d'hôte se range dans ce même fichier. Tant qu'elle est
//! absente, la connexion la capture et la rend pour confirmation ; une fois
//! écrite, toute empreinte différente fait échouer la connexion.

pub mod ssh;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub use ssh::{ProbeResult, SshAuth, SshClient, SshTarget};

// ── Registre ────────────────────────────────────────────────────────────────

/// Comment s'authentifier sur une machine. Le secret ne quitte pas ce fichier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum StoredAuth {
    Password {
        password: String,
    },
    Key {
        /// Chemin d'une clé privée OpenSSH sur cette machine.
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
}

/// Une machine connue du morph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredServer {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: StoredAuth,
    /// Empreinte `SHA256:…` attendue de la clé d'hôte. Absente au premier
    /// contact ; une fois posée, elle est exigée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_sha256: Option<String>,
    /// Machine de rebond, désignée par son propre identifiant dans ce registre.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_via: Option<String>,
}

fn default_port() -> u16 {
    22
}

/// Ce qu'on peut dire d'un serveur sans rien divulguer.
#[derive(Debug, Clone, Serialize)]
pub struct ServerSummary {
    pub id: String,
    pub label: Option<String>,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `password` ou `key` — jamais la valeur.
    pub auth_method: &'static str,
    pub host_key_pinned: bool,
    pub jump_via: Option<String>,
}

impl From<&StoredServer> for ServerSummary {
    fn from(s: &StoredServer) -> Self {
        Self {
            id: s.id.clone(),
            label: s.label.clone(),
            host: s.host.clone(),
            port: s.port,
            username: s.username.clone(),
            auth_method: match s.auth {
                StoredAuth::Password { .. } => "password",
                StoredAuth::Key { .. } => "key",
            },
            host_key_pinned: s.host_key_sha256.is_some(),
            jump_via: s.jump_via.clone(),
        }
    }
}

/// Le fichier qui porte le registre.
///
/// L'hôte désigne un dossier privé par morph ; sans lui, un fichier à côté du
/// répertoire courant, pour pouvoir travailler hors application.
pub fn registry_path() -> PathBuf {
    for key in ["LOCARYN_EXTENSION_DATA_DIR", "LOCARYN_MORPH_ROOT"] {
        if let Ok(dir) = std::env::var(key) {
            if !dir.trim().is_empty() {
                return PathBuf::from(dir).join("servers.json");
            }
        }
    }
    PathBuf::from("servers.json")
}

/// Lire le registre. Un fichier absent n'est pas une erreur : c'est un
/// registre vide.
pub fn load_servers() -> Result<Vec<StoredServer>, String> {
    let path = registry_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("lecture de {} : {e}", path.display())),
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&raw).map_err(|e| format!("{} est illisible : {e}", path.display()))
}

fn save_servers(servers: &[StoredServer]) -> Result<(), String> {
    let path = registry_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{} : {e}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(servers).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| format!("écriture de {} : {e}", path.display()))
}

fn find_server(id: &str) -> Result<StoredServer, String> {
    load_servers()?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| {
            format!(
                "Aucun serveur « {id} » dans le registre. `list_servers` donne les noms connus."
            )
        })
}

// ── Construction de la cible ────────────────────────────────────────────────

fn to_auth(auth: &StoredAuth) -> SshAuth {
    match auth {
        StoredAuth::Password { password } => SshAuth::Password(Zeroizing::new(password.clone())),
        StoredAuth::Key { path, passphrase } => SshAuth::Key {
            path: path.clone(),
            passphrase: passphrase.clone().map(Zeroizing::new),
        },
    }
}

/// Composer la cible, en suivant au plus une machine de rebond.
///
/// Une seule : un rebond qui se désigne lui-même, ou deux qui se renvoient
/// l'un à l'autre, ferait boucler la résolution sans fin.
fn to_target(server: &StoredServer) -> Result<SshTarget, String> {
    let jump = match &server.jump_via {
        None => None,
        Some(jid) => {
            if jid == &server.id {
                return Err(format!(
                    "Le serveur « {} » se désigne lui-même comme rebond.",
                    server.id
                ));
            }
            let j = find_server(jid)?;
            if j.jump_via.is_some() {
                return Err(format!(
                    "Le rebond « {jid} » en désigne un autre ; un seul niveau est pris en charge."
                ));
            }
            Some(Box::new(SshTarget {
                host: j.host.clone(),
                port: j.port,
                username: j.username.clone(),
                auth: to_auth(&j.auth),
                jump: None,
            }))
        }
    };
    Ok(SshTarget {
        host: server.host.clone(),
        port: server.port,
        username: server.username.clone(),
        auth: to_auth(&server.auth),
        jump,
    })
}

async fn connect(server: &StoredServer) -> Result<SshClient, String> {
    let target = to_target(server)?;
    SshClient::connect(&target, server.host_key_sha256.as_deref())
        .await
        .map_err(|e| {
            // Une empreinte qui ne correspond pas mérite d'être nommée : c'est
            // le seul cas où l'échec peut signifier une interception.
            if server.host_key_sha256.is_some() {
                format!(
                    "Connexion à {} refusée : {e}. Si la machine a été réinstallée, retirez son \
                     empreinte du registre pour la reconnaître à nouveau.",
                    server.host
                )
            } else {
                format!("Connexion à {} impossible : {e}", server.host)
            }
        })
}

// ── Opérations ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecRequest {
    pub server_id: String,
    pub command: String,
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
}

/// Exécuter une commande sur la machine désignée.
///
/// La sortie standard et la sortie d'erreur reviennent mêlées par le canal SSH ;
/// on les rend dans `stdout` et on laisse `stderr` vide plutôt que d'inventer
/// une séparation que le protocole n'a pas faite ici.
pub async fn ssh_exec(req: SshExecRequest) -> Result<SshExecResult, String> {
    if req.command.trim().is_empty() {
        return Err("Commande vide : rien à exécuter.".into());
    }
    let server = find_server(&req.server_id)?;
    let client = connect(&server).await?;

    // `cd` échoue bruyamment si le dossier n'existe pas : mieux vaut ça qu'une
    // commande exécutée ailleurs que là où on la croyait.
    let command = match req.working_dir.as_deref().map(str::trim) {
        Some(dir) if !dir.is_empty() => format!("cd {} && {}", shell_quote(dir), req.command),
        _ => req.command.clone(),
    };

    let started = std::time::Instant::now();
    let (out, code) = client
        .run(&command)
        .await
        .map_err(|e| format!("Exécution sur {} : {e}", server.host))?;

    Ok(SshExecResult {
        exit_code: code,
        stdout: out,
        stderr: String::new(),
        execution_time_ms: started.elapsed().as_millis() as u64,
    })
}

/// Les serveurs connus, sans un seul secret.
pub fn list_servers() -> Result<Vec<ServerSummary>, String> {
    Ok(load_servers()?.iter().map(ServerSummary::from).collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    pub server_id: String,
    pub reachable: bool,
    pub os: Option<String>,
    pub whoami: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub is_sudoer: bool,
    pub host_key_algo: String,
    pub host_key_sha256: String,
    /// Vrai quand l'empreinte vient d'être découverte et n'est pas encore
    /// épinglée. Elle le sera au prochain appel de `trust_host_key`.
    pub host_key_new: bool,
}

/// Sonder ce que la machine permet : qui l'on est, quel système, ce qu'on peut
/// lire, écrire, et si `sudo` passe sans mot de passe.
///
/// Le test d'écriture se confine au dossier personnel et efface son fichier.
pub async fn probe_server(server_id: &str) -> Result<ProbeReport, String> {
    let server = find_server(server_id)?;
    let client = connect(&server).await?;
    let r: ProbeResult = client
        .probe()
        .await
        .map_err(|e| format!("Sondage de {} : {e}", server.host))?;
    Ok(ProbeReport {
        server_id: server.id.clone(),
        reachable: r.reachable,
        os: r.os,
        whoami: r.whoami,
        can_read: r.can_read,
        can_write: r.can_write,
        is_sudoer: r.is_sudoer,
        host_key_algo: r.host_key_algo,
        host_key_sha256: r.host_key_sha256,
        host_key_new: server.host_key_sha256.is_none(),
    })
}

/// Épingler l'empreinte présentée par la machine.
///
/// À n'appeler qu'après avoir montré l'empreinte à la personne : c'est elle
/// qui décide de faire confiance, pas le modèle.
pub async fn trust_host_key(server_id: &str, fingerprint: &str) -> Result<ServerSummary, String> {
    let mut servers = load_servers()?;
    let server = servers
        .iter_mut()
        .find(|s| s.id == server_id)
        .ok_or_else(|| format!("Aucun serveur « {server_id} » dans le registre."))?;
    if let Some(existing) = &server.host_key_sha256 {
        if existing != fingerprint {
            return Err(format!(
                "« {server_id} » est déjà épinglé sur une autre empreinte. Retirez-la du registre \
                 à la main si la machine a réellement changé."
            ));
        }
    }
    server.host_key_sha256 = Some(fingerprint.to_string());
    let summary = ServerSummary::from(&*server);
    save_servers(&servers)?;
    Ok(summary)
}

/// Mettre un argument à l'abri du shell distant.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LOCARYN_EXTENSION_DATA_DIR` est global au processus : deux tests qui
    /// le posent en même temps se marchent dessus. Le verrou les met en file.
    /// Sans lui, la suite passe en série et échoue en parallèle — c'est-à-dire
    /// qu'elle échoue en intégration continue.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn registre_temporaire(nom: &str, contenu: &str) -> std::sync::MutexGuard<'static, ()> {
        let garde = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("morph-ssh-{nom}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("servers.json"), contenu).unwrap();
        std::env::set_var("LOCARYN_EXTENSION_DATA_DIR", &dir);
        garde
    }

    #[test]
    fn un_registre_absent_est_un_registre_vide() {
        let _garde = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("morph-ssh-vide");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("LOCARYN_EXTENSION_DATA_DIR", &dir);
        assert!(load_servers().unwrap().is_empty());
    }

    /// Le résumé est ce que voit le modèle : il ne doit porter aucun secret.
    #[test]
    fn le_resume_ne_laisse_filtrer_aucun_secret() {
        let _garde = registre_temporaire(
            "secrets",
            r#"[{"id":"prod","host":"h","username":"u",
                 "auth":{"method":"password","password":"tres-secret"}}]"#,
        );
        let vus = list_servers().unwrap();
        let json = serde_json::to_string(&vus).unwrap();
        assert!(!json.contains("tres-secret"), "{json}");
        assert!(json.contains("\"auth_method\":\"password\""), "{json}");
        assert_eq!(vus[0].port, 22, "le port par défaut doit être posé");
        assert!(!vus[0].host_key_pinned);
    }

    #[test]
    fn une_commande_vide_est_refusee_sans_ouvrir_de_connexion() {
        let _garde = registre_temporaire(
            "vide-cmd",
            r#"[{"id":"a","host":"h","username":"u","auth":{"method":"key","path":"/k"}}]"#,
        );
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(ssh_exec(SshExecRequest {
                server_id: "a".into(),
                command: "   ".into(),
                working_dir: None,
            }))
            .unwrap_err();
        assert!(err.contains("vide"), "{err}");
    }

    #[test]
    fn un_serveur_inconnu_est_nomme() {
        let _garde = registre_temporaire("inconnu", "[]");
        let err = find_server("fantome").unwrap_err();
        assert!(err.contains("fantome"), "{err}");
        assert!(err.contains("list_servers"), "{err}");
    }

    /// Un rebond qui se désigne lui-même ferait boucler la résolution.
    #[test]
    fn un_rebond_circulaire_est_refuse() {
        let _garde = registre_temporaire(
            "boucle",
            r#"[{"id":"a","host":"h","username":"u","jump_via":"a",
                 "auth":{"method":"key","path":"/k"}}]"#,
        );
        let s = find_server("a").unwrap();
        let err = to_target(&s).unwrap_err();
        assert!(err.contains("lui-même"), "{err}");
    }

    #[test]
    fn un_rebond_de_rebond_est_refuse() {
        let _garde = registre_temporaire(
            "chaine",
            r#"[{"id":"a","host":"h","username":"u","jump_via":"b","auth":{"method":"key","path":"/k"}},
                {"id":"b","host":"h2","username":"u","jump_via":"c","auth":{"method":"key","path":"/k"}},
                {"id":"c","host":"h3","username":"u","auth":{"method":"key","path":"/k"}}]"#,
        );
        let s = find_server("a").unwrap();
        let err = to_target(&s).unwrap_err();
        assert!(err.contains("un seul niveau"), "{err}");
    }

    /// Un dossier de travail arrive du modèle : il doit être cité, sinon une
    /// apostrophe ou un `;` y ferait exécuter autre chose.
    #[test]
    fn le_dossier_de_travail_est_cite() {
        assert_eq!(shell_quote("/tmp/a b"), "'/tmp/a b'");
        assert_eq!(shell_quote("/tmp; rm -rf /"), "'/tmp; rm -rf /'");
        assert_eq!(shell_quote("l'ecole"), r"'l'\''ecole'");
    }

    #[test]
    fn epingler_une_empreinte_differente_est_refuse() {
        let _garde = registre_temporaire(
            "epingle",
            r#"[{"id":"a","host":"h","username":"u","host_key_sha256":"SHA256:AAA",
                 "auth":{"method":"key","path":"/k"}}]"#,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(trust_host_key("a", "SHA256:BBB")).unwrap_err();
        assert!(err.contains("déjà épinglé"), "{err}");
        // La même empreinte, elle, passe sans bruit.
        assert!(rt.block_on(trust_host_key("a", "SHA256:AAA")).is_ok());
    }
}
