//! Locaryn SSH Plugin
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecRequest {
    pub server_id: String,
    pub command: String,
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
}

/// Non implemente. La signature est conservee pour que l'interface et le
/// serveur MCP gardent leur forme, mais l'appel echoue franchement plutot
/// que de fabriquer un resultat.
pub async fn ssh_exec(_req: SshExecRequest) -> Result<SshExecResult, String> {
    Err("L'execution distante n'est pas implementee : ce morph n'ouvre aucune connexion SSH. Aucune commande n'a ete executee.".into())
}
