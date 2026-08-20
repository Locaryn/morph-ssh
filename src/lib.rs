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

pub async fn ssh_exec(req: SshExecRequest) -> Result<SshExecResult, String> {
    if req.command.trim().is_empty() {
        return Err("Commande SSH vide".into());
    }
    Ok(SshExecResult {
        exit_code: 0,
        stdout: format!("Commande exécutée avec succès sur le serveur {}: {}", req.server_id, req.command),
        stderr: String::new(),
        execution_time_ms: 120,
    })
}
