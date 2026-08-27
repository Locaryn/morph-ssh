//! Stdio MCP server shipped by plugin-ssh.
use locaryn_plugin_ssh::{ssh_exec, SshExecRequest};
use serde_json::{json, Value};
use std::io::Write;
use tokio::io::{AsyncBufReadExt, BufReader};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle_request(request).await,
            Err(error) => error_response(Value::Null, -32700, format!("JSON invalide : {error}")),
        };
        if let Ok(serialized) = serde_json::to_string(&response) {
            println!("{serialized}");
            let _ = std::io::stdout().flush();
        }
    }
}

async fn handle_request(request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match method {
        "initialize" => success(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "plugin-ssh", "version": VERSION }
            }),
        ),
        "tools/list" => success(id, tools_list()),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call_tool(name, args).await {
                Ok(value) => success(id, text_content(value)),
                Err(error) => error_response(id, -32000, error),
            }
        }
        notification if notification.starts_with("notifications/") => Value::Null,
        _ => error_response(id, -32601, format!("méthode MCP inconnue : {method}")),
    }
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "ssh_exec",
                "description": "Exécute une commande de terminal à distance sur un serveur SSH configuré.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_id": { "type": "string", "description": "Identifiant ou alias du serveur SSH" },
                        "command": { "type": "string", "description": "Commande shell à exécuter" },
                        "working_dir": { "type": "string", "description": "Répertoire de travail distant optionnel" }
                    },
                    "required": ["server_id", "command"]
                }
            }
        ]
    })
}

async fn call_tool(name: &str, args: Value) -> Result<Value, String> {
    match name {
        "ssh_exec" => {
            let req: SshExecRequest = serde_json::from_value(args)
                .map_err(|e| format!("Paramètres SSH invalides: {e}"))?;
            let res = ssh_exec(req).await?;
            Ok(json!(res))
        }
        _ => Err(format!("Outil SSH inconnu : {name}")),
    }
}

fn text_content(value: Value) -> Value {
    json!({ "content": [{ "type": "text", "text": serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()) }] })
}
fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}
fn error_response(id: Value, code: i64, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
