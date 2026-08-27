//! Serveur MCP du morph SSH.
//!
//! Aucun outil ne prend de secret : on désigne une machine par son
//! identifiant, et le mot de passe ou la clé restent dans le registre privé du
//! morph. Un secret passé en argument d'outil entrerait dans la conversation.
use locaryn_plugin_ssh::{list_servers, probe_server, ssh_exec, trust_host_key, SshExecRequest};
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
                "name": "list_servers",
                "description": "Les machines enregistrées dans ce morph : identifiant, hôte,                                 utilisateur, méthode d'authentification et si la clé d'hôte est                                 déjà épinglée. Aucun secret n'est rendu.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "probe_server",
                "description": "Se connecte et rend ce que la machine permet : système, identité,                                 lecture, écriture, sudo sans mot de passe. Le test d'écriture se                                 confine au dossier personnel et efface son fichier. Rend aussi                                 l'empreinte de la clé d'hôte ; `host_key_new` dit qu'elle n'est                                 pas encore épinglée.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_id": { "type": "string", "description": "Identifiant du serveur, tel que rendu par `list_servers`" }
                    },
                    "required": ["server_id"]
                }
            },
            {
                "name": "ssh_exec",
                "description": "Exécute une commande sur une machine enregistrée et rend sa sortie                                 et son code de retour. La commande part telle quelle ; le dossier                                 de travail, lui, est cité.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_id": { "type": "string", "description": "Identifiant du serveur, tel que rendu par `list_servers`" },
                        "command": { "type": "string", "description": "Commande shell à exécuter" },
                        "working_dir": { "type": "string", "description": "Dossier où se placer avant d'exécuter" }
                    },
                    "required": ["server_id", "command"]
                }
            },
            {
                "name": "trust_host_key",
                "description": "Épingle l'empreinte de clé d'hôte d'une machine. À n'appeler                                 qu'après avoir montré l'empreinte à la personne : c'est elle qui                                 décide de faire confiance. Une empreinte déjà épinglée ne peut pas                                 être remplacée par cet outil.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_id": { "type": "string" },
                        "fingerprint": { "type": "string", "description": "Empreinte SHA256:… telle que rendue par `probe_server`" }
                    },
                    "required": ["server_id", "fingerprint"]
                }
            }
        ]
    })
}

async fn call_tool(name: &str, args: Value) -> Result<Value, String> {
    let texte = |cle: &str| -> Result<String, String> {
        args.get(cle)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("Le paramètre « {cle} » manque."))
    };
    match name {
        "list_servers" => Ok(json!({ "servers": list_servers()? })),
        "probe_server" => Ok(json!(probe_server(&texte("server_id")?).await?)),
        "ssh_exec" => {
            let req: SshExecRequest = serde_json::from_value(args.clone())
                .map_err(|e| format!("Paramètres SSH invalides : {e}"))?;
            Ok(json!(ssh_exec(req).await?))
        }
        "trust_host_key" => Ok(json!(
            trust_host_key(&texte("server_id")?, &texte("fingerprint")?).await?
        )),
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
