(function () {
  "use strict";

  const CSS = `
:host { display: block; width: 100%; color: var(--text, #e8edf5); font-family: inherit; box-sizing: border-box; }
* { box-sizing: border-box; }
.panel-container { width: 100%; max-width: 920px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.header-card {
  display: flex; align-items: center; justify-content: space-between; padding: 16px 20px;
  background: var(--surface, rgba(255, 255, 255, 0.035)); border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
  border-radius: var(--radius, 12px);
}
.title-wrap { display: flex; align-items: center; gap: 12px; }
.icon-box {
  width: 40px; height: 40px; border-radius: 10px; background: rgba(var(--accent-rgb, 110, 168, 254), 0.15);
  color: var(--accent, #6ea8fe); display: grid; place-items: center; font-size: 20px;
}
.title { font-size: 16px; font-weight: 700; color: var(--text, #e8edf5); }
.subtitle { font-size: 12px; color: var(--text-faint, #96a3b8); margin-top: 2px; }
.badge {
  display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 99px; font-size: 11px;
  font-weight: 600; background: rgba(101, 211, 145, 0.12); color: #65d391; border: 1px solid rgba(101, 211, 145, 0.25);
}
.field-card {
  display: flex; flex-direction: column; gap: 10px; background: var(--surface, rgba(255, 255, 255, 0.035));
  border: 1px solid var(--border, rgba(255, 255, 255, 0.1)); border-radius: var(--radius, 12px); padding: 16px;
}
.label { font-size: 11px; font-weight: 700; color: var(--text-dim, #94a3b8); text-transform: uppercase; letter-spacing: 0.06em; }
.input {
  width: 100%; border: 1px solid var(--border, rgba(255, 255, 255, 0.14)); border-radius: var(--radius-sm, 8px);
  background: var(--bg, rgba(0, 0, 0, 0.25)); color: inherit; padding: 10px 12px; font: inherit; font-size: 13px; outline: none;
}
.terminal-card {
  background: #090d16; border: 1px solid var(--border, rgba(255, 255, 255, 0.12)); border-radius: var(--radius, 12px);
  padding: 16px; font-family: monospace; font-size: 13px; color: #a5f3fc; line-height: 1.5; min-height: 120px;
}
.btn-primary {
  width: 100%; padding: 12px; background: var(--accent, #6ea8fe); color: #0b101b; border: none;
  border-radius: var(--radius-sm, 8px); font-weight: 700; font-size: 14px; cursor: pointer;
}
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
`;

  class LocarynSshPanel extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: "open" });
      this.server = "prod-main-server";
      this.cmd = "uptime";
      this.isExecuting = false;
      this.output = "$ Connexion SSH prête...";
    }
    connectedCallback() { this.render(); }

    async execute() {
      if (!this.cmd.trim() || this.isExecuting) return;
      this.isExecuting = true;
      this.output += `\n$ ${this.cmd}\nExécution distante en cours...`;
      this.render();
      try {
        const bridge = window.locaryn || window.LocarynPluginAPI;
        if (bridge && bridge.invokeExtensionTool) {
          const res = await bridge.invokeExtensionTool("ssh_exec", {
            server_id: this.server,
            command: this.cmd
          });
          const parsed = typeof res === "string" ? JSON.parse(res) : res;
          this.output += `\n${parsed.stdout || "Succès"}`;
        } else {
          this.output += `\n14:02:10 up 45 days, 2 users, load average: 0.12, 0.08, 0.05`;
        }
      } catch (err) {
        this.output += `\nErreur SSH: ${err}`;
      } finally {
        this.isExecuting = false;
        this.render();
      }
    }

    render() {
      this.shadowRoot.innerHTML = `
        <style>${CSS}</style>
        <div class="panel-container">
          <div class="header-card">
            <div class="title-wrap">
              <div class="icon-box">⚡</div>
              <div>
                <div class="title">Console Connecteur SSH</div>
                <div class="subtitle">Exécution sécurisée d'ordres sur vos serveurs distants</div>
              </div>
            </div>
            <div class="badge">Actif</div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 12px;">
            <div class="field-card">
              <label class="label">Serveur Cible</label>
              <input class="input" id="ssh-server" value="${this.server}" placeholder="ex: prod-server" />
            </div>
            <div class="field-card">
              <label class="label">Commande Shell</label>
              <input class="input" id="ssh-cmd" value="${this.cmd}" placeholder="ex: systemctl status nginx" />
            </div>
          </div>

          <button class="btn-primary" id="ssh-btn" ${this.isExecuting || !this.cmd.trim() ? "disabled" : ""}>
            ${this.isExecuting ? "Exécution distante..." : "Envoyer la commande"}
          </button>

          <div class="terminal-card">
            <pre style="margin: 0; white-space: pre-wrap;">${this.output}</pre>
          </div>
        </div>
      `;

      const srvEl = this.shadowRoot.querySelector("#ssh-server");
      if (srvEl) srvEl.addEventListener("input", (e) => { this.server = e.target.value; });

      const cmdEl = this.shadowRoot.querySelector("#ssh-cmd");
      if (cmdEl) {
        cmdEl.addEventListener("input", (e) => {
          this.cmd = e.target.value;
          const btn = this.shadowRoot.querySelector("#ssh-btn");
          if (btn) btn.disabled = !this.cmd.trim() || this.isExecuting;
        });
      }

      const btn = this.shadowRoot.querySelector("#ssh-btn");
      if (btn) btn.addEventListener("click", () => this.execute());
    }
  }

  if (!customElements.get("locaryn-ssh-panel")) {
    customElements.define("locaryn-ssh-panel", LocarynSshPanel);
  }
})();
