# Documentazione Agente Autonomo CTF (MCP-Based)

Questa guida descrive l'architettura e il funzionamento dell'Agente Autonomo sviluppato per la competizione Cyberchallenge Attack & Defense. L'agente è progettato per operare autonomamente all'interno della macchina vulnerabile, analizzare il codice, configurare il WAF (Firegex) e mitigare gli attacchi in tempo reale.

## Architettura del Sistema

Il sistema è composto da quattro moduli principali che interagiscono tra loro:

1.  **Autonomous CLI (`autonomous_ctf_agent.py`)**: Il punto di ingresso. Gestisce il ciclo di vita dell'agente (Discovery -> Analysis -> WAF Setup -> Monitoring).
2.  **Core Controller (`agent_core.py`)**: Il cervello operativo. Coordina l'uso degli strumenti e mantiene lo stato della sessione (target corrente, regole applicate).
3.  **Agent Brain (`agent_brain.py`)**: Il modulo di intelligenza. Integra strumenti statici (SAST con Bandit) e modelli di linguaggio (LLM via Ollama) per analizzare il codice e generare Regex difensive.
4.  **MCP Server & Tools (`firegex_mcp_server.py`)**: Espone le funzionalità di sistema e di rete come "Tools" utilizzabili. Sebbene possa funzionare come server MCP standard, l'agente Python attuale importa direttamente queste funzioni per efficienza locale.

---

## Flusso Operativo

### 1. Discovery dell'Infrastruttura
L'agente inizia scansionando l'ambiente Docker locale per identificare i servizi da proteggere.
-   **Tool usato**: `discover_infrastructure()`
-   **Logica**: Ispeziona il container `firegex` per trovare le porte esposte e mappa i servizi collegati in modalità `network_mode: service:firegex`.
-   **Risultato**: Identifica IP e Porta del servizio vulnerabile (es. `127.0.0.1:5000`).

### 2. Analisi del Codice (Vulnerability Scanning)
Una volta identificato il target, l'agente esplora il file system per trovare il codice sorgente.
-   **Fase 1: Recon**: Usa `list_files` (ls) per mappare la struttura del progetto, filtrando binari e file inutili.
-   **Fase 2: Lettura**: Usa `read_file_content` (cat) per estrarre il codice sorgente.
-   **Fase 3: Analisi Ibrida (`AgentBrain`)**:
    -   **SAST (Bandit)**: Scansione statica rapida per vulnerabilità note in Python.
    -   **LLM (Ollama)**: Il codice viene inviato al modello (Mistral) con un prompt specifico che include il contesto dell'infrastruttura di gara (Checkers vs Attackers).
    -   **Output**: Il modello restituisce una lista di **Regex** progettate per bloccare gli exploit specifici trovati nel codice (es. SQL Injection, RCE) senza bloccare il traffico legittimo dei checker.

### 3. Configurazione WAF (Firegex)
L'agente configura automaticamente il firewall Firegex per proteggere il servizio rilevato.
-   **Tool usato**: `setup_firegex_service()`
-   **Azioni**:
    1.  Crea un servizio **NFProxy** per intercettare e loggare il traffico HTTP.
    2.  Carica un filtro Python (`AI_SNIFFER_CODE`) nel proxy per analizzare semanticamente richieste e risposte.
    3.  Crea un servizio **NFRegex** (Netfilter Regex) per applicare le regole di blocco ad alte prestazioni nel kernel.
    4.  Avvia i servizi.

### 4. Applicazione Regole (Patching Virtuale)
Le regex generate nella fase di analisi vengono proposte all'utente.
-   **Tool usato**: `add_blocking_rule_regex()`
-   **Logica**: Le regole vengono convertite in base64 e inviate alle API di Firegex. Il modulo NFRegex del kernel Linux bloccherà qualsiasi pacchetto TCP contenente quei pattern.

### 5. Monitoraggio Attivo (Sentry Loop)
L'agente entra in un ciclo infinito di sorveglianza.
-   **Tool usato**: `get_traffic_logs()`
-   **Logica**: Legge i log generati dall'AI Sniffer (`/tmp/ai_context.log`).
-   **Reazione**: Se rileva nuovi pattern di attacco nel traffico vivo (es. payload non visti durante l'analisi statica), può generare e applicare nuove regole di blocco istantaneamente.

---

## Dettaglio Integrazione MCP (Model Context Protocol)

Il file `firegex_mcp_server.py` implementa lo standard MCP. Questo permette all'agente di astarre le azioni complesse in "Tools" semplici:

| Tool | Descrizione | Scopo |
|------|-------------|-------|
| `list_files` | Elenca file ricorsivamente | Esplorazione workspace |
| `read_file_content` | Legge contenuto file | Analisi sorgente |
| `discover_infrastructure` | `docker inspect` ... | Trovare Target IP/Port |
| `setup_firegex_service` | Chiama API Firegex | Configurazione iniziale WAF |
| `add_blocking_rule_regex` | POST /api/nfregex/regexes | Applicazione filtri di difesa |
| `get_traffic_logs` | `tail` su log file | Monitoraggio tempo reale |

Grazie a questa astrazione, l'agente non deve sapere *come* configurare Docker o chiamare le API REST di Firegex; deve solo decidere *quale tool chiamare* in base alla strategia di difesa.
