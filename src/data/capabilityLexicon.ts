/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability lexicon — the vocabulary that maps a tool's name, description
 * verbs, and parameter shape onto the roles used by the toxic-flow graph.
 *
 * The trifecta (the lethal-trifecta toxic flow) requires three roles
 * to be simultaneously reachable in one agent session:
 *   UNTRUSTED_INPUT  →  SENSITIVE_SOURCE  →  EXTERNAL_SINK
 * We deliberately keep UNTRUSTED_INPUT and SENSITIVE_SOURCE separate — merging
 * them (as a naive "sensitive source") both over- and under-flags.
 */

import type { CapabilityTag } from '../types.js';

/** Keyword → tag rules matched against a tool's name and description. */
export interface CapabilitySignal {
  tag: CapabilityTag;
  /** Lowercased keywords/phrases; matched as word-ish substrings. */
  keywords: string[];
}

export const CAPABILITY_SIGNALS: CapabilitySignal[] = [
  {
    tag: 'untrusted-input',
    keywords: [
      'fetch_url',
      'fetch url',
      'fetch',
      'browse',
      'read_issue',
      'read issue',
      'read_pr',
      'read pull request',
      'read_email',
      'read email',
      'read_ticket',
      'read_comment',
      'read comment',
      'web_search',
      'web search',
      'search web',
      'get_page',
      'scrape',
      'crawl',
      'read_message',
      'read_dm',
      'download',
      'rss',
      'read_webhook',
    ],
  },
  {
    tag: 'sensitive-source',
    keywords: [
      'read_file',
      'read file',
      'readfile',
      'get_file_contents',
      'cat_file',
      'read_repo',
      'read_env',
      'read environment',
      'get_env',
      'query_db',
      'query database',
      'run_sql',
      'execute_sql',
      'sql_query',
      'get_logs',
      'read_logs',
      'list_secrets',
      'get_secret',
      'read_secret',
      'read_config',
      'list_keys',
      'get_credentials',
      'get_token',
      'dump',
      'export_data',
      'read_private',
      'list_files',
    ],
  },
  {
    tag: 'external-sink',
    keywords: [
      // Only DIRECTIONAL egress verbs. Bare 'post'/'request'/'forward'/'notify'
      // were removed: a precision audit found they tag readers and navigation
      // ('get_posts', 'browser_request_control', 'go_forward', 'notification
      // settings') as data sinks, inventing half of the toxic-flow false
      // positives. The specific compound forms below remain.
      'http_request',
      'http request',
      'http_post',
      'put_request',
      'send_email',
      'send email',
      'sendmail',
      'send_message',
      'send message',
      'post_message',
      'webhook',
      'create_pull_request',
      'open_pr',
      'create_issue',
      'create_comment',
      'publish_message',
      'publish_event',
      'upload_file',
      'curl',
      'forward_email',
      'forward_message',
      'send_notification',
      'tweet',
      'slack_post',
      'sms',
      'call_api',
      'export_to',
    ],
  },
  {
    tag: 'code-exec',
    keywords: [
      // NOTE: bare 'system'/'command'/'terminal' are intentionally excluded —
      // they match benign text like "file system" or "the command completed".
      // Command execution is caught by the specific verbs below plus the
      // code-exec parameter-name signals.
      'exec',
      'execute command',
      'execute code',
      'execute a command',
      'execute shell',
      'execute the command',
      'run_command',
      'run command',
      'shell',
      'bash',
      'eval',
      'run_code',
      'run_script',
      'run_shell',
      'spawn',
      'subprocess',
      'powershell',
      'python_exec',
    ],
  },
  {
    tag: 'file-write',
    keywords: [
      'write_file',
      'write file',
      'writefile',
      'create_file',
      'edit_file',
      'delete_file',
      'remove_file',
      'move_file',
      'append_file',
      'save_file',
      'overwrite',
      'rmdir',
      'unlink',
      'put_object',
    ],
  },
];

/**
 * Parameter-name → tag hints (schema-shape signals). Deliberately conservative:
 * generic names like `body`/`data`/`content` are NOT mapped (an HTTP body is not
 * a file write) — file mutation is detected from tool-name verbs instead, which
 * avoids the most common capability false positive.
 */
export const PARAM_NAME_SIGNALS: { tag: CapabilityTag; names: string[] }[] = [
  // Only DIRECTIONAL egress param names. Bare 'url'/'uri'/'endpoint' were removed:
  // a `fetch(url)` / web-read tool takes a url to READ FROM, not to send data to,
  // so those are an SSRF precondition (see SSRF_PARAM_NAMES) — not a flow egress
  // sink. 'destination' was also removed: it is overwhelmingly a FILE path (a
  // `move_file(source, destination)` is local I/O, not network egress), which
  // fabricated a toxic flow on pure filesystem servers. 'webhook'/'recipient'
  // remain — they name an outbound communication target, not a local path.
  { tag: 'external-sink', names: ['webhook', 'recipient'] },
  { tag: 'code-exec', names: ['command', 'cmd', 'script', 'shell', 'exec', 'eval'] },
  // 'query' is intentionally omitted — a search "query" is not sensitive-data
  // access; real DB reads are caught by tool-name verbs (query_db, run_sql, …).
  // A parameter merely NAMED path/filepath/filename is a path-TRAVERSAL precondition
  // (see PATH_PARAM_NAMES / MTC-CAP-008), NOT evidence the tool reads sensitive DATA.
  // Tagging it sensitive-source fabricated the read-leg of the toxic-flow trifecta on
  // ~750 packages that touch no sensitive data. Keep only genuinely-sensitive names.
  { tag: 'sensitive-source', names: ['secret', 'sql'] },
];

/** URL/host-shaped parameter names — an unconstrained one is an SSRF precondition. */
// Only genuinely URL/host-shaped names. 'endpoint'/'target'/'server'/'address' were
// removed: they are overwhelmingly config-setter or generic fields, not a fetched
// URL, and drove MTC-CAP-007 false positives on servers that STORE rather than call.
export const SSRF_PARAM_NAMES = ['url', 'uri', 'host', 'hostname'];

/** Path-shaped parameter names — an unconstrained one is a path-traversal precondition. */
export const PATH_PARAM_NAMES = ['path', 'filepath', 'filename', 'file', 'dir', 'directory'];

/** Command-shaped parameter names — an unconstrained one is a command-injection precondition. */
export const COMMAND_PARAM_NAMES = ['command', 'cmd', 'script', 'shell', 'exec', 'eval', 'code'];

/**
 * Field names that must never be collected via MCP elicitation (the spec
 * forbids it). Their presence alongside a declared elicitation capability is a
 * credential-phishing signal.
 */
export const SECRET_FIELD_NAMES = [
  'password',
  'passwd',
  'api_key',
  'apikey',
  'token',
  'secret',
  'ssn',
  'seed_phrase',
  'seedphrase',
  'mnemonic',
  'private_key',
  'privatekey',
  'credit_card',
  'creditcard',
  'cvv',
  'pin',
];

/**
 * The virtual "client built-in" tools. When `includeBuiltins` is set, the
 * toxic-flow graph assumes the host agent also exposes generic web-fetch (an
 * untrusted-input source) and generic file/network tools (sinks), which can
 * complete a trifecta together with a single-capability server.
 */
export const CLIENT_BUILTINS: { tool: string; tags: CapabilityTag[] }[] = [
  { tool: '<client:web-fetch>', tags: ['untrusted-input'] },
  { tool: '<client:filesystem>', tags: ['sensitive-source', 'file-write'] },
  { tool: '<client:shell>', tags: ['code-exec', 'external-sink'] },
];
