/**
 * OS command injection signatures.
 *
 * Detects attempts to execute shell commands through web inputs.
 * Common in web apps that pass user input to system(), exec(),
 * popen(), or shell-out functions.
 *
 * Why these patterns matter:
 *   Successful command injection = full server compromise.
 *   It's OWASP A03:2021 (Injection) and one of the most critical
 *   categories of web vulnerability.
 *
 * Detection strategy:
 *   1. Shell metacharacters (;, |, &&) followed by a command-looking word
 *   2. Command substitution syntax: backticks and $()
 *   3. References to known recon commands (whoami, id, uname, etc.)
 *      and reverse-shell tools (nc, netcat, bash -i)
 */

import type { Signature } from '../types/threat.types';

/**
 * Reusable: a list of common Unix recon commands. These appear in
 * almost every command injection payload because they're the first
 * things attackers run to confirm execution.
 */
const RECON_COMMANDS =
  '(?:whoami|id|uname|hostname|pwd|ls|cat|head|tail|cut|awk|sed|grep|find|ps|netstat|ifconfig|ip|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)';

/**
 * Reusable: optional whitespace, including URL-encoded forms.
 */
const WS = '(?:\\s|%20|%09)';

/**
 * Shell metacharacter chaining (;, ||, &&, |) followed by a command.
 *
 * The metachar must be followed by a recon command word — this drastically
 * cuts false positives compared to "any pipe character".
 *
 * URL-encoded forms:
 *   ; → %3B
 *   | → %7C
 *   & → %26
 */
const CMDI_SHELL_CHAINING: Signature = {
  id: 'cmdi-shell-chaining-01',
  name: 'Command Injection: shell metacharacter chaining',
  type: 'COMMAND_INJECTION',
  pattern: new RegExp(
    `(?:;|%3[bB]|\\|\\||%7[cC]%7[cC]|\\||%7[cC]|&&|%26%26)${WS}*${RECON_COMMANDS}\\b`,
    'i',
  ),
  fields: ['queryString', 'path'],
  confidence: 92,
  severity: 'CRITICAL',
  description: 'Shell metacharacter (; | && etc.) chained with a recon command',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * Command substitution: backticks `cmd` or $(cmd).
 *
 * Both forms execute a command and substitute its output. Either one
 * appearing in URL params is highly suspicious.
 */
const CMDI_COMMAND_SUBSTITUTION: Signature = {
  id: 'cmdi-substitution-01',
  name: 'Command Injection: command substitution',
  type: 'COMMAND_INJECTION',
  pattern: new RegExp(
    `(?:\`|%60|\\$\\(|%24%28)${WS}*${RECON_COMMANDS}`,
    'i',
  ),
  fields: ['queryString', 'path'],
  confidence: 95,
  severity: 'CRITICAL',
  description: 'Shell command substitution (backticks or $()) with a recon command',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * Reverse shell patterns.
 *
 * Specific high-confidence indicators of a reverse-shell payload.
 * These are extremely rare in legitimate traffic.
 */
const CMDI_REVERSE_SHELL: Signature = {
  id: 'cmdi-reverse-shell-01',
  name: 'Command Injection: reverse shell payload',
  type: 'COMMAND_INJECTION',
  pattern:
    /(?:nc(?:%20|\s)+-[el]|bash(?:%20|\s)+-i|\/dev\/tcp\/|python(?:%20|\s)+-c(?:%20|\s)+['"]?import(?:%20|\s)+(?:socket|os|pty))/i,
  fields: ['queryString', 'path'],
  confidence: 98,
  severity: 'CRITICAL',
  description: 'Reverse shell pattern (nc -e, bash -i, /dev/tcp, python pty)',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * Direct reference to /bin/sh or /bin/bash in URL.
 *
 * Almost no legitimate request includes a path to a system shell.
 * If we see /bin/sh in a URL parameter, it's command injection.
 */
const CMDI_SHELL_PATH: Signature = {
  id: 'cmdi-shell-path-01',
  name: 'Command Injection: shell binary path reference',
  type: 'COMMAND_INJECTION',
  pattern: /\/bin\/(?:sh|bash|zsh|dash|ksh)\b/i,
  fields: ['queryString', 'path'],
  confidence: 88,
  severity: 'HIGH',
  description: 'Reference to a system shell binary (/bin/sh, /bin/bash, etc.)',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * Bare recon command in a parameter value.
 *
 * `?cmd=whoami` is suspicious even without metacharacters because the
 * parameter name suggests command execution. We require the parameter
 * value to BE the command (not just contain it as a substring).
 *
 * Pattern: `=` followed by a recon command, followed by either end-of-
 * string or a non-word character (so "=whoami" matches but "=whoamievil"
 * doesn't).
 */
const CMDI_BARE_RECON: Signature = {
  id: 'cmdi-bare-recon-01',
  name: 'Command Injection: bare recon command in parameter',
  type: 'COMMAND_INJECTION',
  pattern: new RegExp(`=${RECON_COMMANDS}(?:$|[^a-zA-Z0-9_]|%[0-9a-fA-F]{2})`, 'i'),
  fields: ['queryString'],
  confidence: 75,
  severity: 'MEDIUM',
  description: 'Bare recon command (whoami, id, etc.) as a parameter value',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

export const COMMAND_INJECTION_SIGNATURES: readonly Signature[] = [
  CMDI_SHELL_CHAINING,
  CMDI_COMMAND_SUBSTITUTION,
  CMDI_REVERSE_SHELL,
  CMDI_SHELL_PATH,
  CMDI_BARE_RECON,
];