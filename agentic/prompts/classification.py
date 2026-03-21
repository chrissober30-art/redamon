"""
RedAmon Attack Skill Classification Prompt

LLM-based classification of user intent to select the appropriate attack skill and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
Dynamically includes only ENABLED skills in the classification prompt.
"""

from project_settings import get_enabled_builtin_skills, get_enabled_user_skills, get_setting


# =============================================================================
# BUILT-IN SKILL SECTIONS (included when the skill is enabled)
# =============================================================================

_CVE_EXPLOIT_SECTION = """### cve_exploit — CVE (MSF)
- Exploit known CVE vulnerabilities directly against a service using Metasploit Framework (MSF) modules
- Keywords: CVE-XXXX, exploit, RCE, vulnerability, pwn, hack, metasploit
"""

_BRUTE_FORCE_SECTION = """### brute_force_credential_guess
- Password guessing / credential attacks using Hydra against login services (SSH, FTP, MySQL, RDP, SMB, etc.)
- Keywords: brute force, crack password, dictionary attack, wordlist, password spray, guess password, credential attack
"""

_PHISHING_SECTION = """### phishing_social_engineering
- Attack where a target user must execute, open, click, or install something (payload, document, link, one-liner)
- Includes: msfvenom payloads, document-based payloads, web delivery, email delivery, handler setup
- Key distinction: target user runs artifact on THEIR machine (vs cve_exploit which hits a service directly)
- Keywords: payload, reverse shell, msfvenom, payload delivery, phishing, document payload, handler
"""

_DOS_SECTION = """### denial_of_service
- Attacks that DISRUPT service availability rather than gaining access or stealing data
- Includes: DoS modules, flooding, slowloris, resource exhaustion, crash exploits
- Key distinction: goal is DISRUPTION/CRASH/UNAVAILABILITY — no shell, no credentials, no data theft
- Keywords: dos, denial of service, crash, disrupt, availability, slowloris, flood, exhaust, stress test, take down, knock offline, overwhelm
"""

_UNCLASSIFIED_SECTION = """### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit the enabled attack skills above
- The agent has no specialized workflow for these — it will use available tools generically
- **Key distinction from phishing:** the attacker directly interacts with a SERVICE/APPLICATION, NOT generating a payload for a target user to execute
  - "Try SQL injection on the web app" → unclassified (attacker sends crafted input to a web service)
  - "Generate a reverse shell payload" → phishing (attacker creates a file for a target user to execute)
- You MUST create a short, descriptive snake_case term followed by "-unclassified"
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Example values: "sql_injection-unclassified", "ssrf-unclassified", "xss-unclassified", "file_upload-unclassified", "directory_traversal-unclassified"
- Keywords: SQL injection, XSS, cross-site scripting, directory traversal, path traversal, SSRF, file upload, command injection, LFI, RFI, deserialization, XXE, privilege escalation
- Example requests:
  - "Try SQL injection on the web app" -> "sql_injection-unclassified"
  - "Test for SSRF on the API" -> "ssrf-unclassified"
  - "Try to upload a web shell" -> "file_upload-unclassified"
  - "Test for XSS on the login page" -> "xss-unclassified"
  - "Attempt directory traversal" -> "directory_traversal-unclassified"
  - "Try command injection on the web form" -> "command_injection-unclassified"
"""

# Map of built-in skill ID -> (section text, classification priority letter)
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    'brute_force_credential_guess': (_BRUTE_FORCE_SECTION, 'b', 'brute_force_credential_guess'),
    'cve_exploit': (_CVE_EXPLOIT_SECTION, 'c', 'cve_exploit'),
    'denial_of_service': (_DOS_SECTION, 'd', 'denial_of_service'),
}

# Priority order for built-in classification instructions
_PRIORITY_INSTRUCTIONS = {
    'phishing_social_engineering': """   {letter}. **phishing_social_engineering** (check FIRST — highest priority):
      - Is the request asking to GENERATE, CREATE, or SET UP a payload, malicious file, document, backdoor, reverse shell, one-liner, or delivery server?
      - Will the output be something a target user must execute, open, click, or install on their machine?
      - Does it mention msfvenom, handler, multi/handler, web delivery, HTA server, encoding for AV evasion?
      - Does it mention sending something via email to a target person?
      - If YES to any → "phishing_social_engineering" """,
    'brute_force_credential_guess': """   {letter}. **brute_force_credential_guess**:
      - Does the request mention password guessing, brute force, credential attacks, wordlists, or dictionary attacks?
      - Does it target a login service (SSH, FTP, MySQL, etc.) with credential-based attack?
      - If YES → "brute_force_credential_guess" """,
    'cve_exploit': """   {letter}. **cve_exploit**:
      - Does the request mention a specific CVE ID or Metasploit exploit module to use DIRECTLY against a service?
      - Does it describe exploiting a service vulnerability where NO target user interaction is needed?
      - If YES → "cve_exploit" """,
    'denial_of_service': """   {letter}. **denial_of_service**:
      - Is the goal to DISRUPT, CRASH, or make a service UNAVAILABLE (not to gain access)?
      - Does it mention DoS, denial of service, flooding, slowloris, stress test, take down, exhaust resources?
      - Is the user NOT trying to get a shell, steal data, or obtain credentials?
      - If YES → "denial_of_service" """,
}


def build_classification_prompt(objective: str) -> str:
    """Build a dynamic classification prompt based on enabled skills.

    Only includes sections for enabled built-in skills and any enabled user skills.
    """
    enabled_builtins = get_enabled_builtin_skills()
    enabled_user_skills = get_enabled_user_skills()

    # RoE enforcement: exclude skills from classification when RoE prohibits them
    if get_setting('ROE_ENABLED', False):
        if not get_setting('ROE_ALLOW_DOS', False):
            enabled_builtins.discard('denial_of_service')
        if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
            enabled_builtins.discard('brute_force_credential_guess')
        if not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False):
            enabled_builtins.discard('phishing_social_engineering')

    # --- Header ---
    parts = [
        "You are classifying a penetration testing request to determine:\n"
        "1. The required PHASE (informational vs exploitation)\n"
        "2. The ATTACK SKILL TYPE (for exploitation requests only)\n"
    ]

    # --- Phase Types (always included) ---
    parts.append("""## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Generating payloads, reverse shells, or delivery mechanisms for target user execution
- Setting up handlers, listeners, or delivery servers
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"
  - "Try SQL injection on the web app"
  - "Generate a reverse shell payload"
  - "Create a malicious Word document"
  - "Set up a web delivery attack"
""")

    # --- Attack Skill Types ---
    parts.append("## Attack Skill Types (ONLY for exploitation phase)\n")

    # Built-in skills (only enabled ones)
    for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service']:
        if skill_id in enabled_builtins:
            section_text, _, _ = _BUILTIN_SKILL_MAP[skill_id]
            parts.append(section_text)

    # User skills — use description if available, otherwise first 500 chars of content
    for skill in enabled_user_skills:
        preview = skill.get('description') or skill['content'][:500]
        if not skill.get('description') and len(skill['content']) > 500:
            preview += "..."
        parts.append(f'### user_skill:{skill["id"]}\n'
                     f'- User-defined attack skill: **{skill["name"]}**\n'
                     f'- Skill description:\n{preview}\n')

    # Unclassified (always included)
    parts.append(_UNCLASSIFIED_SECTION)

    # --- User Request ---
    parts.append(f"## User Request\n{objective}\n")

    # --- Classification Instructions ---
    parts.append("## Instructions\nClassify the user's request:\n")
    parts.append("1. First determine the REQUIRED PHASE:\n"
                 '   - Is this a reconnaissance/information gathering request? -> "informational"\n'
                 '   - Is this an active attack/exploitation request? -> "exploitation"\n')

    parts.append("2. If exploitation, determine the ATTACK SKILL TYPE using this priority order:")

    # Build priority list dynamically
    letter = ord('a')
    priority_order = ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service']
    for skill_id in priority_order:
        if skill_id in enabled_builtins:
            instruction = _PRIORITY_INSTRUCTIONS[skill_id].format(letter=chr(letter))
            parts.append(instruction)
            letter += 1

    # User skills classification instructions
    for skill in enabled_user_skills:
        parts.append(f'   {chr(letter)}. **user_skill:{skill["id"]}** ("{skill["name"]}"):\n'
                     f'      - Does the request match the workflow described in the "{skill["name"]}" skill?\n'
                     f'      - If YES → "user_skill:{skill["id"]}"')
        letter += 1

    # Unclassified + default
    parts.append(f"   {chr(letter)}. **<descriptive_term>-unclassified**:\n"
                 "      - Does the request describe a specific attack technique where the attacker directly interacts with a service?\n"
                 '      - If YES → "<descriptive_term>-unclassified"')
    letter += 1
    default_type = "cve_exploit" if "cve_exploit" in enabled_builtins else "<descriptive_term>-unclassified"
    parts.append(f'   {chr(letter)}. Default to "{default_type}" if truly unclear (e.g., vague "hack the target")\n')

    parts.append('3. If informational, set attack_path_type to "cve_exploit" (default, won\'t be used)\n')

    parts.append("4. Extract TARGET HINTS from the request (best-effort, used for graph linking):\n"
                 '   - target_host: IP address or hostname mentioned (e.g., "10.0.0.5", "www.example.com"). null if none found.\n'
                 '   - target_port: port number mentioned (e.g., 8080, 443). null if none found.\n'
                 '   - target_cves: list of CVE IDs mentioned (e.g., ["CVE-2021-41773"]). Empty list if none found.\n')

    # --- Build valid attack_path_type values for JSON schema ---
    valid_types = []
    for skill_id in priority_order:
        if skill_id in enabled_builtins:
            valid_types.append(f'"{skill_id}"')
    for skill in enabled_user_skills:
        valid_types.append(f'"user_skill:{skill["id"]}"')
    valid_types.append('"<descriptive_term>-unclassified"')

    parts.append(f"""Output valid JSON matching this schema:

```json
{{{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": {' | '.join(valid_types)},
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null,
  "target_host": "10.0.0.5" | "www.example.com" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` is only relevant when required_phase is "exploitation"
- For unclassified paths, the term MUST be lowercase snake_case followed by "-unclassified" (e.g., "sql_injection-unclassified")
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
- `target_host`, `target_port`, `target_cves` are best-effort extraction — null/empty if not mentioned""")

    return "\n".join(parts)


# Keep backward-compatible constant for any code that still references it directly
# (uses all skills enabled as default)
ATTACK_PATH_CLASSIFICATION_PROMPT = None  # Use build_classification_prompt() instead
