#sdk 사용시 from trust_soc_llm import TrustSocLLMClient, EvidenceRef

# LLM Advisor API endpoint
client = TrustSocLLMClient("http://localhost:8000")

# ------------------------------------------------------
# Example 1: SSH Brute Force
# ------------------------------------------------------

log_bruteforce = """
Failed password for invalid user admin from 192.168.0.20 port 51223 ssh2
Failed password for invalid user admin from 192.168.0.20 port 51224 ssh2
Failed password for invalid user admin from 192.168.0.20 port 51225 ssh2
"""

e1 = EvidenceRef(
    type="raw",
    ref_id="ssh_log_001",
    source="auth.log",
    offset=0,
    length=len(log_bruteforce),
    sha256="aabbccddeeff00112233"
)

resp1 = client.analyze(
    event_text=log_bruteforce,
    evidences=[e1]
)

print("\n=== SSH Brute Force Example ===")
print("Incident ID:", resp1.incident_id)
print("Summary:", resp1.summary)
print("Mapping:", resp1.attack_mapping)
print("Actions:", resp1.recommended_actions)
print("Confidence:", resp1.confidence)
print("Next:", resp1.next_action)


# ------------------------------------------------------
# Example 2: Webshell detection
# ------------------------------------------------------

log_webshell = """
POST /upload.php?cmd=whoami
Suspicious PHP execution: cmd.exe /c powershell ...
"""

e2 = EvidenceRef(
    type="raw",
    ref_id="webshell_01",
    source="nginx_access.log",
    offset=120,
    length=80,
    sha256="ffeeddccbbaa99887766"
)

resp2 = client.analyze(
    event_text=log_webshell,
    evidences=[e2]
)

print("\n=== Webshell Example ===")
print("Incident ID:", resp2.incident_id)
print("Summary:", resp2.summary)
print("Mapping:", resp2.attack_mapping)
print("Actions:", resp2.recommended_actions)


# ------------------------------------------------------
# Example 3: Scheduled task creation
# ------------------------------------------------------

log_task = """
User created a new scheduled task: schtasks.exe /create /tn UpdateCheck /tr C:\\malware.exe /sc minute /mo 5
"""

e3 = EvidenceRef(
    type="raw",
    ref_id="schtask_001",
    source="system.log",
    offset=300,
    length=len(log_task),
    sha256="123456abcdef"
)

resp3 = client.analyze(
    event_text=log_task,
    evidences=[e3]
)

print("\n=== Scheduled Task Example ===")
print("Incident ID:", resp3.incident_id)
print("Summary:", resp3.summary)
print("Mapping:", resp3.attack_mapping)
print("Actions:", resp3.recommended_actions)
