# CyberSim6 - Fiches Contre-Mesures
## 6 fiches : Detection, Mitigation, Recuperation

---

## 1. DDoS - Contre-Mesures

### Detection
| Methode | Outil/Script | Seuil |
|---------|-------------|-------|
| Rate monitoring | `cybersim ddos detect` | >50 req/s |
| SYN packet analysis | Wireshark filter: `tcp.flags.syn==1 && tcp.flags.ack==0` | >100 SYN/s |
| HTTP access log analysis | `tail -f access.log \| awk '{print $1}' \| sort \| uniq -c` | >100 req/IP/min |
| Connexions semi-ouvertes | `netstat -an \| grep SYN_RECV \| wc -l` | >50 |

### Mitigation
```bash
# SYN cookies (Linux)
sysctl -w net.ipv4.tcp_syncookies=1

# Rate limiting iptables
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j DROP
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT

# Bloquer une IP source
iptables -A INPUT -s <ATTACKER_IP> -j DROP
```

### Recuperation
1. Verifier que le trafic est revenu a la normale
2. Supprimer les regles temporaires si necessaire
3. Mettre en place des regles permanentes de rate limiting
4. Documenter l'incident et les IPs sources

---

## 2. SQL Injection - Contre-Mesures

### Detection
| Methode | Implementation |
|---------|---------------|
| Pattern matching | `cybersim sqli detect` - Analyse regex des requetes SQL |
| WAF rules | ModSecurity CRS Rule 942100 (SQL Injection) |
| Error monitoring | Alerter sur les HTTP 500 avec messages SQL |
| Query audit | Activer le query log MySQL/PostgreSQL |

### Mitigation
```python
# AVANT (vulnerable)
sql = f"SELECT * FROM users WHERE username='{username}'"

# APRES (securise - prepared statement)
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# Avec ORM (SQLAlchemy)
user = session.query(User).filter_by(username=username).first()
```

```python
# Validation d'entree
import re
def validate_input(user_input):
    if re.search(r"['\";\\-]", user_input):
        raise ValueError("Caracteres non autorises")
    return user_input
```

### Recuperation
1. Identifier les donnees exfiltrees via les logs
2. Restaurer la base de donnees si des modifications ont ete faites
3. Forcer le changement de mots de passe si des credentials ont ete exposees
4. Patcher toutes les requetes vulnerables

---

## 3. Brute Force - Contre-Mesures

### Detection
| Methode | Implementation | Seuil |
|---------|---------------|-------|
| Failed login counter | `cybersim bruteforce detect` | >5 echecs/60s |
| Geographic analysis | Detecter les connexions depuis des pays inhabituels | N/A |
| Timing analysis | Detecter les delais reguliers entre tentatives | <100ms entre essais |
| Account enumeration | Meme reponse pour user inexistant et mauvais password | N/A |

### Mitigation
```python
# Lockout progressif
LOCKOUT_POLICY = {
    5: 60,      # 5 echecs -> lockout 1 min
    10: 300,    # 10 echecs -> lockout 5 min
    20: 3600,   # 20 echecs -> lockout 1h
}

# CAPTCHA apres N echecs
if failed_attempts >= 3:
    require_captcha()

# Rate limiting par IP
from functools import lru_cache
import time
```

```bash
# fail2ban configuration
# /etc/fail2ban/jail.local
[http-auth]
enabled = true
maxretry = 5
bantime = 600
findtime = 60
```

### Recuperation
1. Deverrouiller les comptes apres reinitialisation du mot de passe
2. Activer MFA sur les comptes cibles
3. Analyser les logs pour detecter des acces non autorises
4. Mettre a jour la politique de mots de passe

---

## 4. Phishing - Contre-Mesures

### Detection
| Methode | Implementation |
|---------|---------------|
| Email header analysis | `cybersim phishing detect` - Score de risque |
| SPF/DKIM/DMARC check | Verifier l'authentification de l'expediteur |
| URL reputation | VirusTotal, Google Safe Browsing |
| Urgency keyword scan | Detecter les mots-cles de pression |

### Mitigation
```
# Configuration DNS anti-spoofing
# SPF Record
v=spf1 include:_spf.google.com ~all

# DMARC Policy
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

# DKIM
Configurer la signature DKIM sur le serveur mail
```

```python
# Analyse programmatique d'un email suspect
from cybersim.phishing.detection import PhishingDetector
detector = PhishingDetector(config={}, logger=logger)
result = detector.analyze_email(
    subject="URGENT: Verify your account",
    body="Click http://192.168.1.1/login to verify",
    sender="support@susp1cious.tk",
    url="http://192.168.1.1/login"
)
# result = {"risk_level": "HIGH", "risk_score": 95, ...}
```

### Recuperation
1. Purger l'email de toutes les boites aux lettres
2. Reinitialiser les credentials des utilisateurs victimes
3. Bloquer le domaine de phishing au niveau DNS
4. Envoyer un avertissement a tous les utilisateurs

---

## 5. XSS - Contre-Mesures

### Detection
| Methode | Implementation |
|---------|---------------|
| Input pattern matching | `cybersim xss detect` - Analyse regex |
| CSP violation reports | Content-Security-Policy-Report-Only header |
| WAF rules | ModSecurity CRS Rule 941100 (XSS) |
| Output encoding check | Audit du code pour les outputs non echappes |

### Mitigation
```python
# Echappement HTML (Python)
import html
safe_output = html.escape(user_input, quote=True)
# <script> devient &lt;script&gt;

# Framework template (Jinja2 - auto-escape)
# {{ user_input }} est automatiquement echappe dans Jinja2
```

```
# Content Security Policy header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'

# Autres en-tetes de securite
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

# Cookie protection
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

### Recuperation
1. Supprimer le contenu XSS stocke de la base de donnees
2. Invalider toutes les sessions actives
3. Deployer les correctifs (echappement + CSP)
4. Scanner l'ensemble de l'application pour d'autres failles

---

## 6. Ransomware - Contre-Mesures

### Detection
| Methode | Implementation |
|---------|---------------|
| File extension monitoring | `cybersim ransomware scan` |
| Entropy analysis | Fichiers avec entropie >7.5 = probablement chiffres |
| Canary files | Fichiers pieges dans les repertoires sensibles |
| Process monitoring | Detecter les processus chiffrant massivement |
| Shadow copy deletion | Surveiller les appels a vssadmin |

### Mitigation
```bash
# Sauvegardes automatisees (regle 3-2-1)
# 3 copies, 2 supports, 1 hors-site

# Backup quotidien avec rsync
rsync -avz --delete /data/ /backup/daily/
rsync -avz --delete /data/ user@remote:/backup/offsite/

# Snapshot ZFS (immutable)
zfs snapshot tank/data@$(date +%Y%m%d)

# Windows: activer les shadow copies
vssadmin create shadow /for=C:
```

```python
# Detection programmatique
from cybersim.ransomware.detection import RansomwareDetector, calculate_entropy

# Verifier l'entropie d'un fichier
with open("suspect_file", "rb") as f:
    entropy = calculate_entropy(f.read())
    if entropy > 7.5:
        print("ALERTE: Fichier probablement chiffre!")
```

### Recuperation
1. **Isoler** immediatement le systeme infecte
2. **Identifier** la souche de ransomware (ID Ransomware)
3. **Verifier** la disponibilite d'un dechiffreur gratuit (NoMoreRansom.org)
4. **Restaurer** depuis les sauvegardes (verifier leur integrite d'abord)
5. **Reinstaller** les systemes compromis a partir d'images propres
6. **Documenter** et signaler l'incident aux autorites

---

*CyberSim6 - EMSI Tanger 4IIR | Projet Academique 2025-2026*
