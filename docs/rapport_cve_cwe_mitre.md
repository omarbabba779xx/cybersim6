# CyberSim6 - Rapport de Vulnerabilites CVE/CWE + Mapping MITRE ATT&CK

## 1. DDoS (Distributed Denial of Service)

### CVE References
- **CVE-2016-6515** (OpenSSH DoS) : Permet a un attaquant distant de provoquer un deni de service via des mots de passe tres longs lors de l'authentification.
- **CVE-2018-5711** (PHP GD PNG flood) : Exploitation de la bibliotheque GD pour provoquer une consommation excessive de memoire via des images PNG malformees.

### CWE
- **CWE-400** : Uncontrolled Resource Consumption - Le systeme ne limite pas adequatement les ressources allouees aux requetes.
- **CWE-770** : Allocation of Resources Without Limits or Throttling.

### MITRE ATT&CK
- **Tactique** : Impact (TA0040)
- **Technique** : Network Denial of Service (T1498)
  - **Sub-technique** : T1498.001 - Direct Network Flood
- **Technique** : Endpoint Denial of Service (T1499)
  - **Sub-technique** : T1499.002 - Service Exhaustion Flood

### Indicateurs de Compromission (IOC)
- Pic anormal de trafic reseau (>1000 req/s sur un seul endpoint)
- Nombre eleve de connexions SYN semi-ouvertes
- Augmentation de la latence du serveur >500%
- Logs serveur montrant des requetes repetitives depuis une meme source

---

## 2. SQL Injection (SQLi)

### CVE References
- **CVE-2019-6340** (Drupal SQLi) : Injection SQL dans Drupal permettant l'execution de code arbitraire via des requetes REST.
- **CVE-2021-27928** (MariaDB SQLi) : Injection dans les requetes preparees permettant l'execution de commandes.

### CWE
- **CWE-89** : Improper Neutralization of Special Elements used in an SQL Command (SQL Injection).
- **CWE-564** : SQL Injection: Hibernate (variante ORM).

### MITRE ATT&CK
- **Tactique** : Initial Access (TA0001)
- **Technique** : Exploit Public-Facing Application (T1190)
- **Tactique** : Collection (TA0009)
- **Technique** : Data from Information Repositories (T1213)

### Indicateurs de Compromission (IOC)
- Presence de mots-cles SQL dans les parametres HTTP (UNION, SELECT, DROP, --, /*)
- Erreurs SQL exposees dans les reponses HTTP (500 Internal Server Error)
- Requetes avec des caracteres speciaux (%27, %22, %3B)
- Temps de reponse anormalement longs (indicateur de blind SQLi time-based)

---

## 3. Brute Force

### CVE References
- **CVE-2023-46747** (F5 BIG-IP) : Bypass d'authentification permettant des attaques brute force sur l'interface d'administration.
- **CVE-2021-22986** (F5 iControl) : Acces non autorise via des tentatives d'authentification repetees.

### CWE
- **CWE-307** : Improper Restriction of Excessive Authentication Attempts.
- **CWE-521** : Weak Password Requirements.
- **CWE-262** : Not Using Password Aging.

### MITRE ATT&CK
- **Tactique** : Credential Access (TA0006)
- **Technique** : Brute Force (T1110)
  - **Sub-technique** : T1110.001 - Password Guessing
  - **Sub-technique** : T1110.002 - Password Cracking
  - **Sub-technique** : T1110.003 - Password Spraying
  - **Sub-technique** : T1110.004 - Credential Stuffing

### Indicateurs de Compromission (IOC)
- Nombre eleve de tentatives de connexion echouees (>10/min depuis une meme IP)
- Pattern de tentatives avec des mots de passe sequentiels
- Tentatives sur plusieurs comptes depuis la meme source (password spraying)
- Delais reguliers entre les tentatives (automatisation)

---

## 4. Phishing

### CVE References
- **CVE-2023-23397** (Microsoft Outlook) : Elevation de privileges via des rendez-vous Outlook malveillants permettant le vol de hachages NTLM.
- **CVE-2022-30190** (MSDT Follina) : Execution de code via des documents Office avec des liens ms-msdt.

### CWE
- **CWE-1021** : Improper Restriction of Rendered UI Layers or Frames (UI Redressing / Clickjacking).
- **CWE-451** : User Interface (UI) Misrepresentation of Critical Information.

### MITRE ATT&CK
- **Tactique** : Initial Access (TA0001)
- **Technique** : Phishing (T1566)
  - **Sub-technique** : T1566.001 - Spearphishing Attachment
  - **Sub-technique** : T1566.002 - Spearphishing Link
  - **Sub-technique** : T1566.003 - Spearphishing via Service

### Indicateurs de Compromission (IOC)
- Domaine expediteur different du domaine affiche
- URLs avec des domaines suspects ou des adresses IP directes
- Mots-cles d'urgence (action requise, compte suspendu, etc.)
- Fautes d'orthographe et formatage inconsistant
- Liens HTTP (non HTTPS) vers des pages de connexion

---

## 5. XSS (Cross-Site Scripting)

### CVE References
- **CVE-2022-29078** (EJS Template) : XSS dans le moteur de templates EJS permettant l'execution de code arbitraire cote client.
- **CVE-2021-41184** (jQuery UI) : XSS Stored dans jQuery UI via des options d'initialisation non sanitisees.

### CWE
- **CWE-79** : Improper Neutralization of Input During Web Page Generation (Cross-site Scripting).
  - CWE-79.1 : Reflected XSS
  - CWE-79.2 : Stored XSS
- **CWE-80** : Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS).

### MITRE ATT&CK
- **Tactique** : Execution (TA0002)
- **Technique** : User Execution (T1204)
  - **Sub-technique** : T1204.001 - Malicious Link
- **Tactique** : Collection (TA0009)
- **Technique** : Input Capture (T1056)

### Indicateurs de Compromission (IOC)
- Presence de balises HTML/JavaScript dans les parametres HTTP (<script>, <img onerror=)
- Requetes contenant des handlers d'evenements (onload, onerror, onmouseover)
- Tentatives d'acces a document.cookie ou document.location dans les inputs
- Encodages suspects (&#, %3C, base64) dans les parametres

---

## 6. Ransomware

### CVE References
- **CVE-2017-0144** (EternalBlue / WannaCry) : Vulnerabilite SMBv1 exploitee par WannaCry pour la propagation laterale et le chiffrement de fichiers.
- **CVE-2021-34527** (PrintNightmare) : Execution de code a distance via le service Print Spooler, exploitee par plusieurs familles de ransomware.

### CWE
- **CWE-311** : Missing Encryption of Sensitive Data (utilisee inversement - chiffrement malveillant sans consentement).
- **CWE-693** : Protection Mechanism Failure.
- **CWE-284** : Improper Access Control.

### MITRE ATT&CK
- **Tactique** : Impact (TA0040)
- **Technique** : Data Encrypted for Impact (T1486)
- **Tactique** : Execution (TA0002)
- **Technique** : User Execution (T1204)
- **Tactique** : Exfiltration (TA0010)
- **Technique** : Exfiltration Over C2 Channel (T1041) (double extorsion)

### Indicateurs de Compromission (IOC)
- Modification massive d'extensions de fichiers en peu de temps (.locked, .encrypted, .crypt)
- Creation de fichiers "RANSOM_NOTE.txt" ou similaires dans plusieurs repertoires
- Entropie elevee des fichiers (>7.5 bits/octet = contenu chiffre)
- Activite anormale du disque (I/O intensif)
- Tentatives de suppression des shadow copies (vssadmin delete shadows)
- Communications avec des serveurs C2 connus

---

## Resume - Tableau de Mapping

| Attaque | CWE Principal | CVE Reference | MITRE Tactique | MITRE Technique |
|---------|--------------|---------------|----------------|-----------------|
| DDoS | CWE-400 | CVE-2016-6515 | Impact (TA0040) | T1498, T1499 |
| SQLi | CWE-89 | CVE-2019-6340 | Initial Access (TA0001) | T1190 |
| Brute Force | CWE-307 | CVE-2023-46747 | Credential Access (TA0006) | T1110 |
| Phishing | CWE-1021 | CVE-2023-23397 | Initial Access (TA0001) | T1566 |
| XSS | CWE-79 | CVE-2022-29078 | Execution (TA0002) | T1204 |
| Ransomware | CWE-311 | CVE-2017-0144 | Impact (TA0040) | T1486 |

---

*CyberSim6 - EMSI Tanger 4IIR | Projet Academique 2025-2026*
