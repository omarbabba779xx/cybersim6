# CyberSim6 - Plan de Reponse aux Incidents (IRP)
## 6 Scenarios d'attaque

**Objectif** : Pour chaque type d'attaque, definir les etapes de reponse structurees selon le framework NIST SP 800-61 :
Detection initiale > Triage > Confinement > Eradication > Recuperation > RETEX

**KPI** : Temps de reponse simule <= 15 minutes par scenario

---

## Scenario 1 : DDoS (Distributed Denial of Service)

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : Monitoring reseau detecte un taux de requetes >50 req/s (seuil configurable)
- **Outil** : `python -m cybersim ddos detect` / Wireshark / netstat
- **Indicateurs** : Latence >500ms, CPU serveur >90%, connexions SYN semi-ouvertes en hausse
- **Severite** : HAUTE - Impact direct sur la disponibilite

### Phase 2 - Triage (2-4 min)
- Identifier le type de flood (SYN Flood vs HTTP Flood)
- Analyser les logs unifies pour determiner le volume et la source
- Verifier si l'attaque est distribuee (multiple IPs) ou concentree
- Classification : Incident de disponibilite

### Phase 3 - Confinement (4-8 min)
- Activer le rate limiting sur le pare-feu (iptables/Windows Firewall)
- Bloquer les IPs source identifiees : `iptables -A INPUT -s <IP> -j DROP`
- Activer les SYN cookies : `sysctl -w net.ipv4.tcp_syncookies=1`
- Rediriger le trafic via un service anti-DDoS si disponible
- Limiter les connexions simultanees par IP

### Phase 4 - Eradication (8-11 min)
- Analyser les logs pour identifier toutes les IPs impliquees
- Mettre a jour les regles de pare-feu avec la liste complete
- Verifier qu'aucun agent DDoS (botnet) n'est installe sur le reseau interne
- Documenter les vecteurs d'attaque utilises

### Phase 5 - Recuperation (11-14 min)
- Verifier que le trafic est revenu a la normale
- Restaurer les services affectes
- Surveiller pendant 30 minutes supplementaires pour detecter une recidive
- Valider les KPIs de performance (latence, disponibilite)

### Phase 6 - RETEX (Post-incident)
- Documenter la chronologie complete de l'incident
- Evaluer l'efficacite de la detection (temps de detection)
- Recommandations : mise en place d'un CDN, augmentation de la capacite, regles de rate limiting permanentes
- Mise a jour du plan IRP si necessaire

---

## Scenario 2 : SQL Injection

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : WAF ou analyseur de logs detecte des patterns SQLi dans les requetes
- **Outil** : `python -m cybersim sqli detect` / ModSecurity / analyseur de logs
- **Indicateurs** : Mots-cles SQL dans les parametres HTTP (UNION, SELECT, --, /*)
- **Severite** : CRITIQUE - Risque de fuite de donnees

### Phase 2 - Triage (2-4 min)
- Identifier les endpoints vulnerables exploites
- Determiner le type d'injection (Union, Error-based, Blind)
- Evaluer si des donnees ont ete exfiltrees (verifier les tailles de reponse anormales)
- Classification : Incident de confidentialite + integrite

### Phase 3 - Confinement (4-8 min)
- Bloquer l'IP source de l'attaque
- Desactiver temporairement les endpoints vulnerables
- Activer le mode maintenance sur l'application web
- Revoquer les sessions actives potentiellement compromises

### Phase 4 - Eradication (8-11 min)
- Corriger les requetes SQL vulnerables (parametrisation / prepared statements)
- Mettre a jour les regles WAF pour bloquer les patterns identifies
- Verifier l'integrite de la base de donnees (pas de modifications non autorisees)
- Scanner l'ensemble du code pour d'autres vulnerabilites SQLi

### Phase 5 - Recuperation (11-14 min)
- Restaurer la base de donnees depuis une sauvegarde si compromission confirmee
- Reactiver les endpoints corriges
- Forcer la reinitialisation des mots de passe si des credentials ont ete exposees
- Valider le fonctionnement normal de l'application

### Phase 6 - RETEX
- Documenter les failles exploitees et les CVE/CWE correspondantes
- Audit de code complet recommande
- Formation developpeurs sur les bonnes pratiques (ORM, prepared statements)
- Mise en place de tests de securite automatises (SAST/DAST)

---

## Scenario 3 : Brute Force

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : Systeme detecte >5 echecs de connexion en 60 secondes depuis la meme IP
- **Outil** : `python -m cybersim bruteforce detect` / fail2ban / SIEM
- **Indicateurs** : Tentatives de connexion repetees, patterns de mots de passe sequentiels
- **Severite** : HAUTE - Risque d'acces non autorise

### Phase 2 - Triage (2-4 min)
- Identifier les comptes cibles (un seul compte vs password spraying)
- Verifier si des comptes ont ete compromis (connexion reussie apres echecs)
- Analyser la source (IP unique, proxy, VPN, Tor)
- Classification : Incident d'authentification

### Phase 3 - Confinement (4-7 min)
- Verrouiller les comptes cibles temporairement
- Bloquer l'IP source (pare-feu + application)
- Activer le lockout automatique (10 echecs = verrouillage 15 min)
- Activer le CAPTCHA sur les formulaires de connexion

### Phase 4 - Eradication (7-10 min)
- Forcer la reinitialisation des mots de passe des comptes cibles
- Verifier les logs pour detecter des connexions reussies non autorisees
- Implementer des regles fail2ban permanentes
- Verifier que MFA est active sur tous les comptes critiques

### Phase 5 - Recuperation (10-13 min)
- Deverrouiller les comptes apres reinitialisation
- Notifier les utilisateurs concernes du changement de mot de passe
- Surveiller les comptes cibles pendant 24h
- Valider que les mesures de protection sont actives

### Phase 6 - RETEX
- Evaluer la politique de mots de passe (longueur, complexite)
- Recommandations : MFA obligatoire, politique de lockout, password managers
- Mise en place de monitoring d'authentification en temps reel

---

## Scenario 4 : Phishing

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : Signalement utilisateur ou filtre anti-spam detecte un email suspect
- **Outil** : `python -m cybersim phishing detect` / analyseur d'en-tetes email
- **Indicateurs** : Domaine expediteur suspect, liens HTTP, mots-cles d'urgence
- **Severite** : CRITIQUE si des credentials ont ete soumises

### Phase 2 - Triage (2-4 min)
- Analyser l'email (en-tetes, liens, pieces jointes)
- Determiner le nombre de destinataires dans l'organisation
- Verifier si des utilisateurs ont clique sur les liens
- Verifier si des credentials ont ete soumises au site de phishing

### Phase 3 - Confinement (4-8 min)
- Bloquer le domaine de phishing au niveau DNS et pare-feu
- Supprimer l'email de toutes les boites aux lettres (mail purge)
- Si credentials compromises : desactiver les comptes immediatement
- Bloquer les connexions depuis les IPs du serveur de phishing

### Phase 4 - Eradication (8-11 min)
- Reinitialiser les mots de passe des utilisateurs ayant clique
- Revoquer les tokens de session actifs
- Verifier qu'aucun malware n'a ete installe via le site de phishing
- Signaler le domaine de phishing (abuse report)

### Phase 5 - Recuperation (11-14 min)
- Restaurer l'acces pour les utilisateurs affectes
- Activer MFA sur les comptes compromis
- Envoyer une notification interne d'alerte phishing
- Surveiller les comptes compromis pendant 7 jours

### Phase 6 - RETEX
- Evaluer le taux de clic (nombre de victimes vs destinataires)
- Organiser une session de sensibilisation ciblee
- Ameliorer les filtres anti-spam avec les nouveaux indicateurs
- Planifier des exercices de phishing periodiques

---

## Scenario 5 : XSS (Cross-Site Scripting)

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : WAF detecte des balises HTML/JS dans les parametres HTTP
- **Outil** : `python -m cybersim xss detect` / WAF / CSP violation reports
- **Indicateurs** : Tags <script>, handlers d'evenements (onerror, onload), document.cookie
- **Severite** : HAUTE - Risque de vol de session et d'exfiltration de donnees

### Phase 2 - Triage (2-4 min)
- Identifier le type de XSS (Reflected, Stored, DOM-based)
- Pour Stored XSS : identifier le contenu malveillant stocke en base
- Evaluer l'impact : sessions volees ? donnees exfiltrees ? defacement ?
- Classification : Incident d'integrite + confidentialite

### Phase 3 - Confinement (4-7 min)
- Stored XSS : supprimer/sanitiser le contenu malveillant de la base de donnees
- Reflected XSS : desactiver temporairement le parametre/endpoint vulnerable
- Invalider toutes les sessions actives (rotation des tokens)
- Activer une Content Security Policy (CSP) restrictive

### Phase 4 - Eradication (7-10 min)
- Implementer l'echappement HTML sur tous les outputs (html.escape())
- Ajouter des en-tetes de securite : Content-Security-Policy, X-XSS-Protection
- Valider et sanitiser tous les inputs cote serveur
- Deployer les correctifs sur tous les endpoints identifies

### Phase 5 - Recuperation (10-13 min)
- Reactiver les endpoints corriges
- Forcer la re-connexion de tous les utilisateurs
- Verifier que le contenu malveillant Stored XSS a bien ete supprime
- Tester les correctifs avec les payloads identifies

### Phase 6 - RETEX
- Audit complet des points d'injection XSS dans l'application
- Implementation d'une CSP stricte sur l'ensemble du site
- Formation developpeurs sur les bonnes pratiques XSS prevention
- Integration de tests XSS automatises dans le pipeline CI/CD

---

## Scenario 6 : Ransomware

### Phase 1 - Detection initiale (0-2 min)
- **Alerte** : Monitoring filesystem detecte des modifications massives d'extensions
- **Outil** : `python -m cybersim ransomware scan` / EDR / monitoring I/O
- **Indicateurs** : Extensions .locked/.encrypted, fichiers RANSOM_NOTE, entropie >7.5
- **Severite** : CRITIQUE - Impact maximal sur les donnees et les operations

### Phase 2 - Triage (2-3 min)
- Identifier les systemes affectes et l'etendue du chiffrement
- Determiner la souche de ransomware (signature, note de rancon)
- Evaluer si la propagation est en cours (mouvement lateral)
- Classification : Incident d'integrite + disponibilite | Priorite MAXIMALE

### Phase 3 - Confinement (3-6 min)
- **IMMEDIAT** : Isoler les systemes infectes du reseau (cable + WiFi)
- Desactiver les partages reseau pour stopper la propagation
- Bloquer les communications C2 connues au pare-feu
- Preserver les preuves (ne pas eteindre - dumper la RAM si possible)
- Activer le plan de continuite d'activite (BCP)

### Phase 4 - Eradication (6-10 min)
- Identifier le vecteur d'infection initial (email, RDP, vulnerabilite)
- Supprimer le malware de tous les systemes affectes
- Verifier l'absence de persistence (registre, taches planifiees, services)
- Patcher la vulnerabilite exploitee pour l'acces initial
- Scanner l'ensemble du reseau pour detecter d'autres infections

### Phase 5 - Recuperation (10-14 min)
- Restaurer les fichiers depuis les sauvegardes (verifier qu'elles ne sont pas chiffrees)
- Si pas de sauvegarde : tenter un dechiffrement avec des outils publics (NoMoreRansom.org)
- Reinstaller les systemes compromis a partir d'images propres
- Restaurer les services par ordre de priorite business
- **NE PAS PAYER LA RANCON** - Pas de garantie de dechiffrement

### Phase 6 - RETEX
- Analyse forensique complete (timeline, vecteur d'infection, TTPs)
- Evaluation de la politique de sauvegarde (regle 3-2-1)
- Renforcement : segmentation reseau, EDR, MFA sur RDP
- Exercice de restauration periodique des sauvegardes
- Signalement aux autorites (ANSSI, CNIL si donnees personnelles)

---

## Resume des Temps de Reponse

| Scenario | Detection | Triage | Confinement | Eradication | Recuperation | Total |
|----------|-----------|--------|-------------|-------------|--------------|-------|
| DDoS | 2 min | 2 min | 4 min | 3 min | 3 min | **14 min** |
| SQLi | 2 min | 2 min | 4 min | 3 min | 3 min | **14 min** |
| Brute Force | 2 min | 2 min | 3 min | 3 min | 3 min | **13 min** |
| Phishing | 2 min | 2 min | 4 min | 3 min | 3 min | **14 min** |
| XSS | 2 min | 2 min | 3 min | 3 min | 3 min | **13 min** |
| Ransomware | 2 min | 1 min | 3 min | 4 min | 4 min | **14 min** |

**Tous les scenarios respectent le KPI de 15 minutes.**

---

*CyberSim6 - EMSI Tanger 4IIR | Projet Academique 2025-2026*
