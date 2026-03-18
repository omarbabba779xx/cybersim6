# CyberSim6 - Guide de Sensibilisation a la Cybersecurite
## 6 Attaques, IOCs et Bonnes Pratiques de Defense

---

## Introduction

Ce guide est produit dans le cadre du projet CyberSim6 (EMSI Tanger, 4IIR). Il couvre les 6 types d'attaques simulees dans la plateforme et fournit pour chacune :
- Une description accessible de l'attaque
- Les indicateurs de compromission (IOC) a surveiller
- Les techniques, tactiques et procedures (TTP) utilisees
- Les bonnes pratiques de defense

---

## 1. DDoS - Deni de Service Distribue

### Qu'est-ce que c'est ?
Une attaque DDoS vise a rendre un service indisponible en le submergeant de requetes. Le serveur, incapable de traiter le volume de trafic, devient inaccessible aux utilisateurs legitimes.

### Types simules dans CyberSim6
- **SYN Flood** : Envoi massif de paquets TCP SYN sans completer le handshake
- **HTTP Flood** : Envoi massif de requetes HTTP GET/POST

### IOC - Comment detecter ?
- Latence du site web anormalement elevee
- Serveur qui repond par des erreurs 503 (Service Unavailable)
- Consommation CPU/memoire a 100% sans raison apparente
- Trafic reseau 10x superieur a la normale
- Nombreuses connexions semi-ouvertes dans netstat

### Bonnes pratiques de defense
1. **Rate limiting** : Limiter le nombre de requetes par IP par minute
2. **SYN cookies** : Activer les SYN cookies pour mitiger les SYN floods
3. **CDN/WAF** : Utiliser un CDN (Cloudflare, AWS Shield) pour absorber le trafic
4. **Monitoring** : Surveiller en temps reel les metriques reseau et serveur
5. **Plan de capacite** : Dimensionner l'infrastructure pour supporter des pics
6. **Listes noires** : Maintenir des listes d'IPs malveillantes connues

---

## 2. SQL Injection

### Qu'est-ce que c'est ?
L'injection SQL permet a un attaquant d'inserer du code SQL malveillant dans les champs de saisie d'une application web. Si l'application ne valide pas correctement les entrees, l'attaquant peut lire, modifier ou supprimer des donnees dans la base.

### Types simules dans CyberSim6
- **Auth Bypass** : Contournement de l'authentification (ex: `' OR '1'='1' --`)
- **UNION-based** : Extraction de donnees via des requetes UNION
- **Error-based** : Exploitation des messages d'erreur pour obtenir des informations
- **Blind Boolean** : Inference d'informations via des reponses true/false

### IOC - Comment detecter ?
- Mots-cles SQL dans les URLs ou formulaires (UNION, SELECT, DROP, --)
- Erreurs SQL exposees dans les pages web (messages d'erreur detailles)
- Requetes avec des caracteres speciaux inhabituels (' " ; -- /*)
- Acces a des donnees sensibles non autorisees

### Bonnes pratiques de defense
1. **Prepared Statements** : Toujours utiliser des requetes parametrees
2. **ORM** : Utiliser un ORM (SQLAlchemy, Hibernate) plutot que du SQL brut
3. **Validation des entrees** : Valider le type, la longueur et le format de chaque input
4. **Principe du moindre privilege** : Le compte DB de l'application ne doit avoir que les droits necessaires
5. **WAF** : Deployer un Web Application Firewall avec des regles anti-SQLi
6. **Pas d'erreurs en production** : Ne jamais afficher les erreurs SQL a l'utilisateur

---

## 3. Brute Force

### Qu'est-ce que c'est ?
L'attaque par force brute consiste a essayer systematiquement des combinaisons de mots de passe jusqu'a trouver le bon. L'attaque par dictionnaire est une variante qui utilise une liste de mots de passe courants.

### Types simules dans CyberSim6
- **Attaque par dictionnaire** : Test de mots de passe courants depuis une wordlist
- **Detection** : Monitoring des tentatives echouees et verrouillage

### IOC - Comment detecter ?
- >5 tentatives de connexion echouees en 1 minute depuis la meme IP
- Tentatives avec des mots de passe differents sur le meme compte
- Tentatives sur plusieurs comptes depuis la meme source (password spraying)
- Connexions a des heures inhabituelles (nuit, weekend)

### Bonnes pratiques de defense
1. **Mots de passe forts** : Minimum 12 caracteres, mixte (majuscules, chiffres, speciaux)
2. **MFA (Multi-Factor Authentication)** : Ajouter un second facteur (SMS, TOTP, cle physique)
3. **Verrouillage de compte** : Bloquer apres N tentatives echouees
4. **CAPTCHA** : Ajouter un CAPTCHA apres 3 echecs
5. **fail2ban** : Bloquer automatiquement les IPs apres des echecs repetes
6. **Gestionnaire de mots de passe** : Utiliser un outil comme KeePass ou Bitwarden

---

## 4. Phishing

### Qu'est-ce que c'est ?
Le phishing est une technique d'ingenierie sociale ou l'attaquant se fait passer pour une entite de confiance (banque, employeur, service IT) pour inciter la victime a divulguer ses informations sensibles (identifiants, numeros de carte).

### Types simules dans CyberSim6
- **Page de connexion corporative factice**
- **Fausse alerte de reinitialisation de mot de passe**
- **Imitation de page Office 365**

### IOC - Comment detecter ?
- L'adresse email de l'expediteur ne correspond pas au domaine officiel
- Le lien pointe vers une URL differente du site officiel (survoler avant de cliquer !)
- Ton urgent ou menacant ("Votre compte sera suspendu dans 24h")
- Fautes d'orthographe ou mise en forme inhabituelle
- Demande de credentials via un lien email
- Pas de HTTPS sur la page de connexion

### Bonnes pratiques de defense
1. **Verifier l'URL** : Toujours verifier le domaine avant de saisir des credentials
2. **Ne jamais cliquer** sur des liens dans les emails suspects
3. **Signaler** les emails suspects a l'equipe IT
4. **MFA** : Meme si les credentials sont volees, le 2e facteur protege
5. **Formation** : Exercices de phishing reguliers pour sensibiliser les employes
6. **Filtres anti-spam** : Configurer des filtres email avec SPF, DKIM, DMARC

---

## 5. XSS (Cross-Site Scripting)

### Qu'est-ce que c'est ?
Le XSS permet a un attaquant d'injecter du code JavaScript malveillant dans une page web consultee par d'autres utilisateurs. Ce code peut voler des cookies de session, rediriger vers des sites malveillants, ou modifier le contenu de la page.

### Types simules dans CyberSim6
- **Reflected XSS** : Le script est injecte via un parametre URL et reflete dans la reponse
- **Stored XSS** : Le script est stocke en base de donnees (ex: commentaire) et execute a chaque consultation
- **DOM-based XSS** : Le script s'execute cote client via manipulation du DOM

### IOC - Comment detecter ?
- Balises HTML ou JavaScript dans les champs de saisie (<script>, <img onerror=)
- URLs contenant du code JavaScript encode
- Comportement inattendu de la page (redirections, popups)
- Acces a document.cookie dans les requetes

### Bonnes pratiques de defense
1. **Echappement des sorties** : Toujours echapper le HTML avant l'affichage (html.escape())
2. **Content Security Policy (CSP)** : Restreindre les sources de scripts autorisees
3. **Validation des entrees** : Nettoyer toutes les entrees utilisateur cote serveur
4. **HttpOnly cookies** : Empecher JavaScript d'acceder aux cookies de session
5. **SameSite cookies** : Proteger contre les requetes cross-site
6. **En-tetes de securite** : X-Content-Type-Options, X-XSS-Protection

---

## 6. Ransomware

### Qu'est-ce que c'est ?
Le ransomware est un logiciel malveillant qui chiffre les fichiers de la victime et exige une rancon pour fournir la cle de dechiffrement. C'est l'une des menaces les plus couteuses pour les organisations.

### Type simule dans CyberSim6
- **Chiffrement AES-256** de fichiers fictifs en sandbox
- **Note de rancon** simulee
- **Outil de dechiffrement** pour la recuperation

### IOC - Comment detecter ?
- Fichiers avec des extensions inhabituelle (.locked, .encrypted, .crypt)
- Fichiers "RANSOM_NOTE.txt" apparaissant dans les repertoires
- Activite disque anormalement elevee
- Processus inconnus consommant beaucoup de CPU
- Fichiers qui ne s'ouvrent plus (contenu chiffre = haute entropie)
- Tentatives de suppression des sauvegardes/shadow copies

### Bonnes pratiques de defense
1. **Sauvegardes 3-2-1** : 3 copies, 2 supports differents, 1 hors-site
2. **Tester les restaurations** : Verifier regulierement que les sauvegardes fonctionnent
3. **Mises a jour** : Patcher tous les systemes et logiciels regulierement
4. **Segmentation reseau** : Limiter la propagation laterale
5. **EDR/Antivirus** : Solutions de detection comportementale
6. **Principe du moindre privilege** : Limiter les droits d'ecriture aux besoins reels
7. **NE JAMAIS PAYER** : Aucune garantie de recuperation, finance le crime organise
8. **Formation** : Apprendre a reconnaitre les emails et liens malveillants

---

## Regles d'Or de la Cybersecurite

1. **Mettre a jour** tous les logiciels et systemes d'exploitation
2. **Utiliser le MFA** sur tous les comptes importants
3. **Sauvegarder** regulierement et tester les restaurations
4. **Verifier avant de cliquer** sur un lien ou ouvrir une piece jointe
5. **Utiliser des mots de passe forts** et un gestionnaire de mots de passe
6. **Signaler** tout email ou comportement suspect a l'equipe IT
7. **Chiffrer** les donnees sensibles au repos et en transit
8. **Former** regulierement les utilisateurs aux menaces actuelles

---

## Ressources Utiles

- **MITRE ATT&CK** : https://attack.mitre.org/
- **OWASP Top 10** : https://owasp.org/www-project-top-ten/
- **ANSSI** : https://www.ssi.gouv.fr/
- **NoMoreRansom** : https://www.nomoreransom.org/
- **Have I Been Pwned** : https://haveibeenpwned.com/
- **NVD (National Vulnerability Database)** : https://nvd.nist.gov/

---

*CyberSim6 - EMSI Tanger 4IIR | Projet Academique 2025-2026*
*Redige par l'equipe projet sous la supervision de Pr. Mariem Bouri*
