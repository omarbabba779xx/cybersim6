# Contribuer a CyberSim6

Merci de votre interet pour contribuer a CyberSim6 !

## Regles de securite

**IMPORTANT** : CyberSim6 est un outil educatif. Toute contribution doit respecter :

1. **Loopback uniquement** : Toute attaque doit cibler exclusivement `127.0.0.1` / `localhost`
2. **Sandbox obligatoire** : Le fichier `.cybersim_sandbox` doit etre present dans tout repertoire cible
3. **Non-destructif** : Les fichiers originaux doivent etre conserves par defaut
4. **Pas de donnees reelles** : Aucun email, mot de passe ou donnee reelle

## Comment contribuer

### 1. Preparer l'environnement

```bash
git clone https://github.com/votre-username/cybersim6.git
cd cybersim6
pip install -e ".[dev]"
python -m cybersim sandbox setup
```

### 2. Creer une branche

```bash
git checkout -b feature/nom-de-la-feature
```

### 3. Developper

- Suivre le pattern `BaseModule` pour les nouveaux modules
- Ajouter des tests dans `tests/`
- Documenter les CVE/CWE et MITRE ATT&CK pertinents

### 4. Tester

```bash
python -m pytest tests/ -v
```

### 5. Soumettre un Pull Request

- Description claire des changements
- Tests inclus
- Documentation mise a jour

## Structure d'un nouveau module

```python
from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_target_ip

class MonAttaque(BaseModule):
    MODULE_TYPE = "attack"
    MODULE_NAME = "mon_module"

    def _validate_safety(self):
        validate_target_ip(self.config.get("target", "127.0.0.1"))

    def run(self, **kwargs):
        self.log_event("attack_started", {"message": "...", "status": "warning"})
        # ... logique d'attaque ...
        self.log_event("attack_completed", {"message": "...", "status": "info"})

    def stop(self):
        self._running = False
```

## Convention de code

- Python 3.10+
- Docstrings en anglais
- Commentaires en francais ou anglais
- Noms de variables descriptifs
- Type hints encourages
