# Checklist de durcissement sécurité serveur CentOS Stream 10

## 🔍 Services & Ports
- [ ] Audit services en cours (`systemctl list-units --type=service --state=running`)
- [ ] Stopper services non nécessaires
- [ ] Fermer ports inutiles avec firewalld (`firewall-cmd --remove-port=XXXX/tcp`)

## 🔐 SSH
- [ ] Modifier `/etc/ssh/sshd_config`
- [ ] Générer clé SSH pour utilisateurs
- [ ] Tester nouveau port SSH
- [ ] Redémarrer SSH : `systemctl restart sshd`

## 🛡️ Permissions fichiers
- [ ] Corriger world-writable (`chmod o-w`)
- [ ] Vérifier et contrôler fichiers SUID, SGID
- [ ] Protéger `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`

## 👥 Comptes
- [ ] Vérifier comptes shell valides
- [ ] Supprimer ou désactiver comptes obsolètes
- [ ] Limiter comptes de services

## 📓 Journalisation
- [ ] Activer `rsyslog` et vérifier journaux
- [ ] Envisager syslog distant

## 🛡️ SELinux
- [ ] S’assurer que SELinux est en mode enforcing (`getenforce`)
- [ ] Adapter les contextes si nécessaire

## 🔄 Automatisation
- [ ] Déploiement du script d’audit `/usr/local/bin/audit-securite.sh`
- [ ] Planification via `cron`

## 🚀 Finalisation
- [ ] Revue globale avant passage en prod
- [ ] Sauvegarde snapshots serveur
