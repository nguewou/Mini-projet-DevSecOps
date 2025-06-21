🎯 Objectif global :

Ce Mini Projet vise à mettre en pratique les fondamentaux Linux et les bonnes pratiques de sécurité à travers unaudit complet d’un serveur, suivi de son durcissement, l’automatisation de vérifications, et le déploiement d’une application web.

Phase 1 : Reconnaissance de l’environnement

VM locale: KVM, HYPER-V, VMWARE, VIRTUALBOX, etc
VM cloud: AWS, GCP, AZURE, DIGITAL OCEAN, OVH, etc

Notre environnement de test est en local hébergé sur Hyper-V avec un serveur CentOS Stream 10.
1.	Version du noyau Linux : 6.12.0-66.el10.x86_64
2.	Identifier les services de sécurité actifs de notre environnement de travail
3.	Identifier les ports actuellement ouverts

Phase 2 : Recherche de fichiers et analyse de logs

1.	Recherche de tous les fichiers contenant des secrets potentiels Mots-clés à rechercher sans tenir compte de la casse : password, api_key, token, secret_key, .env.
2.	Analyser les logs d’authentification
3.	Lister les fichiers récemment modifiés dans /etc
   
Phase 3: Analyse des permissions sensibles
1.	Identification des groupes à privilèges sur notre système
2.	Les utilisateurs qui ont accès à un shell de connexion

Phase 4: Mini-Projet

1.	Audit initial
2.	Corrections et durcissement
3.	Script d’audit automatisé
4.	Déploiement application web
6.	Documentation
7.	Test application Web
   Presentation des tests
9.	Livrables
   Compte rendu des exercices 1 à 3 (avec commandes utilisées)
   Script Bash documenté (audit.sh)
   Rapport d’audit automatisé généré
   Application fonctionnelle sur port 8080
   Document final de synthèse (PDF ou Markdown)
