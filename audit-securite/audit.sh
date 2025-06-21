#!/bin/bash


# Variables Couleurs
JAUNE="\033[1;33m"
VERT="\033[1;32m"
ROUGE="\033[1;31m"
NEUTRE="\033[0m"
# Autres variables
SSH_CONFIG="/etc/ssh/sshd_config"
DATE=$(date +"%Y%m%d")
REPORT_FILE="/var/log/audit-${DATE}.log"

# Fonction d'affichage coloré
print_color() {
    echo -e "${1}${2}${NEUTRE}"
}

# --- Fonction du minuteur (Temps d exécution du script d'audit) ---
# Cette fonction est exécutée en arrière-plan
timer_function() {
    SECONDS=0 # Initialise le compteur de secondes

    # Boucle infinie qui se terminera lorsque le script principal se terminera
    while true; do
        # Calcule les minutes et les secondes
        MINUTES=$((SECONDS / 60))
        REMAINDER_SECONDS=$((SECONDS % 60))

        # Affiche le minuteur, en revenant au début de la ligne (\r)
        # et en remplissant l'espace restant (\033[K) pour effacer les anciens caractères
        printf "\rTemps écoulé : %02d:%02d" "$MINUTES" "$REMAINDER_SECONDS"
        sleep 1 # Attend 1 seconde
        SECONDS=$((SECONDS + 1)) # Incrémente le compteur
    done
}

# --- Début du script principal ---
# --- Vérification des privilèges ---
if [ "$EUID" -ne 0 ]; then
  print_color "$JAUNE" "Ce script doit être exécuté avec les privilèges root (sudo)."
  print_color "$JAUNE" "Exemple : sudo $0"
  exit 1
fi


# 1. Lance le minuteur en arrière-plan
# Le & à la fin met la fonction en arrière-plan
# Le disown la détache du shell courant pour qu'elle continue même si le script parent est interrompu inopinément
timer_function &
TIMER_PID=$! # Capture le PID du processus du minuteur

#Message afficher durant l'exécution du script

print_color "$JAUNE" "============================================================================================="
print_color "$JAUNE" "=-------------------------------------------------------------------------------------------="
print_color "$JAUNE" "=Script d'audit de securité des services,des utilisateurs à risque, les permission sensibles="
print_color "$JAUNE" "=-------------------------------------------------------------------------------------------="
print_color "$JAUNE" "============================================================================================="

# === Création du rapport ===
print_color "$NEUTRE" "Créeation du rapport dans /etc/log/"
echo "========== AUDIT DE SÉCURITÉ DU $(hostname) en date du $(date) ==========" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
print_color "$VERT" "Le fichier rapport crée"

# === 0. Detection des ports ouverts ===
print_color "$JAUNE" " === 0. Détection des ports ouverts ==="
echo ">>> PORTS OUVERTS <<<" >> "$REPORT_FILE"
ss -tuln >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# === 1. Détection des fichiers SUID/SGID ===
print_color "$JAUNE" " === 1. Détection des fichiers SUID/SGID ==="
echo ">>> FICHIERS SUID/SGID <<<" >> "$REPORT_FILE"
find / -perm /6000 -type f -exec ls -ld {} \; 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# === 2. Fichiers et répertoires world-writable ===
print_color "$JAUNE" " === 2. Fichiers et répertoires world-writable ==="
echo ">>> FICHIERS WORLD-WRITABLE <<<" >> "$REPORT_FILE"
find / -type f -perm -0002 -exec ls -l {} \; 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo ">>> RÉPERTOIRES WORLD-WRITABLE <<<" >> "$REPORT_FILE"
find / -type d -perm -0002 -exec ls -ld {} \; 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# === 3. Utilisateurs à risque, Analyse des groupes, comptes echus et permission sur les fichiers et repertoire de configuration sensibles ===
print_color "$NEUTRE" " === 3. Utilisateurs à risque, analyse des groupes à privileges, comptes echus et permission des fichiers et repertoires sensibles ==="
echo ">>> UTILISATEURS UID=0 <<<" >> "$REPORT_FILE"
awk -F: '($3 == "0") {print "Utilisateur UID=0 --> " $1}' /etc/passwd >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo ">>> UTILISATEURS AVEC SHELL ACTIF <<<" >> "$REPORT_FILE"
awk -F: '($7 !~ "/nologin" && $7 !~ "/false") {print $1 " --> shell : " $7}' /etc/passwd >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo ">>> UTILISATEURS SANS MOT DE PASSE <<<" >> "$REPORT_FILE"
awk -F: '($2 == "" || $2 == "*") {print $1 " --> PAS DE MOT DE PASSE"}' /etc/shadow 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo ">>> COMPTES ECHUS ET EXPIRÉS <<<" >> "$REPORT_FILE"
passwd -S -a | grep 'L' >> "$REPORT_FILE"

echo ">>> CONTROL DES ACCES IMPLICITES POUR FAIRE un Shutdown <<<" >> "$REPORT_FILE"
grep -E 'users|shutdown' /etc/group >> "$REPORT_FILE"
getent group users >> "$REPORT_FILE" 

echo ">>> IDENTIFICATION DES GROUPES A PRIVILEGES <<<" >> "$REPORT_FILE"
getent group | awk -F: '$3 < 1000 { print $1 ":" $3 }' >> "$REPORT_FILE"

echo ">>> IDENTIFICATION DES GROUPES POUVANT FAIRE DU SUDO <<<" >> "$REPORT_FILE"
awk -F: '($3 == 0) {printf "Utilisateur: %-20s UID: %s\n", $1, $3}' /etc/passwd
grep -E '^[^#].*ALL' /etc/sudoers 2>/dev/null >> "$REPORT_FILE"
grep -E '^[^#].*ALL' /etc/sudoers.d/* 2>/dev/null >> "$REPORT_FILE"

echo ">>> IDENTIFICATION DES UTILISATEURS POUVANT FAIRE DU SUDO  <<<" >> "$REPORT_FILE"
getent group wheel >> "$REPORT_FILE"

echo ">>> IDENTIFICATION DES DROITS SUR LES FICHIERS DE CONFIGURATIONS SENSIBLES  <<<" >> "$REPORT_FILE"
ls -l /etc/fstab /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/sudoers /etc/firewalld/firewalld.conf >> "$REPORT_FILE"
ls -ld /etc/firewalld/helpers /etc/firewalld/icmptypes /etc/firewalld/ipsets /etc/firewalld/policies /etc/firewalld/services /etc/firewalld/zones >> "$REPORT_FILE"

# === 4. Services actifs ===
print_color "$JAUNE" " === 4. Services actifs ==="
echo ">>> SERVICES ACTIFS <<<" >> "$REPORT_FILE"
systemctl list-units --type=service --state=running >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# === 5. Verification du renforcement ssh ===
print_color "$JAUNE" " === 5. Verification du renforcement ssh  ==="
echo ">>> VERIFICATION DE LA CONFIGURATION SSH <<<" >> "$REPORT_FILE"
SSH_CONFIG="/etc/ssh/sshd_config"

print_color "$NEUTRE" "... Vérification de la configuration SSH"

# Vérifier port (journalisation)
PORT=$(grep -i '^Port' "$SSH_CONFIG" | awk '{print $2}')
[ -z "$PORT" ] && PORT="22 (par défaut)"
echo "Port configuré : $PORT" >> "$REPORT_FILE"

# Vérifier PermitRootLogin (Journalisation)
ROOT_LOGIN=$(grep -i '^PermitRootLogin' "$SSH_CONFIG" | awk '{print $2}')
[ "$ROOT_LOGIN" == "no" ] && echo "Root login désactivé" || echo "Root login ACTIVÉ ($ROOT_LOGIN)"  >> "$REPORT_FILE"

# Vérifier PasswordAuthentication
PASS_AUTH=$(grep -i '^PasswordAuthentication' "$SSH_CONFIG" | awk '{print $2}')
[ "$PASS_AUTH" == "no" ] && echo "Authentification par mot de passe désactivée" || echo "Authentification par mot de passe ACTIVE ($PASS_AUTH)"  >> "$REPORT_FILE"

# Vérifier PubkeyAuthentication
PUBKEY_AUTH=$(grep -i '^PubkeyAuthentication' "$SSH_CONFIG" | awk '{print $2}')
[ "$PUBKEY_AUTH" == "yes" ] && echo "Authentification par clé PUBKEY activée" || echo "Authentification par clé désactivée"  >> "$REPORT_FILE"

# Vérifier X11Forwarding
X11=$(grep -i '^X11Forwarding' "$SSH_CONFIG" | awk '{print $2}')
[ "$X11" == "no" ] && echo " X11Forwarding désactivé" || echo " X11Forwarding ACTIVÉ ($X11)"  >> "$REPORT_FILE"

# --- Nouvelle section : Vérification des utilisateurs SSH autorisés ---
echo ""  >> "$REPORT_FILE"
echo "=== Vérification des utilisateurs SSH autorisés ==="  >> "$REPORT_FILE"

# Fonction pour extraire et afficher les règles spécifiques (AllowUsers, DenyUsers, AllowGroups, DenyGroups)
# Renvoie 0 si une règle est trouvée et affichée, 1 sinon.
get_ssh_config_users_groups() {
    local param=$1
    local description=$2
    local values

    # Utilise grep pour trouver le paramètre, ignore les lignes commentées, puis coupe le paramètre et affiche la valeur
    values=$(grep -iE "^\s*${param}\s+" "$SSH_CONFIG" | grep -vE "^\s*#" | awk '{print $2}')

    if [ -n "$values" ]; then
        echo "  - $description :"  >> "$REPORT_FILE"
        # Affiche chaque valeur sur une nouvelle ligne, avec un préfixe d'indentation
        for val in $values; do
            echo "    * $val"  >> "$REPORT_FILE"
        done
        return 0 # Règle trouvée
    else
        return 1 # Aucune règle trouvée
    fi
}

# Recherche et affiche les règles explicites
if get_ssh_config_users_groups "AllowUsers" "Utilisateurs explicitement autorisés (AllowUsers)"; then :
else
    echo "  - Aucune règle 'AllowUsers' trouvée."  >> "$REPORT_FILE"
fi

if get_ssh_config_users_groups "DenyUsers" "Utilisateurs explicitement refusés (DenyUsers)"; then :
else
    echo "  - Aucune règle 'DenyUsers' trouvée."  >> "$REPORT_FILE"
fi

if get_ssh_config_users_groups "AllowGroups" "Groupes explicitement autorisés (AllowGroups)"; then :
else
    echo "  - Aucune règle 'AllowGroups' trouvée."  >> "$REPORT_FILE"
fi

if get_ssh_config_users_groups "DenyGroups" "Groupes explicitement refusés (DenyGroups)"; then :
else
    echo "  - Aucune règle 'DenyGroups' trouvée."  >> "$REPORT_FILE"
fi
echo ""  >> "$REPORT_FILE"

echo "--- Utilisateurs avec clés SSH configurées (.ssh/authorized_keys) ---"  >> "$REPORT_FILE"

# Parcourir tous les utilisateurs avec UID >= 1000 et root, et un shell de connexion valide
cut -d: -f1,3,6,7 /etc/passwd | while IFS=: read -r username uid homedir shell; do
    if [[ "$uid" -ge 1000 || "$username" == "root" ]] && \
       [[ "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "" ]]; then

        AUTHORIZED_KEYS_FILE="$homedir/.ssh/authorized_keys"  >> "$REPORT_FILE"

        if [ -f "$AUTHORIZED_KEYS_FILE" ]; then
            echo "  - Utilisateur : '$username' (UID: $uid)"  >> "$REPORT_FILE"
            echo "    Fichier de clés publiques : '$AUTHORIZED_KEYS_FILE'"  >> "$REPORT_FILE"

            # Vérifier les permissions du répertoire .ssh
            SSH_DIR_PERMS=$(stat -c "%a" "$homedir/.ssh" 2>/dev/null)
            if [ "$SSH_DIR_PERMS" != "700" ]; then
                echo "    ATTENTION : Permissions du répertoire .ssh sont '$SSH_DIR_PERMS' (devrait être 700)."  >> "$REPORT_FILE"
            fi

            # Vérifier les permissions du fichier authorized_keys
            AK_FILE_PERMS=$(stat -c "%a" "$AUTHORIZED_KEYS_FILE" 2>/dev/null)
            if [ "$AK_FILE_PERMS" != "600" ] && [ "$AK_FILE_PERMS" != "640" ]; then
                echo "    ATTENTION : Permissions du fichier authorized_keys sont '$AK_FILE_PERMS' (devrait être 600 ou 640)."  >> "$REPORT_FILE"
            fi

            NUM_KEYS=$(grep -v '^#' "$AUTHORIZED_KEYS_FILE" | wc -l)
            echo "    Nombre de clés publiques trouvées : $NUM_KEYS"  >> "$REPORT_FILE"
            echo ""
        fi
    fi
done

print_color "$VERT" "=== Vérification SSH terminée ==="

# --- Fin du script principal ---

# 2. Une fois que le script principal a terminé ses opérations,
# kill le processus du minuteur en arrière-plan
kill "$TIMER_PID" &>/dev/null # Redirige la sortie vers /dev/null pour éviter les messages d erreur si le PID n'existe plus
wait "$TIMER_PID" 2>/dev/null # Attend que le processus soit réellement terminé (avec un petit délai)
echo "" # Nouvelle ligne après l'affichage final du minuteur
# === Résultat ===
print_color "$VERT" " Rapport généré avec succés: $REPORT_FILE"

printf "Temps total d'exécution : %02d:%02d\n" "$((SECONDS / 60))" "$((SECONDS % 60))"

exit 0

