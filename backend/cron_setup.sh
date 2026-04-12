#!/bin/bash
# ============================================================
# cron_setup.sh
# Configure la collecte automatique toutes les 4 heures
# À exécuter UNE SEULE FOIS sur Ubuntu VM
# ============================================================

echo "=== Configuration du Cron Job — Collecte toutes les 4h ==="

# Chemin vers ton projet (adapter si différent)
PROJET_DIR="/home/arouja/pfe-linux-supervision"
PYTHON_BIN="$PROJET_DIR/.venv311/bin/python"
SCRIPT="$PROJET_DIR/src/collect_logs.py"
LOG_CRON="$PROJET_DIR/logs/cron_collect.log"

# Créer le dossier de logs cron
mkdir -p "$PROJET_DIR/logs"

# La ligne cron : toutes les 4 heures (00:00, 04:00, 08:00, 12:00, 16:00, 20:00)
CRON_LINE="0 */4 * * * $PYTHON_BIN $SCRIPT >> $LOG_CRON 2>&1"

# Ajouter au crontab si pas déjà présent
(crontab -l 2>/dev/null | grep -v "collect_logs"; echo "$CRON_LINE") | crontab -

echo ""
echo "✅ Cron configuré ! Vérification :"
crontab -l
echo ""
echo "📋 Pour voir les logs d'exécution :"
echo "   tail -f $LOG_CRON"
echo ""
echo "🔧 Pour tester MAINTENANT sans attendre :"
echo "   $PYTHON_BIN $SCRIPT"