"""
dashboard.py
Dashboard Streamlit — supervision Linux en temps réel.
Source 1 : live_api.py (logs réels chaque seconde)
Source 2 : main.py batch (analyse ML toutes les 4h)
"""
import streamlit as st
import requests
import pandas as pd
import json
import time
import os

st.set_page_config(
    page_title="Supervision Linux",
    page_icon="🛡️",
    layout="wide"
)

# ──────────────────────────────────────────
# SOURCES DE DONNÉES
# ──────────────────────────────────────────
def get_live_data():
    """Source 1 — logs réels via Flask (chaque seconde)."""
    try:
        r = requests.get("http://localhost:5001/live", timeout=2)
        return r.json()
    except:
        return None


def get_batch_results():
    """Source 2 — résultats ML via main.py (toutes les 4h)."""
    path = "output/results_latest.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


# ──────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────
st.title("🛡️ Tableau de bord — Supervision Linux")
st.caption("Surveillance en temps réel · Kali Linux + Ubuntu Server · AWS S3")

# Indicateur source
live = get_live_data()
batch = get_batch_results()

if live:
    source = live.get("source", "simulation")
    if source == "reel":
        st.success("🟢 Connecté aux logs réels des VMs")
    else:
        st.warning("🟡 Mode simulation — démarre les VMs et sync_logs.sh")
else:
    st.error("🔴 API live non disponible — lance python src/live_api.py")

st.divider()

# ──────────────────────────────────────────
# SECTION 1 — KPIs TEMPS RÉEL
# ──────────────────────────────────────────
st.subheader("⚡ Métriques en temps réel")

if live:
    # Ligne 1 — SSH
    st.markdown("**SSH & Authentification**")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🔴 Tentatives SSH",    live.get("tentatives_ssh", 0))
    c2.metric("✅ Connexions OK",      live.get("connexions_ok", 0))
    c3.metric("👤 User invalides",     live.get("invalid_user", 0))
    c4.metric("💀 Attaques root",      live.get("tentatives_root", 0))
    c5.metric("⚙️ Commandes sudo",     live.get("sudo_cmds", 0))

    st.markdown("**Système & Kernel**")
    c6, c7, c8, c9 = st.columns(4)
    c6.metric("⚠️ Erreurs système",    live.get("erreurs_sys", 0))
    c7.metric("📢 Warnings",           live.get("warnings_sys", 0))
    c8.metric("💥 Erreurs kernel",     live.get("erreurs_kernel", 0))
    c9.metric("🧠 OOM Killer",         live.get("oom_killer", 0))

else:
    st.warning("API live non disponible — lance live_api.py")

st.divider()

# ──────────────────────────────────────────
# SECTION 2 — IPs SUSPECTES + BANNIES
# ──────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    st.subheader("🎯 Top IPs suspectes")
    if live and live.get("top_ips_suspectes"):
        df_ips = pd.DataFrame(live["top_ips_suspectes"])
        df_ips.columns = ["Adresse IP", "Tentatives"]
        df_ips = df_ips.sort_values("Tentatives", ascending=False)
        st.dataframe(df_ips, use_container_width=True, hide_index=True)
        st.caption(f"Total IPs uniques détectées : {live.get('nb_ips_uniques', 0)}")
    else:
        st.info("Aucune IP suspecte détectée")

with col2:
    st.subheader("🚫 IPs bannies par Fail2Ban")
    if live and live.get("ips_bannies"):
        for ip in live["ips_bannies"]:
            st.error(f"🚫 {ip}")
    else:
        st.success("✅ Aucune IP bannie pour l'instant")

    # Stats fichiers lus
    if live and live.get("nb_logs_lus"):
        st.markdown("**Fichiers logs lus**")
        logs_lus = live["nb_logs_lus"]
        for nom, nb in logs_lus.items():
            couleur = "🟢" if nb > 0 else "🔴"
            st.caption(f"{couleur} {nom}.log — {nb} lignes")

st.divider()

# ──────────────────────────────────────────
# SECTION 3 — ANALYSE ML BATCH
# ──────────────────────────────────────────
st.subheader("🤖 Analyse ML — Agents CrewAI (batch 4h)")

col3, col4 = st.columns(2)

with col3:
    if batch:
        b1, b2 = st.columns(2)
        b1.metric("🔍 Anomalies ML",     batch.get("nb_anomalies", 0))
        b2.metric("🚨 Alarmes critiques", batch.get("nb_alarmes", 0))
        st.caption(f"Dernière analyse : {batch.get('date', 'N/A')}")
    else:
        st.info("⏳ En attente de la première analyse ML (lance main.py)")

with col4:
    if batch and batch.get("resultat_agents"):
        st.markdown("**Rapport des agents IA**")
        st.text_area(
            label="",
            value=batch.get("resultat_agents", ""),
            height=150,
            disabled=True
        )

st.divider()

# ──────────────────────────────────────────
# SECTION 4 — LOGS BRUTS EN DIRECT
# ──────────────────────────────────────────
st.subheader("📋 Derniers événements en direct")

if live and live.get("derniers_events"):
    for event in reversed(live["derniers_events"]):
        # Colorier selon le type
        if "Failed" in event or "error" in event.lower() or "Error" in event:
            st.error(f"🔴 {event}")
        elif "warning" in event.lower() or "Warning" in event:
            st.warning(f"🟡 {event}")
        elif "Accepted" in event or "success" in event.lower():
            st.success(f"🟢 {event}")
        else:
            st.text(f"⚪ {event}")
else:
    st.info("En attente des logs...")

# ──────────────────────────────────────────
# FOOTER + TIMESTAMP
# ──────────────────────────────────────────
st.divider()
if live:
    st.caption(f"🕐 Dernière mise à jour : {live.get('timestamp', 'N/A')} | "
               f"Source : {live.get('source', 'N/A')} | "
               f"Rafraîchissement : toutes les secondes")

# Rafraîchissement automatique toutes les secondes
time.sleep(1)
st.rerun()