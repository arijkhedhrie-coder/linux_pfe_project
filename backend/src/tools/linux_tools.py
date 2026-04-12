import paramiko


def run_ssh_command(host: str,
                    username: str,
                    password: str | None = None,
                    key_path: str | None = None,
                    command: str | None = None,
                    port: int = 22,
                    timeout: int = 10) -> str:
    """Se connecte en SSH et execute une commande.

    La connexion peut utiliser un mot de passe ou une cle privee.

    Retourne la sortie standard (ou un message d'erreur).
    """
    if command is None:
        return ""  # pas de commande a executer

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            pkey = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(hostname=host, port=port, username=username, pkey=pkey, timeout=timeout)
        else:
            client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)

        stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        client.close()
        if err:
            return f"ERROR: {err.strip()}"
        return out.strip()
    except Exception as exc:
        return f"SSH connection failed: {exc}"


def get_system_metrics(host: str,
                       username: str,
                       password: str | None = None,
                       key_path: str | None = None,
                       port: int = 22) -> dict:
    """Recupere un ensemble de metriques de base a partir du serveur.

    Renvoie un dictionnaire contenant les sorties des commandes suivantes :
    ``top`` (CPU), ``free`` (memoire) et ``df`` (disque).
    Les valeurs retournees sont simplement les chaines brutes, a analyser
    cote agent ou application.
    """
    cpu = run_ssh_command(host, username, password, key_path, "top -bn1 | grep 'Cpu(s)'", port)
    memory = run_ssh_command(host, username, password, key_path, "free -m", port)
    disk = run_ssh_command(host, username, password, key_path, "df -h", port)

    return {
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
    }
