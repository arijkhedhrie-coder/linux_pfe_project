import random
import datetime

ATTACK_IPS = ["192.168.1.105", "10.0.0.42", "172.16.0.33"]
USERS = ["root", "admin", "ubuntu", "test"]

def gen_ssh_bruteforce():
    ip = random.choice(ATTACK_IPS)
    user = random.choice(USERS)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "timestamp": ts,
        "type": "SSH_BRUTE",
        "source_ip": ip,
        "user": user,
        "severity": "HIGH",
        "message": f"Failed password for {user} from {ip} port 22"
    }

def gen_nmap_scan():
    ip = random.choice(ATTACK_IPS)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "timestamp": ts,
        "type": "PORT_SCAN",
        "source_ip": ip,
        "severity": "MEDIUM",
        "message": f"Nmap scan detected from {ip} on port {random.randint(1, 9999)}"
    }

def gen_kpi():
    return {
        "cpu_load": round(random.uniform(20, 85), 1),
        "ssh_failures": random.randint(0, 150),
        "active_connections": random.randint(1, 40),
        "error_rate": round(random.uniform(0, 12), 2)
    }

def gen_report():
    ip = random.choice(ATTACK_IPS)
    return {
        "summary": f"3 attaques SSH brute-force détectées depuis {ip}.",
        "agents": ["Collector", "Detector", "Reporter"],
        "recommendation": f"Bloquer IP {ip} via iptables."
    }
