import platform
import socket
import getpass
import psutil
import os
from datetime import datetime


def get_system_info():
    username = getpass.getuser()
    hostname = socket.gethostname()
    os_name = platform.system()
    os_version = platform.version()
    machine = platform.machine()

    print("=" * 50)
    print("SYSTEM & NETWORK INSPECTOR")
    print("=" * 50)
    print(f"User: {username}")
    print(f"Hostname: {hostname}")
    print(f"Operating System: {os_name}")
    print(f"OS Version: {os_version}")
    print(f"Machine Type: {machine}")
    print("=" * 50)


def get_resources_usage():
    cpu_usage = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()

    print("RESOURCE USAGE")
    print("-" * 50)
    print(f"CPU Usage: {cpu_usage}%")
    print(f"RAM Usage: {ram.percent}%")
    print(f"Total RAM: {round(ram.total / (1024 ** 3), 2)} GB")
    print(f"Available RAM: {round(ram.available / (1024 ** 3), 2)} GB")
    print("=" * 50)

    return cpu_usage, ram.percent


def get_running_processes(limit=10):
    print("RUNNING PROCESSES")
    print("-" * 50)

    processes = []

    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            processes.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for process in processes[:limit]:
        print(f"PID: {process['pid']} | Name: {process['name']} | User: {process['username']}")

    print("=" * 50)


def get_network_info():
    print("NETWORK INFORMATION")
    print("-" * 50)

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    print("=" * 50)


def get_active_connections(limit=10):
    print("ACTIVE NETWORK CONNECTIONS")
    print("-" * 50)

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Access denied. Try running the program with sudo:")
        print("sudo python3 inspector.py")
        print("=" * 50)
        return

    count = 0

    for conn in connections:
        if conn.laddr:
            local_ip = conn.laddr.ip
            local_port = conn.laddr.port
        else:
            continue

        remote_ip = ""
        remote_port = ""

        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

        status = conn.status

        print(f"{local_ip}:{local_port} -> {remote_ip}:{remote_port} | {status}")

        count += 1
        if count >= limit:
            break

    print("=" * 50)


def detect_suspicious_connections():
    print("SUSPICIOUS ACTIVITY CHECK")
    print("-" * 50)

    common_ports = {
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123,
        135, 139, 143, 161, 389, 443, 445, 587,
        993, 995, 1433, 3306, 3389, 5432, 5900, 8080
    }

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Access denied. Run with sudo for full analysis.")
        print("=" * 50)
        return 0

    unusual_count = 0

    for conn in connections:
        if conn.laddr and conn.raddr and conn.status == "ESTABLISHED":
            port = conn.laddr.port
            remote_ip = conn.raddr.ip

            if port not in common_ports:
                print(f"[!] Unusual port detected: {port} -> {remote_ip}")
                unusual_count += 1

    if unusual_count == 0:
        print("No unusual ports detected.")

    print("=" * 50)

    return unusual_count


def calculate_risk_score(cpu_usage, ram_usage, unusual_ports_count):
    score = 0

    if cpu_usage > 80:
        score += 1

    if ram_usage > 80:
        score += 1

    if unusual_ports_count >= 5:
        score += 2
    elif unusual_ports_count > 0:
        score += 1

    if score >= 3:
        return "HIGH"
    elif score == 2:
        return "MEDIUM"
    else:
        return "LOW"


def save_report(report_lines):
    folder = "Reports"

    if not os.path.exists(folder):
        os.makedirs(folder)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{folder}/report_{timestamp}.txt"

    with open(filename, "w") as file:
        for line in report_lines:
            file.write(line + "\n")

    print(f"Report saved to {filename}")


def main():
    report_lines = []

    get_system_info()
    cpu_usage, ram_usage = get_resources_usage()
    get_running_processes()
    get_network_info()
    get_active_connections()

    unusual_ports = detect_suspicious_connections()
    risk = calculate_risk_score(cpu_usage, ram_usage, unusual_ports)

    print(f"Risk Level: {risk}")
    print("=" * 50)

    report_lines.append("System & Network Inspector Report")
    report_lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"CPU Usage: {cpu_usage}%")
    report_lines.append(f"RAM Usage: {ram_usage}%")
    report_lines.append(f"Unusual Ports Detected: {unusual_ports}")
    report_lines.append(f"Risk Level: {risk}")

    save_report(report_lines)


if __name__ == "__main__":
    main()