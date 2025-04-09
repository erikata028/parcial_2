import os,re,json
import pandas as pd
from collections import Counter, defaultdict

log_dir = r"C:\\Users\\Tatiana\\Downloads\\iptables"

ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

login_fail_regex = r"(login (failed|incorrect|unauthorized))"
apache_error_regex = r"\s(403|404|500|503|401)\s"
firewall_block_regex = r"(Blocked|DROP|iptables)"
snort_alert_regex = r"(snort|alert|\[\*\*\])"
timestamp_regex = r"\[(\d{2}/[A-Za-z]+/\d{4}:\d{2}:\d{2})"

#Guarda la informacion 
log_data = []
ip_counter = Counter()
event_counter = defaultdict(Counter)  # evento -> ip -> count
login_fails = []
apache_errors = []
firewall_blocks = []
snort_alerts = []
timestamps = []

#  Función para regex
def extract_from_regex(pattern, text, ignore_case=False):
    flags = re.IGNORECASE if ignore_case else 0
    return re.findall(pattern, text, flags)

#  Leer y analizar todos los archivos de logs
for filename in os.listdir(log_dir):
    file_path = os.path.join(log_dir, filename)
    if os.path.isfile(file_path):
        with open(file_path, "rt", errors="ignore") as file:
            for line in file:
                log_data.append(line)

                # IPs
                ips = extract_from_regex(ip_regex, line)
                for ip in ips:
                    ip_counter[ip] += 1

                # Login fallido
                if re.search(login_fail_regex, line, re.IGNORECASE):
                    login_fails.append(line)
                    for ip in ips:
                        event_counter["login_fail"][ip] += 1

                # Errores Apache
                if re.search(apache_error_regex, line):
                    apache_errors.append(line)
                    for ip in ips:
                        event_counter["apache_error"][ip] += 1

                # Firewall (opcional)
                if re.search(firewall_block_regex, line, re.IGNORECASE):
                    firewall_blocks.append(line)
                    for ip in ips:
                        event_counter["firewall_block"][ip] += 1

                # Snort IDS (opcional)
                if re.search(snort_alert_regex, line, re.IGNORECASE):
                    snort_alerts.append(line)
                    for ip in ips:
                        event_counter["snort_alert"][ip] += 1

                # Timestamps para tendencias
                ts = extract_from_regex(timestamp_regex, line)
                if ts:
                    timestamps.append(ts[0])

#  Guardar logs como JSON (opcional)
with open("datos.json", "w", encoding="utf-8") as json_file:
    json.dump(log_data, json_file, indent=4)

#  Tendencias de tiempo con pandas
if timestamps:
    df_time = pd.DataFrame(timestamps, columns=["timestamp"])
    df_time["timestamp"] = pd.to_datetime(df_time["timestamp"], format="%d/%b/%Y:%H:%M", errors="coerce")
    ataques_por_dia = df_time["timestamp"].dt.date.value_counts().sort_index()

# Mostrar resumen
print(" IPs más frecuentes:")
for ip, count in ip_counter.most_common(100000):
    print(f"{ip}: {count} veces")

# Eventos por tipo
print("Eventos por tipo y por IP ( sospechosos):")
for tipo_evento, contador in event_counter.items():
    print(f"\n {tipo_evento.upper()} -  IPs:")
    for ip, count in contador.most_common(100000):
        print(f"  {ip}: {count} veces")

# Login fails
print("\n Total login fallidos:", len(login_fails))
print(" Ejemplo:", login_fails[0] if login_fails else "Ninguno")

# Apache errors
print("\n Total errores Apache:", len(apache_errors))
print("Ejemplo:", apache_errors[0] if apache_errors else "Ninguno")

# Firewall blocks
print("\n Bloqueos de firewall:", len(firewall_blocks))

# Snort alerts
print("\n Alertas Snort:", len(snort_alerts))

# Tendencias por fecha
if timestamps:
    print("\n Actividad sospechosa por día:")
    print(ataques_por_dia)

#  Guardar resultados en CSV
pd.DataFrame.from_dict(ip_counter, orient='index', columns=['count']).to_csv("ips_frecuentes.csv")
pd.Series(login_fails).to_csv("login_fails.csv", index=False)
pd.Series(apache_errors).to_csv("apache_errors.csv", index=False)
pd.Series(firewall_blocks).to_csv("firewall_blocks.csv", index=False)
pd.Series(snort_alerts).to_csv("snort_alerts.csv", index=False)
if timestamps:
    ataques_por_dia.to_csv("tendencias_por_dia.csv")

print("\n Análisis completado y resultados guardados en archivos CSV.")
