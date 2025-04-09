import os, re, json, requests
import pandas as pd
from collections import Counter, defaultdict

regex = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\"\s(\d{3})"

def extractFromRegularExpresion(regex, data):
    if data:
        return re.findall(regex, data)
    return None

def ubicacion(ip):
    URI = "http://ip-api.com/json/"
    formatData = {}
    try:
        response = requests.get(f"{URI}{ip}").json()
        formatData["country"] = response.get("country")
        formatData["city"] = response.get("city")
    except Exception as e:
        formatData["country"] = None
        formatData["city"] = None
        print(f"Error al obtener la ubicación para {ip}: {e}")
    return formatData
log_dir = r"C:\\Users\\Tatiana\\Downloads\\syslog"

# Guarda la informacion y la analiza
ipsCode = []
log_data = []
ip_counter = Counter()
event_counter = defaultdict(Counter)
login_fails = []
apache_errors = []
firewall_blocks = []
snort_alerts = []
timestamps = []

ip_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
login_fail_regex = r"(login (failed|incorrect|unauthorized))"
apache_error_regex = r"\s(403|404|500|503|401)\s"
firewall_block_regex = r"(Blocked|DROP|iptables)"
snort_alert_regex = r"(snort|alert|\[\*\*\])"
timestamp_regex = r"\[(\d{2}/[A-Za-z]+/\d{4}:\d{2}:\d{2})"

def extract_from_regex(pattern, text, ignore_case=False):
    flags = re.IGNORECASE if ignore_case else 0
    return re.findall(pattern, text, flags)

# Leer y analizar los archivos en el directorio
for filename in os.listdir(log_dir):
    file_path = os.path.join(log_dir, filename)
    if os.path.isfile(file_path):
        with open(file_path, "rt", errors="ignore") as file:
            for line in file:
                log_data.append(line)

                # IPs + códigos de error
                resultado = extractFromRegularExpresion(regex, line)
                if resultado:
                    ipsCode.extend(resultado)

                # IPs solas
                ips = extract_from_regex(ip_regex, line)
                for ip in ips:
                    ip_counter[ip] += 1

                if re.search(login_fail_regex, line, re.IGNORECASE):
                    login_fails.append(line)
                    for ip in ips:
                        event_counter["login_fail"][ip] += 1

                if re.search(apache_error_regex, line):
                    apache_errors.append(line)
                    for ip in ips:
                        event_counter["apache_error"][ip] += 1

                if re.search(firewall_block_regex, line, re.IGNORECASE):
                    firewall_blocks.append(line)
                    for ip in ips:
                        event_counter["firewall_block"][ip] += 1

                if re.search(snort_alert_regex, line, re.IGNORECASE):
                    snort_alerts.append(line)
                    for ip in ips:
                        event_counter["snort_alert"][ip] += 1

                ts = extract_from_regex(timestamp_regex, line)
                if ts:
                    timestamps.append(ts[0])

# Contar IPs + códigos de error
contadorIps = Counter(ipsCode)

# Obtener geolocalización
info_ubicaciones = []
for (ip, error_code), count in contadorIps.items():
    location = ubicacion(ip)
    print(f"IP: {ip} // Código de error: {error_code} // País: {location['country']} // Ciudad: {location['city']} // Cantidad: {count}")
    info_ubicaciones.append({
        "ip": ip,
        "error_code": error_code,
        "country": location["country"],
        "city": location["city"],
        "count": count
    })

# Guardar en CSV
pd.DataFrame(info_ubicaciones).to_csv("ips_ubicacion_codigo.csv", index=False)

# Guardar datos en JSON
with open("datos.json", "w", encoding="utf-8") as json_file:
    json.dump(log_data, json_file, indent=4)

# Tendencias de tiempo
if timestamps:
    df_time = pd.DataFrame(timestamps, columns=["timestamp"])
    df_time["timestamp"] = pd.to_datetime(df_time["timestamp"], format="%d/%b/%Y:%H:%M", errors="coerce")
    ataques_por_dia = df_time["timestamp"].dt.date.value_counts().sort_index()

# Mostrar resumen
print("\n IPs unicas ")
for ip, count in ip_counter.most_common(10000):
    print(f"{ip}: {count} veces")

print("\n Eventos por tipo y por IP (sospechosos) ")
for tipo_evento, contador in event_counter.items():
    print(f"\n{tipo_evento.upper()} - IPs:")
    for ip, count in contador.most_common(100000):
        print(f"  {ip}: {count} veces")

print("\n Total login fallidos:", len(login_fails))
print("Ejemplo:", login_fails[0] if login_fails else "Ninguno")

print("\nTotal errores Apache:", len(apache_errors))
print("Ejemplo:", apache_errors[0] if apache_errors else "Ninguno")

print("\nBloqueos de firewall:", len(firewall_blocks))
print("\nAlertas Snort:", len(snort_alerts))

if timestamps:
    print("\nActividad sospechosa por día:")
    print(ataques_por_dia)

# Guardar CSVs
pd.DataFrame.from_dict(ip_counter, orient='index', columns=['count']).to_csv("ips_frecuentes.csv")
pd.Series(login_fails).to_csv("login_fails.csv", index=False)
pd.Series(apache_errors).to_csv("apache_errors.csv", index=False)
pd.Series(firewall_blocks).to_csv("firewall_blocks.csv", index=False)
pd.Series(snort_alerts).to_csv("snort_alerts.csv", index=False)
if timestamps:
    ataques_por_dia.to_csv("tendencias_por_dia.csv")

print("\n Análisis completado y resultados guardados en archivos CSV.")
