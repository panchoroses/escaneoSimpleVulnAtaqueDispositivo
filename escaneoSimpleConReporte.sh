#!/bin/bash

# Fecha y nombre del reporte HTML
FECHA=$(date '+%Y-%m-%d_%H-%M-%S')
HTML_REPORT="reporte_auditoria_$FECHA.html"

# Solicitar datos al usuario
read -p "Ingrese la dirección del servidor DHCP: " DHCP_SERVER
read -p "Ingrese el rango de IPs a escanear (ej. 192.168.1.0/24): " IP_RANGE

echo "[+] Escaneando la red en busca de dispositivos..."
timeout 20s nmap -sn $IP_RANGE -oG hosts.txt > /dev/null

# Extraer direcciones IP activas
cat hosts.txt | grep "Up" | awk '{print $2}' > active_ips.txt
rm hosts.txt  # Eliminar archivo temporal

echo "[+] Analizando dispositivos conectados..."
total_ips=0
normal_ips=0
vulnerabilidades=0
ataques=0
vulnerabilidades_list=""
ataques_list=""

while read -r IP; do
    # Saltar la IP del servidor DHCP para evitar bloqueos
    if [[ "$IP" == "$DHCP_SERVER" ]]; then
        echo "[!] Saltando la IP del servidor DHCP: $IP"
        continue
    fi

    total_ips=$((total_ips + 1))
    echo "------------------------------------------------"
    echo "[*] Analizando: $IP"

    # Obtener nombre del host con tiempo límite de 10 segundos
    HOSTNAME=$(timeout 10s nslookup $IP | grep "name" | awk '{print $4}')
    if [[ -z "$HOSTNAME" ]]; then
        HOSTNAME="Desconocido"
    fi
    echo "    Hostname: $HOSTNAME"

    # Escaneo de vulnerabilidades con tiempo límite de 30 segundos
    echo "    Escaneando vulnerabilidades..."
    VULNS=$(timeout 30s nmap -sV --script vuln $IP)

    # Clasificación de criticidad
    if echo "$VULNS" | grep -q "VULNERABLE"; then
        CRITICIDAD="Crítica"
        vulnerabilidades=$((vulnerabilidades + 1))
        vulnerabilidades_list="$vulnerabilidades_list\nIP: $IP - Vulnerabilidades encontradas"
    elif echo "$VULNS" | grep -q "CVE" && echo "$VULNS" | grep -q "HIGH"; then
        CRITICIDAD="Alta"
        vulnerabilidades=$((vulnerabilidades + 1))
        vulnerabilidades_list="$vulnerabilidades_list\nIP: $IP - Alta criticidad"
    elif echo "$VULNS" | grep -q "CVE" && echo "$VULNS" | grep -q "MEDIUM"; then
        CRITICIDAD="Media"
        vulnerabilidades=$((vulnerabilidades + 1))
        vulnerabilidades_list="$vulnerabilidades_list\nIP: $IP - Media criticidad"
    elif echo "$VULNS" | grep -q "Potentially"; then
        CRITICIDAD="Baja"
        vulnerabilidades=$((vulnerabilidades + 1))
        vulnerabilidades_list="$vulnerabilidades_list\nIP: $IP - Baja criticidad"
    else
        CRITICIDAD="Ninguna"
        normal_ips=$((normal_ips + 1))
    fi

    if [[ "$CRITICIDAD" == "Ninguna" ]]; then
        echo "    Estado: ✅ Normal (Sin vulnerabilidades detectadas)"
    else
        echo "    ⚠ Vulnerabilidad encontrada (Criticidad: $CRITICIDAD)"
        echo "$VULNS" | grep -E "VULNERABLE|CVE|Potentially" -A 5
    fi

    # Detección de ataques: Analizar puertos abiertos con tiempo límite
    echo "    Verificando si está siendo atacado..."
    PORTS=$(timeout 5s nmap --top-ports 20 $IP | grep "open" | wc -l)

    if [[ "$PORTS" -ge 15 ]]; then
        echo "    🚨 Posible ataque detectado: 🚨"
        echo "    ⚠ Muchos puertos abiertos ($PORTS)"
        ATAQUE_CRITICIDAD="Crítica"
        ataques=$((ataques + 1))
        ataques_list="$ataques_list\nIP: $IP - Crítica (Muchos puertos abiertos)"
    elif [[ "$PORTS" -ge 10 ]]; then
        echo "    ⚠ Posible ataque detectado: Muchos puertos abiertos ($PORTS)"
        ATAQUE_CRITICIDAD="Alta"
        ataques=$((ataques + 1))
        ataques_list="$ataques_list\nIP: $IP - Alta criticidad (Muchos puertos abiertos)"
    elif [[ "$PORTS" -ge 5 ]]; then
        echo "    ⚠ Posible actividad sospechosa ($PORTS puertos abiertos)"
        ATAQUE_CRITICIDAD="Media"
        ataques=$((ataques + 1))
        ataques_list="$ataques_list\nIP: $IP - Media criticidad (Actividad sospechosa)"
    else
        echo "    No se detectaron ataques activos."
        ATAQUE_CRITICIDAD="Ninguna"
    fi

    echo "    -> Criticidad del ataque: $ATAQUE_CRITICIDAD"
    echo "------------------------------------------------"
done < active_ips.txt

rm active_ips.txt  # Limpiar archivo temporal

# Calcular porcentaje de normalidad
normalidad=$((100 * normal_ips / total_ips))

echo "[+] Análisis completado."
echo "[+] Total de dispositivos analizados: $total_ips"
echo "[+] Dispositivos sin vulnerabilidades ni ataques: $normal_ips"
echo "[+] Porcentaje de normalidad: $normalidad%"

if [[ $vulnerabilidades -gt 0 ]]; then
    echo "[+] Vulnerabilidades encontradas:"
    echo -e "$vulnerabilidades_list"
else
    echo "[+] No se encontraron vulnerabilidades."
fi

if [[ $ataques -gt 0 ]]; then
    echo "[+] Posibles ataques detectados:"
    echo -e "$ataques_list"
else
    echo "[+] No se detectaron ataques."
fi

echo "[+] Generando reporte HTML: $HTML_REPORT"

{
echo "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
echo "<title>Reporte Auditoría de Red - $FECHA</title>"
echo "<style>
body { font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; color: #333; }
h1 { color: #444; }
section { background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 0 5px #ccc; }
.good { color: green; font-weight: bold; }
.warn { color: orange; font-weight: bold; }
.bad { color: red; font-weight: bold; }
pre { background: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }
</style>
</head><body>"

echo "<h1>📋 Reporte de Auditoría de Red</h1>"
echo "<p><strong>Fecha:</strong> $FECHA</p>"
echo "<section><h2>🔢 Resumen General</h2>"
echo "<p><strong>Total dispositivos analizados:</strong> $total_ips</p>"
echo "<p><strong>Dispositivos sin vulnerabilidades ni ataques:</strong> $normal_ips</p>"
echo "<p><strong>Porcentaje de normalidad:</strong> $normalidad%</p></section>"

echo "<section><h2>🛡️ Vulnerabilidades Detectadas</h2>"
if [[ $vulnerabilidades -gt 0 ]]; then
    echo "<p class='bad'><strong>Vulnerabilidades encontradas:</strong> $vulnerabilidades</p>"
    echo "<pre>$vulnerabilidades_list</pre>"
else
    echo "<p class='good'>No se encontraron vulnerabilidades.</p>"
fi
echo "</section>"

echo "<section><h2>🚨 Posibles Ataques Detectados</h2>"
if [[ $ataques -gt 0 ]]; then
    echo "<p class='bad'><strong>Ataques detectados:</strong> $ataques</p>"
    echo "<pre>$ataques_list</pre>"
else
    echo "<p class='good'>No se detectaron ataques.</p>"
fi
echo "</section>"

echo "<footer><p>🛠️ Generado automáticamente por script de auditoría.</p></footer>"
echo "</body></html>"
} > "$HTML_REPORT"

echo "[+] ✅ Reporte HTML generado con éxito: $HTML_REPORT"
