import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

MAILHOG_API = "http://localhost:8025/api/v2/messages"

def get_last_email_body():
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()
    if not data["items"]:
        return None
    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

@pytest.fixture(autouse=True)
def setup_create_user():
    i = random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    salida = requests.post("http://localhost:5000/users",
                        data={
                            "username": username, 
                            "password": password,
                            "email": email,
                            "first_name": "Name",
                            "last_name": f'{username}son'
                        })
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    response = requests.post("http://localhost:5000/auth/set-password", json={"token": token, "newPassword": password})
    return [username, password]

def test_invoice_query_param_sql_injection(setup_create_user):
    """Test SQL injection en query parameters del endpoint /api/invoices"""
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json"
    }

    #obtener datos normales para comparación
    print("\n[BASELINE] Obteniendo facturas sin filtros...")
    baseline_resp = requests.get("http://localhost:3000/api/invoices", headers=headers)
    print(f"[BASELINE] Status: {baseline_resp.status_code}")
    baseline_count = 0
    if baseline_resp.status_code == 200:
        try:
            baseline_data = baseline_resp.json()
            baseline_count = len(baseline_data) if isinstance(baseline_data, list) else 0
            print(f"[BASELINE] Total de facturas: {baseline_count}")
        except:
            pass
    
    # Vectores de ataque SQL injection en query parameters
    sql_injection_payloads = [
        # (params, description)
        ({"status": "x", "operator": "='x' OR 1=1 -- '"}, "Boolean OR 1=1 bypass"),
        ({"status": "x", "operator": "='x'"}, "Control - sin inyección"),
        ({"status": "' OR '1'='1", "operator": "="}, "String-based OR injection"),
        ({"status": "x' OR 'x'='x", "operator": "="}, "String concatenation bypass"),
        ({"status": "1", "operator": "=1 OR 1=1--"}, "Operator parameter injection"),
        ({"status": "x'; DROP TABLE invoices--", "operator": "="}, "Destructive injection"),
        ({"status": "x' UNION SELECT * FROM users--", "operator": "="}, "UNION-based injection"),
        ({"status": "x", "operator": "='x' AND 1=2 UNION SELECT NULL--"}, "UNION with AND bypass"),
    ]

    vulnerabilities_found = []
    
    for params, description in sql_injection_payloads:
        print(f"\n[TEST] Probando: {description}")
        print(f"[TEST] Params: {params}")
        
        try:
            resp = requests.get("http://localhost:3000/api/invoices", params=params, headers=headers, timeout=5)
            
            print(f"[RESULT] Status: {resp.status_code}")
            print(f"[RESULT] Response length: {len(resp.text)} bytes")
            print(f"[RESULT] Response preview: {resp.text[:300]}")
            
            # Indicadores de inyección SQL exitosa
            is_vulnerable = False
            reason = []
            result_count = None
            
            # 1. Status 200 con payload que incluye OR 1=1 (debería fallar o retornar vacío)
            if resp.status_code == 200 and "OR 1=1" in str(params.values()):
                try:
                    json_data = resp.json()
                    if isinstance(json_data, list):
                        result_count = len(json_data)
                        print(f"[ANALYSIS] Retornó {result_count} registros")
                        
                        # si retorna datos cuando no debería (status='x' no existe)
                        if result_count > 0 and params.get("status") == "x":
                            is_vulnerable = True
                            reason.append(f"Retorna {result_count} registros con condición imposible (status='x')")
                        
                        # Si retorna MÁS datos que el baseline con OR 1=1
                        if result_count > baseline_count and baseline_count > 0:
                            is_vulnerable = True
                            reason.append(f"Retorna más registros ({result_count}) que baseline ({baseline_count})")
                        
                        # Si retorna TODOS los registros posibles
                        if result_count >= baseline_count and baseline_count > 0 and "OR 1=1" in str(params.values()):
                            is_vulnerable = True
                            reason.append("OR 1=1 bypass exitoso - retorna todos los registros")
                except Exception as e:
                    print(f"[ERROR] No se pudo parsear JSON: {e}")
            
            # Comparación con control (sin inyección)
            if "sin inyección" in description:
                # Este es nuestro control, guardamos para comparar
                control_status = resp.status_code
                print(f"[CONTROL] Status del control: {control_status}")
            
            # Status 500 indicaria que el payload fue procesado y causó error SQL
            if resp.status_code == 500:
                is_vulnerable = True
                reason.append("Error 500 - el payload llegó a la base de datos")
            
            # Mensajes de error SQL expuestos
            sql_error_indicators = [
                "syntax error", "postgresql", "pg::", "column", 
                "relation", "table", "database", "SQL", "query",
                "SELECT", "FROM", "WHERE", "syntax", "pg_"
            ]
            if any(indicator in resp.text.lower() for indicator in sql_error_indicators):
                reason.append("Error SQL expuesto en respuesta")
            
            # Diferente comportamiento entre control y payload malicioso
            if "OR 1=1" in str(params.values()) and resp.status_code != 200:
                reason.append("Comportamiento anómalo con OR 1=1")
            
            if is_vulnerable:
                vulnerabilities_found.append({
                    "payload": params,
                    "description": description,
                    "status": resp.status_code,
                    "reason": reason,
                    "response": resp.text[:500],
                    "result_count": result_count
                })
        
        except requests.exceptions.Timeout:
            print("[ERROR] Timeout - posible time-based SQL injection")
            vulnerabilities_found.append({
                "payload": params,
                "description": description,
                "status": "TIMEOUT",
                "reason": ["Request timeout - posible time-based injection"],
                "response": "",
                "result_count": None
            })
        except Exception as e:
            print(f"[ERROR] Exception: {e}")
    
    # Reporte final
    if vulnerabilities_found:
        print("\n" + "="*77)
        print("⚠️  VULNERABILIDADES SQL INJECTION DETECTADAS:")
        print("="*77)
        for vuln in vulnerabilities_found:
            print(f"\n[VULNERABLE] {vuln['description']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  Status: {vuln['status']}")
            print(f"  Razones: {', '.join(vuln['reason'])}")
            if vuln['result_count'] is not None:
                print(f"  Registros retornados: {vuln['result_count']}")
            print(f"  Response: {vuln['response'][:200]}...")
        print("\n" + "="*77)
        pytest.fail(f"🚨 Se detectaron {len(vulnerabilities_found)} vulnerabilidades de SQL injection")
    else:
        print("\n✅ No se detectaron vulnerabilidades de SQL injection")
        print("La aplicación está correctamente protegida")
