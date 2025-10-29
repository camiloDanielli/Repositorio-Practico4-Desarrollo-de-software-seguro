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

def test_invoice_sql_injection_multiple_vectors(setup_create_user):
    """Test múltiples vectores de inyección SQL para detectar vulnerabilidades reales"""
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # crear una factura válida para tener datos de referencia
    valid_resp = requests.get("http://localhost:5000/invoices", headers=headers)
    print(f"\n[INFO] Facturas válidas disponibles: {valid_resp.status_code}")
    if valid_resp.status_code == 200:
        print(f"[INFO] Contenido: {valid_resp.json()}")
    
    # Vectores de ataque SQL injection
    sql_injection_payloads = [
        ("1 OR 1=1", "Boolean-based blind injection"),
        ("1' OR '1'='1", "String-based injection"),
        ("1; DROP TABLE invoices--", "Destructive injection"),
        ("1 UNION SELECT * FROM users--", "UNION-based injection"),
        ("1' AND '1'='1", "String AND condition"),
        ("999999 OR 1=1", "Non-existent ID with OR"),
    ]

    vulnerabilities_found = []
    
    for payload, description in sql_injection_payloads:
        print(f"\n[TEST] Probando: {description}")
        print(f"[TEST] Payload: {payload}")
        
        resp = requests.get(f"http://localhost:5000/invoices/{payload}", headers=headers)
        
        print(f"[RESULT] Status: {resp.status_code}")
        print(f"[RESULT] Response: {resp.text[:200]}")  # Primeros 200 caracteres
        
        # Indicadores de inyección SQL exitosa
        is_vulnerable = False
        reason = []
        
        # 1. Status 200 con payload malicioso (debería ser 400/404)
        if resp.status_code == 200:
            is_vulnerable = True
            reason.append("Status 200 con payload malicioso")
            
            # Verificar si retorna múltiples registros (indicador fuerte)
            try:
                json_data = resp.json()
                if isinstance(json_data, list) and len(json_data) > 1:
                    reason.append(f"Retorna múltiples registros ({len(json_data)})")
                elif isinstance(json_data, dict) and json_data.get("id") != 1:
                    # Si el payload tiene "1" pero retorna otro ID, puede ser vulnerable
                    reason.append(f"ID manipulado: esperaba cerca de 1, obtuvo {json_data.get('id')}")
            except:
                pass
        
        # 2. Mensajes de error SQL expuestos
        sql_error_indicators = [
            "syntax error", "postgresql", "pg::", "column", 
            "relation", "table", "database", "SQL", "query"
        ]
        if any(indicator in resp.text.lower() for indicator in sql_error_indicators):
            if resp.status_code == 500:
                # 500 con error SQL puede indicar que el payload fue procesado
                reason.append("Error SQL expuesto en respuesta")
        
        # 3. Respuesta diferente con payloads similares (time-based detection)
        # Este es más complejo y requeriría múltiples requests
        
        if is_vulnerable:
            vulnerabilities_found.append({
                "payload": payload,
                "description": description,
                "status": resp.status_code,
                "reason": reason,
                "response": resp.text[:500]
            })
    
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
            print(f"  Response: {vuln['response'][:200]}...")
        print("\n" + "="*77)
        pytest.fail(f"Se detectaron {len(vulnerabilities_found)} vulnerabilidades de SQL injection")
    else:
        print("\n✅ No se detectaron vulnerabilidades de SQL injection")
        print("La aplicación está correctamente protegida con parámetros preparados")

def test_invoice_sql_injection_simple(setup_create_user):
    """Test simplificado que verifica protección básica"""
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    malicious_invoice_id = "1 OR 1=1"
    resp = requests.get(f"http://localhost:5000/invoices/{malicious_invoice_id}", headers=headers)

    print(f"\nStatus code: {resp.status_code}")
    print(f"Response body: {resp.text}")

    # La aplicación debe rechazar el input malicioso (400, 404, o 500 son aceptables)
    # Lo importante es que NO retorne 200 con datos
    assert resp.status_code != 200, "⚠️  VULNERABLE: La aplicación aceptó el payload malicioso"
    
    # Verificar que no hay información sensible en el error
    sensitive_keywords = ["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE"]
    has_sql_leak = any(keyword in resp.text.upper() for keyword in sensitive_keywords)
    
    if has_sql_leak:
        print("⚠️  WARNING: La respuesta expone información SQL (no es crítico si usa parámetros preparados)")