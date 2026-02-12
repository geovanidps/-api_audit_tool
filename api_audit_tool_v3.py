import requests
import json
import argparse
import sys
import time
import random

class APIAuditToolV3:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "EthicalAuditTool/3.0 (OWASP 2026 Aligned)"
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def log_result(self, vulnerability, status, details):
        color = "\033[91m" if "VULNERÁVEL" in status else "\033[92m" if "PROTEGIDO" in status else "\033[94m"
        reset = "\033[0m"
        print(f"\n{color}[+] Vulnerabilidade: {vulnerability}{reset}")
        print(f"    Status: {status}")
        print(f"    Detalhes: {details}")

    def _make_request(self, method, url, headers, json_data=None, data=None):
        try:
            if method.upper() == "GET":
                return requests.get(url, headers=headers)
            elif method.upper() == "POST":
                return requests.post(url, headers=headers, json=json_data, data=data)
            elif method.upper() == "PUT":
                return requests.put(url, headers=headers, json=json_data, data=data)
            elif method.upper() == "DELETE":
                return requests.delete(url, headers=headers)
            elif method.upper() == "OPTIONS":
                return requests.options(url, headers=headers)
            else:
                return requests.request(method, url, headers=headers, json=json_data, data=data)
        except requests.exceptions.ConnectionError:
            self.log_result("Erro de Conexão", "ERRO", "Falha ao conectar ao alvo. Verifique a URL ou o status do WAF.")
            return None
        except Exception as e:
            self.log_result("Erro na Requisição", "ERRO", f"Ocorreu um erro: {e}")
            return None

    def check_bola(self, endpoint, test_id):
        """API1:2023/2026 - Broken Object Level Authorization"""
        url = f"{self.base_url}/{endpoint}/{test_id}"
        print(f"[*] Testando BOLA em {url}...")
        response = self._make_request("GET", url, self.headers)
        if response:
            if response.status_code == 200:
                self.log_result("API1 (BOLA)", "POTENCIALMENTE VULNERÁVEL", f"Acesso ao recurso {test_id} retornou 200 OK. Verifique manualmente se os dados pertencem a outro usuário.")
            elif response.status_code in [401, 403]:
                self.log_result("API1 (BOLA)", "PROTEGIDO", f"Acesso negado ({response.status_code}) ao ID {test_id}.")
            else:
                self.log_result("API1 (BOLA)", "INFO", f"Resposta inesperada: {response.status_code}")

    def check_broken_auth(self, login_endpoint, username_wordlist=None, password_wordlist=None):
        """API2:2023/2026 - Broken Authentication (com Brute Force e bypass de Rate Limit)"""
        url = f"{self.base_url}/{login_endpoint}"
        print(f"[*] Testando Broken Authentication (Brute Force) em {url}...")

        usernames = username_wordlist if username_wordlist else ["admin", "user", "test", "root"]
        passwords = password_wordlist if password_wordlist else ["password", "123456", "admin", "test", "root", "toor"]

        waf_bypass_headers = [
            {"X-Forwarded-For": f"192.168.1.{random.randint(1, 254)}"},
            {"X-Originating-IP": f"10.0.0.{random.randint(1, 254)}"},
            {"X-Remote-IP": f"172.16.0.{random.randint(1, 254)}"},
            {}
        ]

        for user in usernames:
            for pwd in passwords:
                for bypass_header in waf_bypass_headers:
                    current_headers = self.headers.copy()
                    current_headers.update(bypass_header)

                    payload = {"username": user, "password": pwd}
                    response = self._make_request("POST", url, current_headers, json_data=payload)
                    if response:
                        if response.status_code == 200:
                            self.log_result("API2 (Broken Auth)", "VULNERÁVEL", f"Credenciais válidas encontradas: {user}:{pwd}")
                            return
                        elif response.status_code == 429:
                            self.log_result("API2 (Broken Auth)", "INFO", f"Rate limiting detectado para {user}:{pwd}. Tentando bypass...")
                            time.sleep(random.uniform(2, 5)) # Pequeno delay para tentar bypass
                        elif response.status_code == 401:
                            pass # Credenciais inválidas, esperado
                        else:
                            self.log_result("API2 (Broken Auth)", "INFO", f"Resposta inesperada ({response.status_code}) para {user}:{pwd} com headers {bypass_header}")
        self.log_result("API2 (Broken Auth)", "PROTEGIDO", "Nenhuma credencial válida encontrada ou WAF/Rate Limit eficaz.")

    def check_property_auth(self, endpoint, update_payload):
        """API3:2023/2026 - Broken Object Property Level Authorization"""
        url = f"{self.base_url}/{endpoint}"
        print(f"[*] Testando Property Level Authorization em {url}...")
        response = self._make_request("PUT", url, self.headers, json_data=update_payload)
        if response:
            if response.status_code == 200:
                self.log_result("API3 (Property Auth)", "AVALIAÇÃO MANUAL NECESSÁRIA", "A API aceitou o payload. Verifique se campos restritos (ex: \'role\') foram alterados. Status: 200 OK.")
            else:
                self.log_result("API3 (Property Auth)", "PROTEGIDO", f"API recusou alteração com status {response.status_code}.")

    def check_resource_consumption(self, endpoint, param_name):
        """API4:2023/2026 - Unrestricted Resource Consumption"""
        url = f"{self.base_url}/{endpoint}?{param_name}=999999999"
        print(f"[*] Testando Unrestricted Resource Consumption em {url}...")
        response = self._make_request("GET", url, self.headers)
        if response:
            if response.status_code == 200 and len(response.content) > 1000000:
                self.log_result("API4 (Resource Consumption)", "VULNERÁVEL", "API retornou grande volume de dados sem restrição de limite. Potencial DoS/custo.")
            elif response.status_code == 429:
                self.log_result("API4 (Resource Consumption)", "PROTEGIDO", "Rate limiting detectado (429 Too Many Requests).")
            else:
                self.log_result("API4 (Resource Consumption)", "PROTEGIDO", "API limitou a resposta ou retornou erro para valor excessivo.")

    def check_bfla(self, admin_endpoint):
        """API5:2023/2026 - Broken Function Level Authorization"""
        url = f"{self.base_url}/{admin_endpoint}"
        print(f"[*] Testando Broken Function Level Authorization em {url}...")
        response = self._make_request("GET", url, self.headers)
        if response:
            if response.status_code == 200:
                self.log_result("API5 (BFLA)", "VULNERÁVEL", f"Usuário atual conseguiu acessar endpoint administrativo: {admin_endpoint}")
            elif response.status_code in [401, 403]:
                self.log_result("API5 (BFLA)", "PROTEGIDO", f"Acesso negado ({response.status_code}) ao endpoint {admin_endpoint}.")
            else:
                self.log_result("API5 (BFLA)", "INFO", f"Resposta inesperada ({response.status_code}) ao endpoint {admin_endpoint}.")

    def check_unrestricted_business_flows(self, business_endpoint, num_requests=10):
        """API6:2023/2026 - Unrestricted Access to Sensitive Business Flows"""
        url = f"{self.base_url}/{business_endpoint}"
        print(f"[*] Testando Unrestricted Access to Sensitive Business Flows em {url} ({num_requests} requisições)...")
        vulnerable = False
        for i in range(num_requests):
            response = self._make_request("POST", url, self.headers, json_data={"action": "buy_ticket", "quantity": 1})
            if response and response.status_code == 200:
                vulnerable = True
            elif response and response.status_code == 429:
                self.log_result("API6 (Business Flows)", "PROTEGIDO", "Rate limiting detectado.")
                return
            time.sleep(0.1) # Pequeno delay para simular uso humano
        if vulnerable:
            self.log_result("API6 (Business Flows)", "POTENCIALMENTE VULNERÁVEL", f"{num_requests} requisições bem-sucedidas sem detecção de automação. Verifique a lógica de negócio.")
        else:
            self.log_result("API6 (Business Flows)", "PROTEGIDO", "API parece ter mecanismos contra automação ou fluxo não vulnerável.")

    def check_ssrf(self, endpoint, param):
        """API7:2023/2026 - Server Side Request Forgery"""
        internal_urls = [
            "http://169.254.169.254/latest/meta-data/", # AWS EC2 Metadata
            "http://localhost:80",
            "http://127.0.0.1:8080",
            "http://10.0.0.1/admin"
        ]
        print(f"[*] Testando SSRF em {self.base_url}/{endpoint} com parâmetro '{param}'...")
        for internal_url in internal_urls:
            url = f"{self.base_url}/{endpoint}?{param}={internal_url}"
            response = self._make_request("GET", url, self.headers)
            if response:
                if response.status_code == 200 and ("instance-id" in response.text or "Server" in response.headers):
                    self.log_result("API7 (SSRF)", "VULNERÁVEL", f"A API processou a URL interna: {internal_url}. Resposta: {response.text[:100]}...")
                    return
                elif response.status_code != 400 and response.status_code != 404:
                    self.log_result("API7 (SSRF)", "AVISO", f"Resposta inesperada ({response.status_code}) para {internal_url}. Pode indicar SSRF.")
        self.log_result("API7 (SSRF)", "PROTEGIDO", "Nenhuma URL interna processada ou resposta sensível detectada.")

    def check_misconfig(self):
        """API8:2023 / A02:2025 - Security Misconfiguration"""
        print(f"[*] Analisando configurações de segurança em {self.base_url}...")
        response = self._make_request("OPTIONS", self.base_url, self.headers)
        if response:
            server = response.headers.get("Server", "Oculto")
            x_powered = response.headers.get("X-Powered-By", "N/A")
            methods = response.headers.get("Allow", "N/A")
            
            details = f"Server: {server} | X-Powered-By: {x_powered} | Métodos Permitidos: {methods}"
            self.log_result("API8 (Misconfiguration)", "INFO", details)
            
            if "TRACE" in methods or "PUT" in methods and "PUT" not in self.base_url.upper(): # PUT só é perigoso se não for esperado
                self.log_result("API8 (Misconfiguration)", "AVISO", f"Métodos HTTP potencialmente perigosos habilitados: {methods}")
            if "X-Content-Type-Options" not in response.headers or "X-Frame-Options" not in response.headers:
                self.log_result("API8 (Misconfiguration)", "AVISO", "Headers de segurança ausentes (X-Content-Type-Options, X-Frame-Options).")
        else:
            self.log_result("API8 (Misconfiguration)", "ERRO", "Não foi possível obter resposta OPTIONS.")

    def check_inventory(self, old_version_paths=None):
        """API9:2023/2026 - Improper Inventory Management (Shadow & Zombie APIs)"""
        paths_to_check = old_version_paths if old_version_paths else [
            "v1/users", "v0/data", "dev/api/status", "api/debug", "api/test"
        ]
        print(f"[*] Testando Improper Inventory Management em {self.base_url}...")
        for path in paths_to_check:
            url = f"{self.base_url}/{path}"
            response = self._make_request("GET", url, self.headers)
            if response:
                if response.status_code != 404:
                    self.log_result("API9 (Inventory)", "AVISO", f"Endpoint de versão antiga/debug/shadow detectado: {url} (Status: {response.status_code})")
                else:
                    self.log_result("API9 (Inventory)", "PROTEGIDO", f"Caminho {path} não encontrado (Status: 404).")

    def check_unsafe_consumption(self, endpoint, third_party_data_param):
        """API10:2023 - Unsafe Consumption of APIs"""
        # Simula um payload malicioso vindo de uma API de terceiros
        malicious_payload = {"data": f"<script>alert(\'XSS\')</script>", "id": "123"}
        url = f"{self.base_url}/{endpoint}"
        print(f"[*] Testando Unsafe Consumption of APIs em {url}...")
        response = self._make_request("POST", url, self.headers, json_data=malicious_payload)
        if response:
            if response.status_code == 200 and "<script>" in response.text:
                self.log_result("API10 (Unsafe Consumption)", "VULNERÁVEL", "API processou e refletiu payload malicioso de terceiros (XSS).")
            else:
                self.log_result("API10 (Unsafe Consumption)", "PROTEGIDO", "API parece validar dados de terceiros.")

    def check_exceptional_conditions(self, endpoint):
        """A10:2025 - Mishandling of Exceptional Conditions (OWASP Top 10 2025/2026)"""
        url = f"{self.base_url}/{endpoint}"
        print(f"[*] Testando tratamento de erros (A10:2025) em {url}...")
        malformed_payloads = [
            json.dumps({"id": "not-an-int"}),
            json.dumps({"id": [1, 2, 3]}),
            json.dumps({"id": {"$gt": ""}}), # NoSQL Injection test
            "INVALID JSON"
        ]
        for p in malformed_payloads:
            current_headers = self.headers.copy()
            if p == "INVALID JSON":
                current_headers["Content-Type"] = "text/plain"
            response = self._make_request("POST", url, current_headers, data=p if p == "INVALID JSON" else None, json_data=json.loads(p) if p != "INVALID JSON" else None)
            if response:
                if response.status_code == 500:
                    self.log_result("A10 (Error Handling)", "AVISO", f"Payload malformado causou Erro 500. Verifique se há vazamento de stack trace. Payload: {p}")
                    return
                elif response.status_code == 200 and "error" not in response.text.lower():
                     self.log_result("A10 (Error Handling)", "AVISO", f"Payload malformado ({p}) resultou em 200 OK sem indicação de erro. Potencial fail-open.")
                     return
        self.log_result("A10 (Error Handling)", "PROTEGIDO", "API tratou inputs malformados sem erros fatais ou vazamento de informações.")

    def check_waf_bypass(self, endpoint, method="GET", payload=None):
        """Testa técnicas de WAF Bypass"""
        url = f"{self.base_url}/{endpoint}"
        print(f"[*] Testando WAF Bypass em {url} com método {method}...")

        bypass_techniques = [
            {"headers": {"X-Forwarded-For": "127.0.0.1"}, "desc": "X-Forwarded-For Header"},
            {"headers": {"X-Originating-IP": "127.0.0.1"}, "desc": "X-Originating-IP Header"},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}, "desc": "X-Custom-IP-Authorization Header"},
            {"url_path": f"/{endpoint.replace("/", "//")}", "desc": "Double Slash in Path"},
            {"url_path": f"/{endpoint.replace("/", "/%2f")}", "desc": "Encoded Slash in Path"},
            {"url_path": f"/{endpoint.replace("/", "/%252f")}", "desc": "Double Encoded Slash in Path"},
            {"headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"}, "desc": "Common User-Agent"},
            {"headers": {"User-Agent": ""}, "desc": "Empty User-Agent"},
        ]

        for tech in bypass_techniques:
            current_headers = self.headers.copy()
            current_url = url
            current_json_data = payload
            current_data = None

            if "headers" in tech:
                current_headers.update(tech["headers"])
            if "url_path" in tech:
                current_url = f"{self.base_url}{tech["url_path"]}"

            response = self._make_request(method, current_url, current_headers, json_data=current_json_data, data=current_data)
            if response:
                if response.status_code != 403: # Assumindo 403 como bloqueio do WAF
                    self.log_result("WAF Bypass", "POTENCIALMENTE VULNERÁVEL", f"WAF bypass bem-sucedido com: {tech["desc"]}. Status: {response.status_code}")
                    return
                else:
                    self.log_result("WAF Bypass", "INFO", f"WAF bloqueou com: {tech["desc"]}. Status: {response.status_code}")
        self.log_result("WAF Bypass", "PROTEGIDO", "Nenhuma técnica de bypass testada funcionou.")

def main_menu():
    print("\033[95m" + "="*60 + "\033[0m")
    print("   API SECURITY AUDIT TOOL V3 - OWASP TOP 10 (2023/2026 ALIGNED)")
    print("\033[95m" + "="*60 + "\033[0m")
    
    base_url = input("URL Base da API (ex: http://localhost:8000): ")
    token = input("Token JWT (opcional): ")
    
    audit = APIAuditToolV3(base_url, token)

    while True:
        print("\n--- Menu de Auditoria Ética ---")
        print("1. Testar BOLA (API1:2023)")
        print("2. Testar Broken Auth/Brute Force (API2:2023)")
        print("3. Testar Property Level Auth (API3:2023)")
        print("4. Testar Unrestricted Resource Consumption (API4:2023)")
        print("5. Testar Broken Function Level Auth (API5:2023)")
        print("6. Testar Unrestricted Business Flows (API6:2023)")
        print("7. Testar SSRF (API7:2023)")
        print("8. Testar Security Misconfiguration (API8:2023 / A02:2025)")
        print("9. Testar Improper Inventory Management (API9:2023)")
        print("10. Testar Unsafe Consumption of APIs (API10:2023)")
        print("11. Testar Mishandling of Exceptional Conditions (A10:2025)")
        print("12. Testar WAF Bypass")
        print("13. Executar Auditoria Completa (Todos os testes aplicáveis)")
        print("0. Sair")
        
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            end = input("Endpoint (ex: api/v1/user): ")
            tid = input("ID Alvo (ex: 123): ")
            audit.check_bola(end, tid)
        elif choice == '2':
            end = input("Endpoint Login (ex: api/auth/login): ")
            audit.check_broken_auth(end)
        elif choice == '3':
            end = input("Endpoint do Recurso (ex: api/v1/profile/me): ")
            payload_str = input("Payload JSON de teste (ex: {'role': 'admin'}): ")
            try:
                payload = json.loads(payload_str.replace("'", '"'))
                audit.check_property_auth(end, payload)
            except json.JSONDecodeError:
                print("Erro: Payload JSON inválido.")
        elif choice == '4':
            end = input("Endpoint de listagem (ex: api/v1/products): ")
            param = input("Parâmetro de limite (ex: limit): ")
            audit.check_resource_consumption(end, param)
        elif choice == '5':
            end = input("Endpoint Admin (ex: api/admin/users): ")
            audit.check_bfla(end)
        elif choice == '6':
            end = input("Endpoint de fluxo de negócio (ex: api/v1/tickets/buy): ")
            audit.check_unrestricted_business_flows(end)
        elif choice == '7':
            end = input("Endpoint que aceita URL (ex: api/v1/fetch): ")
            param = input("Parâmetro da URL (ex: url): ")
            audit.check_ssrf(end, param)
        elif choice == '8':
            audit.check_misconfig()
        elif choice == '9':
            paths = input("Caminhos de versão antiga/debug (separados por vírgula, padrão: v1/users,api/debug): ")
            audit.check_inventory(paths.split(',') if paths else None)
        elif choice == '10':
            end = input("Endpoint que consome dados de terceiros (ex: api/v1/webhook): ")
            param = input("Parâmetro que recebe dados de terceiros (ex: data): ")
            audit.check_unsafe_consumption(end, param)
        elif choice == '11':
            end = input("Endpoint para teste de erro (ex: api/v1/data): ")
            audit.check_exceptional_conditions(end)
        elif choice == '12':
            end = input("Endpoint para teste de WAF Bypass (ex: api/v1/search?q=union+select): ")
            method = input("Método HTTP (GET/POST, padrão GET): ") or "GET"
            payload_str = input("Payload JSON (opcional, para POST): ")
            payload = json.loads(payload_str) if payload_str else None
            audit.check_waf_bypass(end, method, payload)
        elif choice == '13':
            print("\nIniciando Auditoria Completa (requer inputs para alguns testes)...")
            # Testes que podem ser executados sem input específico
            audit.check_misconfig()
            audit.check_waf_bypass("api/v1/status", method="GET") # Exemplo simples de WAF bypass
            # Outros testes requerem inputs do usuário, então são melhor executados individualmente
            print("\nAuditoria Completa Concluída. Alguns testes exigem interação manual ou inputs específicos.")
        elif choice == '0':
            print("Encerrando auditoria ética. Até logo!")
            break
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main_menu()
