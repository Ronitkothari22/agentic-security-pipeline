import subprocess
import logging
import os
import json
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import ipaddress

# Set up logging
log_dir = os.path.join(os.getcwd(), 'Logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, 'security_pipeline.log')
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ScopeConfig:
    def __init__(self, allowed_domains: List[str], allowed_ips: List[str]):
        self.allowed_domains = [d.lower() for d in allowed_domains]
        self.allowed_ips = [ipaddress.ip_network(ip, strict=False) for ip in allowed_ips]

    def is_in_scope(self, target: str) -> bool:
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self.allowed_ips)
        except ValueError:
            target = target.lower()
            return any(target == d or target.endswith('.' + d) for d in self.allowed_domains)

class SecurityTask(BaseModel):
    task_type: str
    target: str
    parameters: Dict[str, str]
    status: str = 'pending'
    result: Optional[str] = None
    error: Optional[str] = None

def run_security_tool(task: SecurityTask) -> str:
    logging.info(f"Starting {task.task_type} on {task.target}")
    if task.task_type == 'nmap':
        cmd = ['nmap', '-Pn', task.target, '-p', task.parameters.get('-p', '80')]
    elif task.task_type == 'gobuster':
        cmd = ['gobuster', 'dir', '-u', f"http://{task.target}", '-w', task.parameters.get('wordlist', r'C:\wordlists\common.txt'), '-b', '400']
    elif task.task_type == 'ffuf':
        cmd = ['ffuf', '-u', f"http://{task.target}/FUZZ", '-w', task.parameters.get('wordlist', r'C:\wordlists\common.txt')]
    elif task.task_type == 'sqlmap':
        cmd = ['python', r'C:\Tools\sqlmap\sqlmap.py', '-u', task.target, '--batch', f"--level={task.parameters.get('level', '1')}"]
    else:
        raise ValueError(f"Unknown task type: {task.task_type}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=5)
        logging.info(f"Completed {task.task_type} on {task.target}")
        return result.stdout
    except subprocess.TimeoutExpired as e:
        logging.error(f"{task.task_type} on {task.target} timed out after 5 seconds")
        return e.stdout if e.stdout else "Timed out"
    except subprocess.CalledProcessError as e:
        logging.error(f"{task.task_type} failed on {task.target}: {e.stderr}")
        return e.stdout if e.stdout else f"Failed: {e.stderr}"
    except FileNotFoundError:
        logging.error(f"Tool {task.task_type} not found.")
        raise RuntimeError(f"Tool {task.task_type} not found.")

def parse_nmap_output(output: str) -> List[int]:
    open_ports = []
    for line in output.splitlines():
        if '/tcp' in line and 'open' in line:
            try:
                port = int(line.split('/')[0].strip())
                open_ports.append(port)
            except (ValueError, IndexError):
                continue
    return open_ports

def parse_gobuster_output(output: str) -> List[str]:
    directories = []
    for line in output.splitlines():
        if line.startswith('/'):
            parts = line.split()
            if parts:
                directories.append(parts[0])
    return directories

def parse_ffuf_output(output: str) -> List[str]:
    findings = []
    for line in output.splitlines():
        if '[Status:' in line:
            parts = line.split()
            if len(parts) > 1:
                findings.append(parts[1])  # Status code
    return findings

def parse_sqlmap_output(output: str) -> Dict[str, Any]:
    findings = {'vulnerable': False}
    if 'is vulnerable' in output.lower():
        findings['vulnerable'] = True
    return findings

class SecurityPipeline:
    def __init__(self, scope: ScopeConfig, initial_tasks: List[SecurityTask]):
        self.state = {
            'scope': scope,
            'tasks': initial_tasks,
            'findings': {}
        }

    def run(self):
        for task in self.state['tasks']:
            if task.status != 'pending':
                continue
            if not self.state['scope'].is_in_scope(task.target):
                task.status = 'failed'
                task.error = 'Target out of scope'
                logging.error(f"Task {task.task_type} on {task.target} out of scope")
                continue
            task.status = 'running'
            try:
                task.result = run_security_tool(task)
                task.status = 'completed'
                findings = self.state['findings'].setdefault(task.target, {})
                if task.task_type == 'nmap':
                    findings['open_ports'] = parse_nmap_output(task.result)
                elif task.task_type == 'gobuster':
                    findings['directories'] = parse_gobuster_output(task.result)
                elif task.task_type == 'ffuf':
                    findings['ffuf_results'] = parse_ffuf_output(task.result)
                elif task.task_type == 'sqlmap':
                    findings['sqlmap_results'] = parse_sqlmap_output(task.result)
            except Exception as e:
                task.status = 'failed'
                task.error = str(e)
                logging.error(f"Task {task.task_type} on {task.target} failed: {e}")
        report = {
            "tasks": [task.dict() for task in self.state['tasks']],
            "findings": self.state['findings'],
            "scope": {
                "domains": self.state['scope'].allowed_domains,
                "ips": [str(ip) for ip in self.state['scope'].allowed_ips]
            }
        }
        report_path = os.path.join(os.getcwd(), 'audit_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        logging.info("Final report generated: audit_report.json")
        return self.state