import pytest
from security_pipeline import ScopeConfig, SecurityTask, run_security_tool, parse_nmap_output, parse_gobuster_output, SecurityPipeline
from unittest.mock import patch

def test_scope_config():
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=["192.168.1.0/24"])
    assert scope.is_in_scope("example.com") == True
    assert scope.is_in_scope("sub.example.com") == True
    assert scope.is_in_scope("other.com") == False
    assert scope.is_in_scope("192.168.1.10") == True
    assert scope.is_in_scope("10.0.0.1") == False

@patch('subprocess.run')
def test_run_security_tool_gobuster(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="/test (Status: 200)")
    result = run_security_tool("gobuster", "http://example.com", {"wordlist": r"C:\wordlists\common.txt"})
    assert "/test" in result
    mock_run.assert_called_once()

@patch('subprocess.run')
def test_failure_retry(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Error")
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=[])
    task = SecurityTask(task_type="nmap", target="example.com", parameters={"-p": "80"})
    pipeline = SecurityPipeline(scope, [task])
    state = pipeline.run()
    assert state['tasks'][0].retry_count == 3
    assert state['tasks'][0].status == 'failed'

def test_parse_nmap_output():
    sample_output = "PORT     STATE SERVICE\n80/tcp   open  http"
    ports = parse_nmap_output(sample_output)
    assert ports == [80]

def test_parse_gobuster_output():
    sample_output = "/admin (Status: 200)"
    dirs = parse_gobuster_output(sample_output)
    assert dirs == ["/admin"]