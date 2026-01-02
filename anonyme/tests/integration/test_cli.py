import pytest
import subprocess
import json
import re


def extract_json(output: str) -> dict:
    """Extract JSON from output that may contain log messages and ANSI codes"""
    # Strip ANSI color codes
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    clean_output = ansi_escape.sub('', output)
    
    # Find JSON block with proper brace counting
    lines = clean_output.strip().split('\n')
    json_lines = []
    in_json = False
    brace_count = 0
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('{') and not in_json:
            in_json = True
        
        if in_json:
            json_lines.append(line)
            # Count braces to know when JSON is complete
            brace_count += stripped.count('{') - stripped.count('}')
            
            if brace_count == 0 and in_json:
                break
    
    if json_lines:
        json_str = '\n'.join(json_lines)
        return json.loads(json_str)
    
    raise ValueError("No JSON found in output")


class TestCLIInterface:
    
    def test_cli_help(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "--help"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "anonyme" in result.stdout.lower()
    
    def test_cli_version(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "--version"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "1.0.0" in result.stdout
    
    def test_cli_single_prompt_safe(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "Hello world"],
            capture_output=True,
            text=True
        )
        
        assert "ALLOW" in result.stdout
    
    def test_cli_detect_email(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "test@example.com"],
            capture_output=True,
            text=True
        )
        
        assert "BLOCK" in result.stdout
    
    def test_cli_json_output(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "Hello", "--json"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        
        data = extract_json(result.stdout)
        assert "version" in data
        assert "total_prompts" in data
        assert "results" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["action"] == "ALLOW"
    
    def test_cli_multiple_prompts(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "Hello", "test@example.com", "Safe text"],
            capture_output=True,
            text=True
        )
        
        assert "3/3" in result.stdout or "Summary: 3" in result.stdout
    
    def test_cli_verbose_mode(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "test@example.com", "--verbose"],
            capture_output=True,
            text=True
        )
        
        # In verbose mode, should show findings details
        assert "BLOCK" in result.stdout or "Email" in result.stdout
    
    def test_cli_json_structure(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "test@example.com", "--json"],
            capture_output=True,
            text=True
        )
        
        data = extract_json(result.stdout)
        assert data["total_prompts"] == 1
        result_item = data["results"][0]
        assert "prompt" in result_item
        assert "action" in result_item
        assert "risk_score" in result_item
        assert "reasons" in result_item
        assert "metadata" in result_item
    
    def test_cli_handles_special_characters(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "Test with special chars: @#$%^&*()"],
            capture_output=True,
            text=True
        )
        
        # Just verify it ran without crashing
        assert result.stdout  # Has some output
    
    def test_cli_empty_findings_json(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "Safe text", "--json"],
            capture_output=True,
            text=True
        )
        
        data = extract_json(result.stdout)
        assert data["results"][0]["reasons"] == []
        assert data["results"][0]["risk_score"] == 0.0
