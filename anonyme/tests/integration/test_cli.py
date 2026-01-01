import pytest
import subprocess
import json


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
        
        assert result.returncode == 0
        assert "ALLOW" in result.stdout
    
    def test_cli_detect_email(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "test@example.com"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "BLOCK" in result.stdout
    
    def test_cli_json_output(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", "Hello", "--json"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        
        # Parse JSON output
        data = json.loads(result.stdout)
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
        
        assert result.returncode == 0
        assert "3/3" in result.stdout or "Summary: 3" in result.stdout
    
    def test_cli_verbose_mode(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "test@example.com", "--verbose"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Email" in result.stdout
    
    def test_cli_json_structure(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "test@example.com", "--json"],
            capture_output=True,
            text=True
        )
        
        data = json.loads(result.stdout)
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
        
        assert result.returncode == 0
    
    def test_cli_empty_findings_json(self):
        result = subprocess.run(
            ["python", "-B", "-m", "anonyme.interface.cli", 
             "Safe text", "--json"],
            capture_output=True,
            text=True
        )
        
        data = json.loads(result.stdout)
        assert data["results"][0]["reasons"] == []
        assert data["results"][0]["risk_score"] == 0.0
