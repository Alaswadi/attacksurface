"""
Base scanner class for security tools integration
"""

import subprocess
import json
import logging
import os
import tempfile
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ToolNotFoundError(BaseScannerError):
    """Raised when a security tool is not found"""
    pass

class ScanTimeoutError(BaseScannerError):
    """Raised when a scan times out"""
    pass

class BaseScanner(ABC):
    """Base class for all security scanners"""
    
    def __init__(self, tool_name: str, tool_path: Optional[str] = None):
        self.tool_name = tool_name
        self.tool_path = tool_path or self._find_tool()
        self.timeout = 300  # 5 minutes default timeout
        
    def _find_tool(self) -> str:
        """Find the tool executable in PATH"""
        import shutil
        import os

        # Prefer /usr/local/bin/ over other locations for better permissions
        preferred_path = f"/usr/local/bin/{self.tool_name}"
        if os.path.isfile(preferred_path) and os.access(preferred_path, os.X_OK):
            logger.info(f"Found {self.tool_name} at preferred location: {preferred_path}")
            return preferred_path

        # Fallback to PATH search
        tool_path = shutil.which(self.tool_name)
        if not tool_path:
            raise ToolNotFoundError(f"{self.tool_name} not found in PATH or /usr/local/bin/")

        logger.info(f"Found {self.tool_name} at: {tool_path}")
        return tool_path
    
    def _run_command(self, cmd: List[str], input_data: Optional[str] = None) -> Dict[str, Any]:
        """Run a command and return the result"""
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                text=True,
                timeout=self.timeout
            )
            
            stdout, stderr = process.communicate(input=input_data)
            
            return {
                'returncode': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'success': process.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            raise ScanTimeoutError(f"{self.tool_name} scan timed out after {self.timeout} seconds")
        except Exception as e:
            raise BaseScannerError(f"Error running {self.tool_name}: {str(e)}")
    
    def _create_temp_file(self, content: str, suffix: str = '.txt') -> str:
        """Create a temporary file with content"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            return f.name
    
    def _cleanup_temp_file(self, filepath: str):
        """Clean up temporary file"""
        try:
            os.unlink(filepath)
        except OSError:
            pass
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform the scan - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse tool output - must be implemented by subclasses"""
        pass
    
    def is_available(self) -> bool:
        """Check if the tool is available"""
        try:
            result = self._run_command([self.tool_path, '-h'])
            logger.info(f"{self.tool_name} availability check: returncode={result['returncode']}, success={result['success']}")
            if result['stderr']:
                logger.info(f"{self.tool_name} stderr: {result['stderr']}")
            return result['success'] or result['returncode'] in [0, 1]  # Some tools return 1 for help
        except Exception as e:
            logger.error(f"{self.tool_name} availability check failed: {str(e)}")
            return False
    
    def get_version(self) -> str:
        """Get tool version"""
        try:
            result = self._run_command([self.tool_path, '-version'])
            if result['success']:
                return result['stdout'].strip()
            return "Unknown"
        except:
            return "Unknown"
