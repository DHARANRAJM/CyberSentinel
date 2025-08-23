import logging
import sys
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

class CyberSentinelLogger:
    """Logger class for CyberSentinel with colored console output"""
    
    def __init__(self, name="CyberSentinel", log_file="cybersentinel.log"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def info(self, message):
        """Log info message with green [+] prefix"""
        self.logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def warning(self, message):
        """Log warning message with yellow [!] prefix"""
        self.logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def error(self, message):
        """Log error message with red [-] prefix"""
        self.logger.error(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    def critical(self, message):
        """Log critical message with magenta [!!] prefix"""
        self.logger.critical(f"{Fore.MAGENTA}[!!]{Style.RESET_ALL} {message}")
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")
    
    def scan_start(self, target):
        """Log scan start with special formatting"""
        self.info(f"Starting vulnerability scan for target: {Fore.CYAN}{target}{Style.RESET_ALL}")
    
    def scan_complete(self, target, duration):
        """Log scan completion with special formatting"""
        self.info(f"Scan completed for {Fore.CYAN}{target}{Style.RESET_ALL} in {duration:.2f} seconds")
    
    def vulnerability_found(self, vuln_type, severity, details=""):
        """Log vulnerability finding with severity-based coloring"""
        severity_colors = {
            'Critical': Fore.MAGENTA,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN
        }
        color = severity_colors.get(severity, Fore.WHITE)
        prefix = "[!!]" if severity == "Critical" else "[!]"
        self.logger.warning(f"{color}{prefix}{Style.RESET_ALL} {vuln_type} - {color}{severity} Risk{Style.RESET_ALL}")
        if details:
            self.logger.info(f"    Details: {details}")

# Global logger instance
logger = CyberSentinelLogger()
