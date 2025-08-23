#!/usr/bin/env python3

"""
CyberSentinel Pro - Endpoint Agent
Minimal agent implementation for Phase 1
Author: CyberSentinel Team
Version: 2.0
"""

import asyncio
import json
import logging
import platform
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import yaml
import psutil
import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberSentinelAgent:
    """CyberSentinel Pro endpoint agent"""
    
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.agent_id = uuid.UUID(self.config.get('agent_id', str(uuid.uuid4())))
        self.api_url = self.config['api_url']
        self.api_key = self.config['api_key']
        self.collectors = self.config.get('collectors', {})
        self.intervals = self.config.get('intervals', {})
        self.buffer_max = self.config.get('buffer_max', 1000)
        
        # Initialize HTTP client
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                'X-API-Key': self.api_key,
                'User-Agent': f'CyberSentinel-Agent/2.0 ({platform.system()})'
            }
        )
        
        # Event buffer for offline resilience
        self.event_buffer: List[Dict[str, Any]] = []
        self.finding_buffer: List[Dict[str, Any]] = []
        
        # System info
        self.hostname = platform.node()
        self.os_type = platform.system().lower()
        self.os_version = platform.release()
        self.ip_address = self.get_local_ip()
        self.version = "2.0.0"
        
        logger.info(f"Agent initialized: {self.agent_id}")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    async def send_heartbeat(self) -> bool:
        """Send heartbeat to API"""
        try:
            heartbeat_data = {
                "agent_id": str(self.agent_id),
                "hostname": self.hostname,
                "os_type": self.os_type,
                "os_version": self.os_version,
                "ip_address": self.ip_address,
                "version": self.version,
                "config": {
                    "collectors": self.collectors,
                    "intervals": self.intervals
                }
            }
            
            response = await self.client.post(
                f"{self.api_url}/ingest/heartbeat",
                json=heartbeat_data
            )
            
            if response.status_code == 200:
                logger.info("Heartbeat sent successfully")
                return True
            else:
                logger.error(f"Heartbeat failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return False
    
    async def collect_port_snapshot(self) -> List[Dict[str, Any]]:
        """Collect current port information"""
        events = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            listening_ports = []
            
            for conn in connections:
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'pid': conn.pid
                    }
                    listening_ports.append(port_info)
            
            # Create port snapshot event
            event = {
                'agent_id': str(self.agent_id),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'port.snapshot',
                'severity': 1,
                'source': 'port_collector',
                'payload': {
                    'listening_ports': listening_ports,
                    'total_ports': len(listening_ports)
                }
            }
            
            events.append(event)
            logger.info(f"Collected {len(listening_ports)} listening ports")
            
        except Exception as e:
            logger.error(f"Port collection error: {e}")
            
            # Create error event
            error_event = {
                'agent_id': str(self.agent_id),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'collector.error',
                'severity': 3,
                'source': 'port_collector',
                'payload': {
                    'error': str(e),
                    'collector': 'port_snapshot'
                }
            }
            events.append(error_event)
        
        return events
    
    async def collect_process_snapshot(self) -> List[Dict[str, Any]]:
        """Collect current process information"""
        events = []
        
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            # Create process snapshot event
            event = {
                'agent_id': str(self.agent_id),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'process.snapshot',
                'severity': 1,
                'source': 'process_collector',
                'payload': {
                    'processes': processes[:50],  # Top 50 processes
                    'total_processes': len(processes)
                }
            }
            
            events.append(event)
            logger.info(f"Collected {len(processes)} processes")
            
        except Exception as e:
            logger.error(f"Process collection error: {e}")
            
            # Create error event
            error_event = {
                'agent_id': str(self.agent_id),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'collector.error',
                'severity': 3,
                'source': 'process_collector',
                'payload': {
                    'error': str(e),
                    'collector': 'process_snapshot'
                }
            }
            events.append(error_event)
        
        return events
    
    async def send_events(self, events: List[Dict[str, Any]]) -> bool:
        """Send events to API"""
        if not events:
            return True
        
        try:
            response = await self.client.post(
                f"{self.api_url}/ingest/events",
                json=events
            )
            
            if response.status_code == 201:
                logger.info(f"Sent {len(events)} events successfully")
                return True
            else:
                logger.error(f"Failed to send events: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending events: {e}")
            return False
    
    async def run_collector(self, collector_name: str):
        """Run a specific collector"""
        if collector_name == 'ports' and self.collectors.get('ports', False):
            events = await self.collect_port_snapshot()
            self.event_buffer.extend(events)
        
        elif collector_name == 'processes' and self.collectors.get('processes', False):
            events = await self.collect_process_snapshot()
            self.event_buffer.extend(events)
        
        # Add more collectors here as they're implemented
    
    async def flush_buffers(self):
        """Send buffered events to API"""
        if self.event_buffer:
            success = await self.send_events(self.event_buffer)
            if success:
                self.event_buffer.clear()
            elif len(self.event_buffer) > self.buffer_max:
                # Remove oldest events if buffer is full
                self.event_buffer = self.event_buffer[-self.buffer_max//2:]
                logger.warning("Event buffer overflow, removed oldest events")
    
    async def run(self):
        """Main agent loop"""
        logger.info("Starting CyberSentinel Pro Agent...")
        
        # Send initial heartbeat
        await self.send_heartbeat()
        
        # Main collection loop
        last_heartbeat = time.time()
        last_port_collection = 0
        last_process_collection = 0
        
        heartbeat_interval = 60  # 1 minute
        port_interval = self.intervals.get('ports', 300)  # 5 minutes
        process_interval = self.intervals.get('processes', 300)  # 5 minutes
        
        try:
            while True:
                current_time = time.time()
                
                # Send heartbeat
                if current_time - last_heartbeat >= heartbeat_interval:
                    await self.send_heartbeat()
                    last_heartbeat = current_time
                
                # Collect ports
                if current_time - last_port_collection >= port_interval:
                    await self.run_collector('ports')
                    last_port_collection = current_time
                
                # Collect processes
                if current_time - last_process_collection >= process_interval:
                    await self.run_collector('processes')
                    last_process_collection = current_time
                
                # Flush event buffer
                await self.flush_buffers()
                
                # Sleep for a short interval
                await asyncio.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("Agent stopped by user")
        except Exception as e:
            logger.error(f"Agent error: {e}")
        finally:
            # Final buffer flush
            await self.flush_buffers()
            await self.client.aclose()
            logger.info("Agent shutdown complete")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='CyberSentinel Pro Agent')
    parser.add_argument('--config', '-c', default='config.yaml', 
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    try:
        agent = CyberSentinelAgent(args.config)
        await agent.run()
    except Exception as e:
        logger.error(f"Failed to start agent: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))
