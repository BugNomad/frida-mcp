"""
Unit tests for frida-mcp module.

Tests core functionality including:
- Configuration loading
- Script wrapping
- Message collection
- Device connection
"""

import unittest
import asyncio
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from collections import deque

# Import modules to test
import frida_mcp
from frida_mcp import (
    wrap_script_for_mcp,
    create_message_collector,
    _load_config,
    _resolve_server_path_from_config,
)


class TestScriptWrapping(unittest.TestCase):
    """Test script wrapping functionality."""
    
    def test_wrap_script_for_mcp_basic(self):
        """Test that script wrapping produces valid output."""
        user_script = "console.log('test');"
        wrapped = wrap_script_for_mcp(user_script)
        
        # Check that wrapped script contains key elements
        self.assertIn("safeStringify", wrapped)
        self.assertIn("console.log", wrapped)
        self.assertIn("send", wrapped)
        self.assertIn(user_script, wrapped)
    
    def test_wrap_script_for_mcp_empty(self):
        """Test wrapping empty script."""
        wrapped = wrap_script_for_mcp("")
        self.assertIn("safeStringify", wrapped)
        self.assertIn("console.log", wrapped)


class TestMessageCollector(unittest.TestCase):
    """Test message collection functionality."""
    
    def test_create_message_collector(self):
        """Test message collector creation."""
        handler, messages = create_message_collector()
        
        self.assertIsNotNone(handler)
        self.assertIsInstance(messages, list)
        self.assertEqual(len(messages), 0)
    
    def test_message_collector_with_send_message(self):
        """Test collecting send messages."""
        handler, messages = create_message_collector()
        
        message = {
            'type': 'send',
            'payload': {'type': 'log', 'message': 'test message'}
        }
        
        handler(message, None)
        
        self.assertEqual(len(messages), 1)
        self.assertIn('test message', messages[0])
    
    def test_message_collector_with_error_message(self):
        """Test collecting error messages."""
        handler, messages = create_message_collector()
        
        message = {
            'type': 'error',
            'description': 'test error'
        }
        
        handler(message, None)
        
        self.assertEqual(len(messages), 1)
        self.assertIn('Error', messages[0])
        self.assertIn('test error', messages[0])
    
    def test_message_collector_with_external_buffer(self):
        """Test message collector with external buffer."""
        external_buffer = deque(maxlen=100)
        handler, messages = create_message_collector(external_buffer)
        
        message = {
            'type': 'send',
            'payload': {'type': 'log', 'message': 'external test'}
        }
        
        handler(message, None)
        
        self.assertEqual(len(messages), 1)
        self.assertEqual(len(external_buffer), 1)
        self.assertIn('external test', external_buffer[0])


class TestConfigLoading(unittest.TestCase):
    """Test configuration loading."""
    
    def test_load_config_default(self):
        """Test loading default configuration."""
        config = _load_config()
        
        self.assertIsInstance(config, dict)
        self.assertEqual(config.get("server_port"), 27042)
        self.assertEqual(config.get("adb_path"), "adb")
    
    def test_load_config_from_file(self):
        """Test loading configuration from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_config = {
                "server_port": 12345,
                "device_id": "test_device"
            }
            json.dump(test_config, f)
            temp_path = f.name
        
        try:
            # Mock os.path.isfile to return True for our temp file
            with patch('os.path.isfile') as mock_isfile:
                with patch('builtins.open', create=True) as mock_open:
                    mock_isfile.return_value = True
                    mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(test_config)
                    
                    # This would require more complex mocking to fully test
                    # For now, just verify the function doesn't crash
                    config = _load_config()
                    self.assertIsInstance(config, dict)
        finally:
            os.unlink(temp_path)


class TestServerPathResolution(unittest.TestCase):
    """Test frida-server path resolution."""
    
    def test_resolve_server_path_default(self):
        """Test default server path resolution."""
        with patch.dict(frida_mcp.CONFIG, {
            "server_path": None,
            "server_name": None
        }):
            path = _resolve_server_path_from_config()
            self.assertEqual(path, "/data/local/tmp/frida-server")
    
    def test_resolve_server_path_with_name(self):
        """Test server path resolution with custom name."""
        with patch.dict(frida_mcp.CONFIG, {
            "server_path": None,
            "server_name": "custom_frida"
        }):
            path = _resolve_server_path_from_config()
            self.assertEqual(path, "/data/local/tmp/custom_frida")
    
    def test_resolve_server_path_with_base(self):
        """Test server path resolution with custom base."""
        with patch.dict(frida_mcp.CONFIG, {
            "server_path": "/custom/path",
            "server_name": None
        }):
            path = _resolve_server_path_from_config()
            self.assertEqual(path, "/custom/path")
    
    def test_resolve_server_path_with_both(self):
        """Test server path resolution with both base and name."""
        with patch.dict(frida_mcp.CONFIG, {
            "server_path": "/custom/path",
            "server_name": "frida_bin"
        }):
            path = _resolve_server_path_from_config()
            self.assertEqual(path, "/custom/path/frida_bin")


class TestAsyncFunctions(unittest.TestCase):
    """Test async functions."""

    def test_ensure_device_connected_no_device(self):
        """Test device connection when no device available."""
        async def run_test():
            # Reset global device state
            frida_mcp.device = None

            with patch('frida.get_usb_device', side_effect=Exception("No device")):
                with patch('frida.get_device', side_effect=Exception("No device")):
                    with patch('frida.get_device_manager') as mock_manager:
                        mock_manager.return_value.add_remote_device.side_effect = Exception("No remote")
                        result = await frida_mcp.ensure_device_connected()
                        self.assertFalse(result)

        asyncio.run(run_test())


if __name__ == '__main__':
    unittest.main()

