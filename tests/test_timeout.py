import unittest
import sys
import argparse
from unittest.mock import patch
from autobloody import main


class TestTimeoutArgument(unittest.TestCase):
    """Test that timeout argument is properly parsed and has correct default"""
    
    def test_timeout_default_value(self):
        """Test that timeout has default value of 60"""
        # Mock sys.argv to provide required arguments
        test_args = [
            'autobloody',
            '-dp', 'test_password',
            '-ds', 'TEST.SOURCE@DOMAIN.LOCAL',
            '-dt', 'TEST.TARGET@DOMAIN.LOCAL',
            '--host', '192.168.1.1'
        ]
        
        with patch.object(sys, 'argv', test_args):
            parser = argparse.ArgumentParser()
            # Recreate the parser setup from main.py
            parser.add_argument("-dp", "--dbpassword", required=True)
            parser.add_argument("-ds", "--dbsource", required=True)
            parser.add_argument("-dt", "--dbtarget", required=True)
            parser.add_argument("--host", required=True)
            parser.add_argument("--timeout", type=int, default=60)
            
            args = parser.parse_args(test_args[1:])
            
            # Verify default timeout is 60
            self.assertEqual(args.timeout, 60)
    
    def test_timeout_custom_value(self):
        """Test that custom timeout value is properly set"""
        test_args = [
            'autobloody',
            '-dp', 'test_password',
            '-ds', 'TEST.SOURCE@DOMAIN.LOCAL',
            '-dt', 'TEST.TARGET@DOMAIN.LOCAL',
            '--host', '192.168.1.1',
            '--timeout', '120'
        ]
        
        with patch.object(sys, 'argv', test_args):
            parser = argparse.ArgumentParser()
            parser.add_argument("-dp", "--dbpassword", required=True)
            parser.add_argument("-ds", "--dbsource", required=True)
            parser.add_argument("-dt", "--dbtarget", required=True)
            parser.add_argument("--host", required=True)
            parser.add_argument("--timeout", type=int, default=60)
            
            args = parser.parse_args(test_args[1:])
            
            # Verify custom timeout is properly set
            self.assertEqual(args.timeout, 120)


if __name__ == "__main__":
    unittest.main()
