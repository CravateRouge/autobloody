"""
Unit tests for optional domain and username arguments in main.py
"""
import unittest
from unittest.mock import Mock, AsyncMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from autobloody.main import run_autobloody


class TestOptionalArgs(unittest.IsolatedAsyncioTestCase):
    """Test cases for optional domain and username parameters"""
    
    async def test_domain_and_username_from_path_dict(self):
        """Test that domain and username are extracted from path_dict when not provided"""
        # Create mock args without domain and username
        mock_args = Mock()
        mock_args.domain = None
        mock_args.username = None
        mock_args.yes = True
        
        # Create mock path_dict with domain and samaccountname in first node
        path_dict = [
            {
                "start_node": {
                    "name": "TEST.USER@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "samaccountname": "test.user",
                    "distinguishedname": "CN=Test User,DC=test,DC=local",
                    "objectid": "S-1-5-21-123456789-123456789-123456789-1234"
                },
                "end_node": {
                    "name": "TARGET.USER@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "samaccountname": "target.user",
                    "distinguishedname": "CN=Target User,DC=test,DC=local",
                    "objectid": "S-1-5-21-123456789-123456789-123456789-5678"
                },
                "cost": 0
            }
        ]
        
        # Mock pathgen to return our test path_dict
        with patch('autobloody.main.pathgen', new_callable=AsyncMock) as mock_pathgen:
            mock_pathgen.return_value = path_dict
            
            # Mock automation.Automation to avoid actual instantiation
            with patch('autobloody.main.automation.Automation') as mock_automation:
                mock_auto_instance = Mock()
                mock_auto_instance.exploit = AsyncMock()
                mock_automation.return_value = mock_auto_instance
                
                # Run the function
                await run_autobloody(mock_args)
                
                # Verify that domain and username were set from path_dict
                self.assertEqual(mock_args.domain, "TEST.LOCAL")
                self.assertEqual(mock_args.username, "test.user")
    
    async def test_domain_and_username_preserved_when_provided(self):
        """Test that provided domain and username are not overwritten"""
        # Create mock args with domain and username already set
        mock_args = Mock()
        mock_args.domain = "PROVIDED.DOMAIN"
        mock_args.username = "provided.user"
        mock_args.yes = True
        
        # Create mock path_dict with different values
        path_dict = [
            {
                "start_node": {
                    "name": "TEST.USER@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "samaccountname": "test.user",
                    "distinguishedname": "CN=Test User,DC=test,DC=local",
                    "objectid": "S-1-5-21-123456789-123456789-123456789-1234"
                },
                "end_node": {
                    "name": "TARGET.USER@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "samaccountname": "target.user",
                    "distinguishedname": "CN=Target User,DC=test,DC=local",
                    "objectid": "S-1-5-21-123456789-123456789-123456789-5678"
                },
                "cost": 0
            }
        ]
        
        # Mock pathgen to return our test path_dict
        with patch('autobloody.main.pathgen', new_callable=AsyncMock) as mock_pathgen:
            mock_pathgen.return_value = path_dict
            
            # Mock automation.Automation to avoid actual instantiation
            with patch('autobloody.main.automation.Automation') as mock_automation:
                mock_auto_instance = Mock()
                mock_auto_instance.exploit = AsyncMock()
                mock_automation.return_value = mock_auto_instance
                
                # Run the function
                await run_autobloody(mock_args)
                
                # Verify that provided domain and username were preserved
                self.assertEqual(mock_args.domain, "PROVIDED.DOMAIN")
                self.assertEqual(mock_args.username, "provided.user")
    
    async def test_empty_path_dict_does_not_crash(self):
        """Test that empty path_dict doesn't cause crashes"""
        # Create mock args without domain and username
        mock_args = Mock()
        mock_args.domain = None
        mock_args.username = None
        mock_args.yes = True
        
        # Empty path_dict
        path_dict = []
        
        # Mock pathgen to return empty path_dict
        with patch('autobloody.main.pathgen', new_callable=AsyncMock) as mock_pathgen:
            mock_pathgen.return_value = path_dict
            
            # Mock automation.Automation to avoid actual instantiation
            with patch('autobloody.main.automation.Automation') as mock_automation:
                mock_auto_instance = Mock()
                mock_auto_instance.exploit = AsyncMock()
                mock_automation.return_value = mock_auto_instance
                
                # Run the function - should not crash
                await run_autobloody(mock_args)
                
                # Domain and username should remain None
                self.assertIsNone(mock_args.domain)
                self.assertIsNone(mock_args.username)


if __name__ == '__main__':
    unittest.main()
