"""
Unit tests for automation.py changes
Tests the new functions for shadowCredentials and ACL inheritance checks
"""
import unittest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from autobloody.automation import Automation


class TestAutomationChanges(unittest.IsolatedAsyncioTestCase):
    """Test cases for the new automation functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_args = Mock()
        self.mock_args.username = "test_user"
        self.mock_args.password = "test_pass"
        self.mock_args.domain = "test.local"
        self.mock_args.host = "dc.test.local"
        
        # Create a simple path
        self.path = []
        
        # Initialize Automation object
        self.automation = Automation(self.mock_args, self.path)
    
    def test_rel_types_mapping(self):
        """Test that rel_types mapping has been updated correctly"""
        # Check that edge type 100000 is mapped to _shadowCredentialsOrForceChange
        self.assertEqual(
            self.automation.rel_types[100000].__name__,
            '_shadowCredentialsOrForceChange'
        )
        
        # Check that edge type 200 is mapped to _aclOuGpo
        self.assertEqual(
            self.automation.rel_types[200].__name__,
            '_aclOuGpo'
        )
        
        # Check that edge type 110000 still points to _forceChangePassword
        self.assertEqual(
            self.automation.rel_types[110000].__name__,
            '_forceChangePassword'
        )
    
    def test_shadowCredentialsOrForceChange_exists(self):
        """Test that _shadowCredentialsOrForceChange method exists"""
        self.assertTrue(hasattr(self.automation, '_shadowCredentialsOrForceChange'))
        self.assertTrue(callable(getattr(self.automation, '_shadowCredentialsOrForceChange')))
    
    def test_aclOuGpo_exists(self):
        """Test that _aclOuGpo method exists"""
        self.assertTrue(hasattr(self.automation, '_aclOuGpo'))
        self.assertTrue(callable(getattr(self.automation, '_aclOuGpo')))
    
    async def test_shadowCredentialsOrForceChange_simulation(self):
        """Test _shadowCredentialsOrForceChange in simulation mode"""
        # Set up simulation mode
        self.automation.simulation = True
        self.automation.rel_str = {
            "password": "[Change password] of {} to {}"
        }
        
        # Create mock relationship
        rel = {
            "end_node": {
                "name": "target_user"
            }
        }
        
        # Mock _printOperation
        self.automation._printOperation = Mock()
        
        # Call the function
        await self.automation._shadowCredentialsOrForceChange(rel)
        
        # Verify _printOperation was called
        self.automation._printOperation.assert_called_once()
    
    async def test_aclOuGpo_simulation(self):
        """Test _aclOuGpo in simulation mode"""
        # Set up simulation mode
        self.automation.simulation = True
        self.automation.rel_str = {
            "genericAll": "[GenericAll given] on {} to {}"
        }
        
        # Create mock relationship
        rel = {
            "start_node": {
                "name": "source_user"
            },
            "end_node": {
                "name": "target_ou"
            }
        }
        
        # Mock _genericAll
        self.automation._genericAll = AsyncMock()
        
        # Call the function
        await self.automation._aclOuGpo(rel)
        
        # Verify _genericAll was called
        self.automation._genericAll.assert_called_once_with(rel)


if __name__ == '__main__':
    unittest.main()
