"""
Unit test for samaccountname property in path nodes
Tests that the pathgen function includes samaccountname in node properties
"""
import unittest
from unittest.mock import Mock, MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from autobloody import main


class TestSamAccountName(unittest.IsolatedAsyncioTestCase):
    """Test cases for samaccountname property in path nodes"""
    
    async def test_pathgen_includes_samaccountname(self):
        """Test that pathgen includes samaccountname for both start_node and end_node"""
        # Create mock args
        mock_args = Mock()
        mock_args.dburi = "bolt://localhost:7687"
        mock_args.dbuser = "neo4j"
        mock_args.dbpassword = "password"
        mock_args.dbsource = "USER1@DOMAIN.LOCAL"
        mock_args.dbtarget = "DOMAIN.LOCAL"
        
        # Create mock relationship with samaccountname
        mock_rel = Mock()
        mock_rel.start_node = {
            "name": "USER1@DOMAIN.LOCAL",
            "distinguishedname": "CN=User1,CN=Users,DC=domain,DC=local",
            "objectid": "S-1-5-21-123456789-1234567890-123456789-1001",
            "samaccountname": "user1"
        }
        mock_rel.end_node = {
            "name": "GROUP1@DOMAIN.LOCAL",
            "distinguishedname": "CN=Group1,CN=Groups,DC=domain,DC=local",
            "objectid": "S-1-5-21-123456789-1234567890-123456789-1002",
            "samaccountname": "group1"
        }
        mock_rel.__getitem__ = lambda self, key: 100 if key == "cost" else None
        
        # Mock database
        with patch('autobloody.main.database.Database') as mock_db_class, \
             patch('autobloody.main.proxy_bypass.ProxyBypass') as mock_bypass_class:
            
            mock_db = Mock()
            mock_db.getPrivescPath.return_value = [mock_rel]
            mock_db.close = Mock()
            mock_db_class.return_value = mock_db
            
            mock_bypass = Mock()
            mock_bypass.disable = Mock()
            mock_bypass_class.return_value = mock_bypass
            
            # Call pathgen
            result = await main.pathgen(mock_args)
            
            # Verify that samaccountname is included in the result
            self.assertEqual(len(result), 1)
            self.assertIn("samaccountname", result[0]["start_node"])
            self.assertIn("samaccountname", result[0]["end_node"])
            self.assertEqual(result[0]["start_node"]["samaccountname"], "user1")
            self.assertEqual(result[0]["end_node"]["samaccountname"], "group1")
    
    async def test_pathgen_handles_missing_samaccountname(self):
        """Test that pathgen handles nodes without samaccountname property"""
        # Create mock args
        mock_args = Mock()
        mock_args.dburi = "bolt://localhost:7687"
        mock_args.dbuser = "neo4j"
        mock_args.dbpassword = "password"
        mock_args.dbsource = "USER1@DOMAIN.LOCAL"
        mock_args.dbtarget = "DOMAIN.LOCAL"
        
        # Create mock relationship without samaccountname
        mock_rel = Mock()
        mock_rel.start_node = {
            "name": "USER1@DOMAIN.LOCAL",
            "distinguishedname": "CN=User1,CN=Users,DC=domain,DC=local",
            "objectid": "S-1-5-21-123456789-1234567890-123456789-1001"
        }
        mock_rel.end_node = {
            "name": "GROUP1@DOMAIN.LOCAL",
            "distinguishedname": "CN=Group1,CN=Groups,DC=domain,DC=local",
            "objectid": "S-1-5-21-123456789-1234567890-123456789-1002"
        }
        mock_rel.__getitem__ = lambda self, key: 100 if key == "cost" else None
        
        # Mock database
        with patch('autobloody.main.database.Database') as mock_db_class, \
             patch('autobloody.main.proxy_bypass.ProxyBypass') as mock_bypass_class:
            
            mock_db = Mock()
            mock_db.getPrivescPath.return_value = [mock_rel]
            mock_db.close = Mock()
            mock_db_class.return_value = mock_db
            
            mock_bypass = Mock()
            mock_bypass.disable = Mock()
            mock_bypass_class.return_value = mock_bypass
            
            # Call pathgen - should not raise an error
            result = await main.pathgen(mock_args)
            
            # Verify that samaccountname is included with empty string default
            self.assertEqual(len(result), 1)
            self.assertIn("samaccountname", result[0]["start_node"])
            self.assertIn("samaccountname", result[0]["end_node"])
            self.assertEqual(result[0]["start_node"]["samaccountname"], "")
            self.assertEqual(result[0]["end_node"]["samaccountname"], "")


if __name__ == '__main__':
    unittest.main()
