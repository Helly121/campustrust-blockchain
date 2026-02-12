import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class WalletFeaturesTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test'
        self.app = app.test_client()
        
    def test_wallet_page_access(self):
        response = self.app.get('/wallet')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Campus Wallet', response.data)

    @patch('app.send_algo_payment')
    def test_wallet_pay(self, mock_pay):
        mock_pay.return_value = {'success': True, 'tx_id': 'TEST_TX_ID'}
        
        response = self.app.post('/wallet/pay', data={
            'receiver': 'TEST_ADDR', 
            'amount': '1.0',
            'note': 'Test Note'
        }, follow_redirects=True)
        
        self.assertIn(b'Payment Sent!', response.data)
        self.assertIn(b'TEST_TX_ID', response.data)
        mock_pay.assert_called_with('TEST_ADDR', '1.0', 'Test Note')

    @patch('app.create_asa')
    def test_wallet_create_asset(self, mock_create):
        mock_create.return_value = {'success': True, 'tx_id': 'TX_ID', 'asset_id': 123}
        
        response = self.app.post('/wallet/create_asset', data={
            'unit_name': 'TEST', 
            'asset_name': 'Test Coin',
            'total': '100',
            'decimals': '0'
        }, follow_redirects=True)
        
        self.assertIn(b'Asset Created!', response.data)
        self.assertIn(b'123', response.data)

    @patch('app.mint_nft')
    def test_wallet_mint_nft(self, mock_mint):
        mock_mint.return_value = {'success': True, 'tx_id': 'TX_ID', 'asset_id': 456}
        
        response = self.app.post('/wallet/mint_nft', data={
            'unit_name': 'NFT', 
            'asset_name': 'Test NFT',
            'ipfs_url': 'ipfs://test'
        }, follow_redirects=True)
        
        self.assertIn(b'NFT Minted!', response.data)

    @patch('app.deploy_smart_contract')
    def test_wallet_contract_deploy(self, mock_deploy):
        # We need to mock the approval_program/clear_state_program imports in app, 
        # but since they are imported at top level, simply mocking the deploy function might be enough
        # provided app.py doesn't crash on import if pyteal is missing.
        # However, the route checks `if not approval_program`.
        # So we need to ensure app.approval_program is not None for this test to reach deploy.
        
        with patch('app.approval_program', MagicMock()), \
             patch('app.clear_state_program', MagicMock()):
            
            mock_deploy.return_value = {'success': True, 'tx_id': 'TX_ID', 'app_id': 789}
            
            response = self.app.post('/wallet/contract/deploy', follow_redirects=True)
            self.assertIn(b'Contract Deployed!', response.data)
            self.assertIn(b'789', response.data)

    @patch('app.call_bank_deposit')
    def test_wallet_contract_deposit(self, mock_deposit):
        mock_deposit.return_value = {'success': True, 'tx_id': 'TX_ID'}
        
        response = self.app.post('/wallet/contract/interact', data={
            'app_id': '789',
            'action': 'deposit',
            'amount': '1.0'
        }, follow_redirects=True)
        
        self.assertIn(b'Action DEPOSIT Successful!', response.data)

    @patch('app.get_contract_history')
    def test_wallet_contract_history(self, mock_history):
        mock_history.return_value = {
            'success': True, 
            'history': [{'round': 100, 'action': 'Deposit', 'amount': 10, 'user': 'User1', 'tx_id': 'TX1'}]
        }
        
        response = self.app.post('/wallet/contract/history', data={'app_id': '789'})
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Deposit', response.data)
        self.assertIn(b'User1', response.data)

if __name__ == '__main__':
    unittest.main()
