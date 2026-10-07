"""Read-only assertions against a recorded finalized Full Consensus run."""
import hashlib, json
from pathlib import Path
import pytest
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant

def test_finalized_live_contract():
    record=Path('docs/live-record.json')
    if not record.exists(): pytest.skip('No observed deployment record')
    r=json.loads(record.read_text())
    if not r.get('verified_complete'): pytest.skip('Live verification not complete')
    c=create_client(chain=studionet,account=Account.create())
    assert c.chain_id==61999
    a=json.loads(c.read_contract(r['contract'],'get_accounting',args=[],transaction_hash_variant=TransactionHashVariant.LATEST_FINAL))
    assert a['escrow']==0 and a['claimable']==0 and a['funded']==a['emitted'] and a['balance']==0
    s=json.loads(c.read_contract(r['contract'],'get_submission',args=['1:1'],transaction_hash_variant=TransactionHashVariant.LATEST_FINAL))
    assert s['state']=='SETTLED' and s['result']['judgment']['outcome']=='ACCEPTED'
    assert s['decision_hash']==r['get_submission']['decision_hash']
    assert hashlib.sha256(Path('contracts/patchbond.py').read_bytes()).hexdigest()==r['source_sha256']
