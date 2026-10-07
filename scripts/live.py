"""Official GenLayer Python SDK; stable Studionet only, Full Consensus only.
Private local account file: .private/accounts.json (never committed).
Commands: deploy, bounty, commit, reveal, adjudicate, settle, withdraw, inspect.
Persist tx IDs immediately; resume with `poll NAME` without duplicating writes.
"""
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant

ROOT=Path(__file__).resolve().parents[1]
RECORD=ROOT/'docs/live-record.json'

def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
def digest(x): return hashlib.sha256(canonical(x).encode()).hexdigest()
def load(): return json.loads(RECORD.read_text()) if RECORD.exists() else {}
def save(r): RECORD.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')

def client(role):
    accounts=json.loads((ROOT/'.private/accounts.json').read_text())
    c=create_client(chain=studionet,account=Account.from_key(accounts[role]['key']))
    assert c.chain_id==61999, 'RPC chain identity changed; refuse to sign'
    return c

def receipt(name,c):
    r=load(); tx=c.get_transaction(r['transactions'][name]['hash'])
    (ROOT/'docs/receipts').mkdir(exist_ok=True)
    (ROOT/'docs/receipts'/f'{name}.json').write_text(json.dumps(tx,indent=2,default=str)+'\n')
    r['transactions'][name]['status']=tx.get('status'); save(r)
    print(json.dumps(tx,default=str),flush=True)
    return tx

def submit(name,c,fn,args=None,value=0):
    r=load()
    if name in r.get('transactions',{}):
        print('Already submitted; poll existing ID:',r['transactions'][name]['hash'],flush=True); return
    if fn=='deploy':
        code=(ROOT/'contracts/patchbond.py').read_bytes()
        r.update(network='Studionet',chain_id=61999,rpc='https://studio.genlayer.com/api',
                 source_sha256=hashlib.sha256(code).hexdigest(),source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
        tx=c.deploy_contract(code=code,args=[],leader_only=False)
    else:
        tx=c.write_contract(address=r['contract'],function_name=fn,args=args or [],value=value,leader_only=False)
    h=tx.hex() if hasattr(tx,'hex') else str(tx)
    if not h.startswith('0x'): h='0x'+h
    r.setdefault('transactions',{})[name]={'hash':h,'submitted_at':datetime.now(timezone.utc).isoformat(),'leader_only':False}
    save(r); print('SUBMITTED',name,h,flush=True)
    receipt(name,c)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('action'); parser.add_argument('name',nargs='?'); a=parser.parse_args()
    role='developer' if a.action in ('commit','reveal','withdraw') else 'sponsor'; c=client(role); r=load()
    if a.action=='deploy': submit('deployment',c,'deploy')
    elif a.action=='poll': receipt(a.name,c)
    elif a.action=='bounty': submit('bounty',c,'create_bounty',[canonical(json.loads((ROOT/'docs/live-terms.json').read_text()))],10**15)
    elif a.action=='commit':
        p=json.loads((ROOT/'docs/live-package.json').read_text()); secrets=json.loads((ROOT/'.private/reveal.json').read_text())
        domain=json.loads(c.read_contract(r['contract'],'get_domain',transaction_hash_variant=TransactionHashVariant.LATEST_FINAL))
        h=digest(dict(protocol='patchbond/1',domain=domain,bounty='1',submitter=c.local_account.address.lower(),package=p,salt=secrets['salt']))
        submit('commitment',c,'commit_patch',['1',h],10**12)
    elif a.action=='reveal':
        p=json.loads((ROOT/'docs/live-package.json').read_text()); secrets=json.loads((ROOT/'.private/reveal.json').read_text())
        submit('reveal',c,'reveal_patch',['1:1',canonical(p),secrets['salt']])
    elif a.action=='adjudicate': submit('adjudication',c,'adjudicate',['1:1'])
    elif a.action=='settle': submit('settlement',c,'settle_reward',['1'])
    elif a.action=='withdraw': submit('withdrawal',c,'withdraw')
    elif a.action=='inspect':
        for method,args in [('get_bounty',['1']),('get_submission',['1:1']),('get_accounting',[])]:
            obj=c.read_contract(r['contract'],method,args=args,transaction_hash_variant=TransactionHashVariant.LATEST_FINAL)
            r[method]=json.loads(obj); print(method,obj,flush=True)
        r['sponsor_balance']=c.get_balance(json.loads((ROOT/'.private/accounts.json').read_text())['sponsor']['address'])
        r['developer_balance']=c.get_balance(json.loads((ROOT/'.private/accounts.json').read_text())['developer']['address'])
        save(r)
    else: raise SystemExit('unknown action')
if __name__=='__main__': main()
