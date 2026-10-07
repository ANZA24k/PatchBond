import copy, hashlib, json, random, re, sys
from datetime import datetime, timezone
import pytest
BASE='a'*40
CANDIDATE='b'*40
SALT='c'*64
NONCE='d'*64
START=1800000000

def warp(vm,s): vm.warp(datetime.fromtimestamp(s,timezone.utc).isoformat())
def terms():
    return dict(repository='https://github.com/anza24k/patchbond',base_commit=BASE,title='Fix clamp',
        specification='Inclusive clamp; reversed bounds raise ValueError.',acceptance_criteria=['Clamp correctly','Reject reversed bounds'],
        expected_behavior='Exact integer behavior',required_tests=['fixtures/live_patch/test_clamp.py'],recommended_tests=[],
        toolchain='Python 3.12; static review permitted',allowed_scope=['fixtures/live_patch'],allowed_deviations='Regression tests',
        disallowed_deviations='Unrelated changes',forbidden_paths=['contracts'],security_constraints='No networking',
        compatibility_constraints='Keep signature',documentation_requirements='Committed report',max_changed_files=12,
        max_evidence=24,max_source_bytes=16384,max_submissions=8,deadline=START+1000,bond=7)

@pytest.fixture
def setup(direct_vm,direct_deploy):
    warp(direct_vm,START)
    c=direct_deploy('contracts/patchbond.py',sdk_version='v0.2.16')
    from genlayer import Address
    direct_vm.sender=Address(direct_vm.sender)
    direct_vm.strict_mocks=True; direct_vm.check_pickling=True
    m=sys.modules[c.__class__.__module__]
    direct_vm.value=100; bid=c.create_bounty(json.dumps(terms())); direct_vm.value=0
    return direct_vm,c,m,bid

def make_package(c,m,bid='1'):
    bodies={('base','fixtures/live_patch/clamp.py'):b'def clamp(x,low,high): return x\n',
            ('candidate','fixtures/live_patch/clamp.py'):b'def clamp(x,low,high):\n    if low>high: raise ValueError()\n    return max(low,min(x,high))\n',
            ('candidate','fixtures/live_patch/test_clamp.py'):b'from clamp import clamp\nassert clamp(10,0,5)==5\n'}
    def manifest():
        return sorted([dict(revision=r,path=p,sha256=hashlib.sha256(b).hexdigest(),bytes=len(b)) for (r,p),b in bodies.items()],key=lambda x:(x['revision'],x['path']))
    att=dict(protocol=m.PROTOCOL,domain=json.loads(c.get_domain()),bounty=bid,submitter=c._direct(),
        requirements_hash=json.loads(c.get_bounty(bid))['requirements_hash'],base_commit=BASE,nonce=NONCE,payload_hash=m.digest(manifest()))
    bodies[('candidate',m.ATTESTATION)]=m.canonical(att).encode()
    return dict(candidate_commit=CANDIDATE,nonce=NONCE,evidence=manifest()),bodies

def mock_evidence(vm,p,bodies,mutate=None):
    for revision,sha,root in [('base',BASE,'e'*40),('candidate',CANDIDATE,'f'*40)]:
        commit=dict(sha=sha,tree={'sha':root},parents=[] if revision=='base' else [{'sha':BASE}])
        entries=[dict(path=path,sha=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),mode='100644',type='blob') for (r,path),b in bodies.items() if r==revision]
        tree=dict(sha=root,truncated=False,tree=entries)
        if mutate: mutate(revision,commit,tree)
        vm.mock_web(re.escape('https://api.github.com/repos/anza24k/patchbond/git/commits/'+sha)+'$',{'status':200,'body':json.dumps(commit)})
        vm.mock_web(re.escape('https://api.github.com/repos/anza24k/patchbond/git/trees/'+root+'?recursive=1')+'$',{'status':200,'body':json.dumps(tree)})
    for (r,path),b in bodies.items():
        vm.mock_web(re.escape('https://raw.githubusercontent.com/anza24k/patchbond/'+(BASE if r=='base' else CANDIDATE)+'/'+path)+'$',{'status':200,'body':b})

def judgment(p,outcome='ACCEPTED'):
    return dict(outcome=outcome,reasoning='Implementation and tests satisfy the criteria.',acceptance_score=95,
        test_evidence_score=95,scope_compliance_score=95,evidence_quality_score=95,security_risk='LOW',
        requirements_satisfied=[0,1] if outcome=='ACCEPTED' else [],requirements_failed=[0,1] if outcome=='REJECTED' else [],
        material_issues=[] if outcome=='ACCEPTED' else ['Insufficient'],material_deviations=[],
        citations=['https://raw.githubusercontent.com/anza24k/patchbond/'+CANDIDATE+'/'+p['evidence'][-1]['path']])

def reveal(setup,package=None):
    vm,c,m,bid=setup; p,bodies=package or make_package(c,m,bid)
    vm.value=7; sid=c.commit_patch(bid,m.commitment_hash(json.loads(c.get_domain()),bid,c._direct(),p,SALT)); vm.value=0
    warp(vm,START+1); c.reveal_patch(sid,json.dumps(p),SALT)
    return sid,p,bodies

def credit(c,account):
    from genlayer import Address
    return c.get_credit(account if isinstance(account,Address) else Address(account))

def invariant(c):
    a=json.loads(c.get_accounting()); assert a['funded']==a['escrow']+a['claimable']+a['emitted']

def test_creation_hash_immutability(setup):
    vm,c,m,bid=setup; b=json.loads(c.get_bounty(bid))
    assert b['reward']==100 and b['state']=='LOCKED'
    assert b['requirements_hash']==m.digest(dict(reversed(list(terms().items()))))
    assert not hasattr(c,'update_terms') and not hasattr(c,'cancel_bounty'); invariant(c)

def test_zero_funding_json(setup):
    vm,c,_,_=setup
    with vm.expect_revert('positive funding'): c.create_bounty(json.dumps(terms()))
    vm.value=1
    for s in ['{"bond":1,"bond":2}','{','[]','x'*24001]:
        with vm.expect_revert(): c.create_bounty(s)

@pytest.mark.parametrize('field,value',[
 ('deadline',START),('deadline',START+59),('deadline',START+31*86400),('bond',-1),('bond',True),
 ('base_commit','main'),('base_commit','A'*40),('base_commit','a'*39),
 ('repository','https://github.com/anza24k/patchbond/tree/main'),('repository','http://github.com/anza24k/patchbond'),
 ('repository','https://user:pass@github.com/anza24k/patchbond'),('repository','https://github.com:443/anza24k/patchbond'),
 ('repository','https://github.com/anza24k/patchbond#x'),('repository','https://github.com/anza24k/patchbond?x=1'),
 ('repository','https://127.0.0.1/anza24k/patchbond'),('repository','https://localhost/anza24k/patchbond'),
 ('repository','https://10.0.0.1/anza24k/patchbond'),('repository','https://github.com./anza24k/patchbond'),
 ('repository','https://github.com/anza24k/%70atchbond'),('repository','https://github.com/ANZA24k/PatchBond'),
 ('repository','https://github.com/anza24k/patchbond.git'),('max_changed_files',13),('max_evidence',25),
 ('max_source_bytes',16385),('max_submissions',33),('required_tests',['../evil']),('acceptance_criteria',[]),('allowed_scope',[])])
def test_bad_terms(setup,field,value):
    vm,c,_,_=setup; t=terms(); t[field]=value; vm.value=1
    with vm.expect_revert(): c.create_bounty(json.dumps(t))

def test_wrong_bond_duplicate_limits(setup):
    vm,c,_,bid=setup; vm.value=6
    with vm.expect_revert('exact bond'): c.commit_patch(bid,'a'*64)
    vm.value=7; c.commit_patch(bid,'a'*64)
    with vm.expect_revert('duplicate commitment'): c.commit_patch(bid,'a'*64)
    for i in range(7): c.commit_patch(bid,str(i)*64)
    with vm.expect_revert('submission limit'): c.commit_patch(bid,'f'*64)
    invariant(c)

def test_wrong_salt_timestamp_and_replay(setup):
    vm,c,m,bid=setup; p,_=make_package(c,m); vm.value=7
    sid=c.commit_patch(bid,m.commitment_hash(json.loads(c.get_domain()),bid,c._direct(),p,SALT)); vm.value=0
    with vm.expect_revert('later transaction'): c.reveal_patch(sid,json.dumps(p),SALT)
    warp(vm,START+1)
    with vm.expect_revert('commitment mismatch'): c.reveal_patch(sid,json.dumps(p),'f'*64)
    c.reveal_patch(sid,json.dumps(p),SALT)
    with vm.expect_revert('reveal closed'): c.reveal_patch(sid,json.dumps(p),SALT)

def test_wrong_submitter(setup,direct_bob):
    vm,c,m,bid=setup; p,_=make_package(c,m); vm.value=7
    sid=c.commit_patch(bid,m.commitment_hash(json.loads(c.get_domain()),bid,c._direct(),p,SALT)); vm.value=0
    warp(vm,START+1); vm.sender=direct_bob
    with vm.expect_revert('wrong submitter'): c.reveal_patch(sid,json.dumps(p),SALT)

@pytest.mark.parametrize('offset,allowed',[(999,True),(1000,False),(1001,False)])
def test_deadline_boundary(setup,offset,allowed):
    vm,c,_,bid=setup; warp(vm,START+offset); vm.value=7
    if allowed: c.commit_patch(bid,'a'*64)
    else:
        with vm.expect_revert('deadline'): c.commit_patch(bid,'a'*64)

@pytest.mark.parametrize('outcome',['ACCEPTED','REJECTED','INCONCLUSIVE'])
def test_verdicts_consensus_settlement(setup,outcome):
    vm,c,_,bid=setup; sid,p,bodies=reveal(setup); mock_evidence(vm,p,bodies)
    vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p,outcome))); c.adjudicate(sid)
    assert vm.run_validator() is True
    s=json.loads(c.get_submission(sid)); assert s['result']['judgment']['outcome']==outcome
    assert s['bond_returned'] and len(s['decision_hash'])==64 and credit(c,vm.sender)==7
    old=c.get_submission(sid)
    with vm.expect_revert('adjudication closed'): c.adjudicate(sid)
    assert c.get_submission(sid)==old
    if outcome=='ACCEPTED':
        c.settle_reward(bid)
        with vm.expect_revert('no unsettled winner'): c.settle_reward(bid)
        with vm.expect_revert('refund closed'): c.refund_bounty(bid)
    else:
        warp(vm,START+1000); c.refund_bounty(bid)
        with vm.expect_revert('refund closed'): c.refund_bounty(bid)
    assert credit(c,vm.sender)==107; invariant(c)

def test_validator_disagrees(setup):
    vm,c,_,_=setup; sid,p,bodies=reveal(setup); mock_evidence(vm,p,bodies)
    vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p))); c.adjudicate(sid)
    vm.clear_mocks(); mock_evidence(vm,p,bodies); vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p,'REJECTED')))
    assert vm.run_validator() is False

@pytest.mark.parametrize('raw',['not json','{}','[]','{"outcome":"ACCEPTED"}'])
def test_bad_model(setup,raw):
    vm,c,_,_=setup; sid,p,bodies=reveal(setup); mock_evidence(vm,p,bodies); vm.mock_llm('PATCHBOND_POLICY_V1',raw)
    c.adjudicate(sid); assert json.loads(c.get_submission(sid))['result']['judgment']['outcome']=='INCONCLUSIVE'
    assert credit(c,vm.sender)==7

@pytest.mark.parametrize('kind',['hash','length','wrong_parent','forbidden','truncated','redirect','unavailable','oversize','attestation'])
def test_objective_failures(setup,kind):
    vm,c,m,_=setup; p,bodies=make_package(c,m)
    if kind=='hash': p['evidence'][0]['sha256']='0'*64
    if kind=='length': p['evidence'][0]['bytes']+=1
    if kind=='attestation':
        k=('candidate',m.ATTESTATION); a=json.loads(bodies[k]); a['submitter']='0x'+'1'*40; bodies[k]=m.canonical(a).encode()
        item=next(x for x in p['evidence'] if x['path']==m.ATTESTATION)
        item.update(sha256=hashlib.sha256(bodies[k]).hexdigest(),bytes=len(bodies[k]))
    sid,p,bodies=reveal(setup,(p,bodies))
    def mutate(r,commit,tree):
        if r=='candidate':
            if kind=='wrong_parent': commit['parents']=[{'sha':'0'*40}]
            if kind=='forbidden': tree['tree'].append(dict(path='contracts/evil.py',sha='0'*40,type='blob',mode='100644'))
            if kind=='truncated': tree['truncated']=True
    mock_evidence(vm,p,bodies,mutate)
    if kind in ('redirect','unavailable','oversize'):
        vm.strict_mocks=False; vm.clear_mocks(); vm.mock_web('git/commits',{'status':302 if kind=='redirect' else 503 if kind=='unavailable' else 200,'body':'x'*65537 if kind=='oversize' else ''})
    vm.strict_mocks=False # Later fetches deliberately not reached by objective failures.
    c.adjudicate(sid)
    assert json.loads(c.get_submission(sid))['result']['judgment']['outcome']==('INCONCLUSIVE' if kind=='unavailable' else 'INVALID_SUBMISSION')
    assert credit(c,vm.sender)==7; invariant(c)

def test_copy_not_reserving_original(setup,direct_bob):
    vm,c,m,bid=setup; p,bodies=make_package(c,m); original=vm.sender; vm.sender=direct_bob
    sid,_,_=reveal(setup,(p,bodies)); mock_evidence(vm,p,bodies); vm.strict_mocks=False; c.adjudicate(sid)
    assert json.loads(c.get_submission(sid))['result']['judgment']['outcome']=='INVALID_SUBMISSION'
    assert 'candidate:'+bid+':'+CANDIDATE not in c.used
    vm.sender=original; warp(vm,START+2); vm.value=7
    sid=c.commit_patch(bid,m.commitment_hash(json.loads(c.get_domain()),bid,c._direct(),p,SALT)); vm.value=0
    warp(vm,START+3); c.reveal_patch(sid,json.dumps(p),SALT); vm.clear_mocks(); mock_evidence(vm,p,bodies)
    vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p))); c.adjudicate(sid)
    assert json.loads(c.get_bounty(bid))['winner']==sid

def test_expiry_no_stuck_escrow(setup):
    vm,c,_,bid=setup; sid,_,_=reveal(setup); warp(vm,START+1000)
    with vm.expect_revert('live adjudication'): c.refund_bounty(bid)
    with vm.expect_revert('bond still live'): c.release_bond(sid)
    warp(vm,START+87400); c.refund_bounty(bid); c.release_bond(sid)
    with vm.expect_revert('bond already'): c.release_bond(sid)
    assert json.loads(c.get_accounting())['escrow']==0 and credit(c,vm.sender)==107; invariant(c)

def test_unrevealed_permissionless_release(setup,direct_bob):
    vm,c,_,bid=setup; owner=vm.sender; vm.value=7; sid=c.commit_patch(bid,'0'*64); vm.value=0
    warp(vm,START+1000); vm.sender=direct_bob; c.release_bond(sid); c.refund_bounty(bid)
    assert credit(c,owner)==107 and credit(c,direct_bob)==0

def test_randomized_invariant_append_only(setup):
    vm,c,_,_=setup; rng=random.Random(49)
    for i in range(24):
        t=terms(); t['bond']=rng.randrange(20); vm.value=rng.randrange(1,10000); bid=c.create_bounty(json.dumps(t))
        vm.value=t['bond']; sid=c.commit_patch(bid,hashlib.sha256(str(i).encode()).hexdigest()); vm.value=0
        before=c.get_history(0,50); warp(vm,START+1000); c.release_bond(sid); c.refund_bounty(bid)
        assert c.get_history(0,len(before))==before; invariant(c); warp(vm,START)
    assert json.loads(c.get_accounting())['escrow']==100

def test_schema_equivalence(setup):
    _,c,m,_=setup; p,_=make_package(c,m); j=judgment(p); proof={'manifest':[{'url':j['citations'][0]}]}
    for key,bad in [('acceptance_score',True),('acceptance_score',101),('security_risk','HIGH'),('requirements_satisfied',[0]),('citations',['https://evil.test/']),('material_issues',['bug'])]:
        obj=copy.deepcopy(j); obj[key]=bad
        with pytest.raises(m.gl.vm.UserError): m.normalize_judgment(obj,terms(),proof)
    a={'proof':proof,'judgment':j}; b=copy.deepcopy(a); b['judgment']['reasoning']='Independent prose'; assert m.equivalent(a,b)
    b['judgment']['acceptance_score']=79; assert not m.equivalent(a,b)
    b=copy.deepcopy(a); b['proof']={}; assert not m.equivalent(a,b)

def test_pickling(setup):
    vm,c,_,_=setup; sid,p,bodies=reveal(setup); mock_evidence(vm,p,bodies)
    vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p))); c.adjudicate(sid)
    from gltest.direct.loader import _validate_pickling
    _,leader,validator=vm._captured_validators[-1]; _validate_pickling(leader,'leader'); _validate_pickling(validator,'validator')

def test_withdraw_failure_guards(setup):
    vm,c,_,bid=setup
    with vm.expect_revert('no credit'): c.withdraw()
    warp(vm,START+1000); c.refund_bounty(bid)
    with vm.expect_revert('insufficient contract balance'): c.withdraw()

@pytest.mark.parametrize('change',[lambda p:p.update(candidate_commit='main'),lambda p:p.update(nonce='x'),
    lambda p:p['evidence'][0].update(path='../evil'),lambda p:p['evidence'][0].update(path='file%2Fname'),
    lambda p:p['evidence'][0].update(bytes=16385),lambda p:p.update(evidence=p['evidence']*7),
    lambda p:p['evidence'].reverse(),lambda p:p['evidence'].append(p['evidence'][0])])
def test_package_objective_limits(setup,change):
    vm,c,m,bid=setup; p,_=make_package(c,m); change(p)
    with vm.expect_revert(): m.validate_package(p,terms())


def test_origin_authorization(setup,direct_bob):
    vm,c,_,_=setup; vm.origin=direct_bob; vm.value=100
    with vm.expect_revert('direct originating'): c.create_bounty(json.dumps(terms()))


def test_losing_bonds_after_winner(setup):
    vm,c,_,bid=setup; sid,p,bodies=reveal(setup)
    vm.value=7; losing=c.commit_patch(bid,'0'*64); vm.value=0
    mock_evidence(vm,p,bodies); vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p))); c.adjudicate(sid)
    c.release_bond(losing); c.settle_reward(bid)
    assert credit(c,vm.sender)==114 and json.loads(c.get_accounting())['escrow']==0
    invariant(c)


def test_duplicate_authenticated_submission(setup):
    vm,c,m,bid=setup; p,bodies=make_package(c,m)
    # Two distinct commitments of the same candidate. Review the first as rejected,
    # then independently authenticate and reject the second as duplicate.
    ids=[]
    for salt,at in [('c'*64,START),('f'*64,START+1)]:
        warp(vm,at); vm.value=7
        sid=c.commit_patch(bid,m.commitment_hash(json.loads(c.get_domain()),bid,c._direct(),p,salt)); vm.value=0
        warp(vm,at+1); c.reveal_patch(sid,json.dumps(p),salt); ids.append(sid)
    mock_evidence(vm,p,bodies); vm.mock_llm('PATCHBOND_POLICY_V1',json.dumps(judgment(p,'REJECTED')))
    c.adjudicate(ids[0]); c.adjudicate(ids[1])
    assert json.loads(c.get_submission(ids[1]))['result']['judgment']['outcome']=='INVALID_SUBMISSION'
    assert credit(c,vm.sender)==14; invariant(c)


def test_withdraw_emission_once(setup,monkeypatch):
    vm,c,m,bid=setup; warp(vm,START+1000); c.refund_bounty(bid); vm.deal(vm._contract_address,100)
    # Observe the actual SDK's EthSend request through official Direct Mode WASI.
    from gltest.direct import wasi_mock
    original=wasi_mock._handle_gl_call; sends=[]
    def handler(context,request):
        if 'EthSend' in request:
            sends.append(request['EthSend']); return {}
        return original(context,request)
    monkeypatch.setattr(wasi_mock,'_handle_gl_call',handler)
    c.withdraw(); assert len(sends)==1 and sends[0]['value']==100 and sends[0]['calldata']==b''
    assert sends[0]['address']==m.gl.message.sender_address
    assert credit(c,vm.sender)==0 and json.loads(c.get_accounting())['emitted']==100
    with vm.expect_revert('no credit'): c.withdraw()
    invariant(c)
