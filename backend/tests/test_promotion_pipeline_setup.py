"""Private setup file operations with generated fixtures, no database/RPC calls."""
import importlib.util,json
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime,timezone
import pytest
from app.intake.promotion_pipeline.core import digest,parse

spec=importlib.util.spec_from_file_location('promotion_setup_script',Path(__file__).parents[1]/'scripts/manage_promotion_pipeline.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
@pytest.fixture
def env(tmp_path,monkeypatch):
    monkeypatch.setattr(M,'ensure_stopped',lambda origin:None)
    root=tmp_path/'state';root.mkdir(mode=0o700);app=tmp_path/'app';app.mkdir(mode=0o700);repo=tmp_path/'repo';repo.mkdir()
    file=app/'workspace.json';value={'policy':'fixture-only','future_setting':{'preserve':True},'promotion_intake_config':str(root/'runtime.json')};file.write_text(json.dumps(value));file.chmod(0o600)
    return SimpleNamespace(state_root=root,repository=repo,workspace_config=file,network_file=root/'promotions-network.json',existing_network=app/'existing-network.json'),value

def test_disable_removes_only_optional_setting_and_preserves_future_settings_and_backup(env):
    args,value=env;before=args.workspace_config.read_bytes()
    assert M.disable(args,None,'fixture-origin')['status']=='PROMOTION_PIPELINE_DISABLED'
    result=json.loads(args.workspace_config.read_bytes());assert result=={k:v for k,v in value.items() if k!='promotion_intake_config'}
    assert list(args.state_root.glob('workspace-before-disable-*.json'))[0].read_bytes()==before
    assert M.disable(args,None,'fixture-origin')['status']=='PROMOTION_PIPELINE_ALREADY_DISABLED'

def test_disable_cannot_remove_another_runtime_configuration(env):
    args,value=env;value['promotion_intake_config']='/another/private/runtime.json';args.workspace_config.write_text(json.dumps(value));before=args.workspace_config.read_bytes()
    with pytest.raises(M.IntakeError if hasattr(M,'IntakeError') else ValueError):M.disable(args,None,'fixture-origin')
    assert args.workspace_config.read_bytes()==before

def test_network_configuration_is_separate_idempotent_and_does_not_change_existing_urls(env):
    args,_=env;value={'policy':'FINDINGS_LIVE_SEPOLIA_NETWORK_V1','rpc_urls':['https://fixture.quiknode.pro/test-only','https://eth-sepolia.g.alchemy.com/v2/test-only'],'max_fee_gwei':'5','priority_fee_gwei':'1','max_total_fee_eth':'0.025','confirmations':12}
    args.existing_network.write_text(json.dumps(value));args.existing_network.chmod(0o600);before=args.existing_network.read_bytes()
    result=M.network(args,None,'fixture-origin');assert result['status']=='PRIVATE_PROMOTIONS_NETWORK_PREPARED'
    assert json.loads(args.network_file.read_bytes())=={**value,'policy':'PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1'}
    assert args.existing_network.read_bytes()==before and M.network(args,None,'fixture-origin')==result

def test_demo_csv_is_labelled_controlled_and_preserves_the_original_profile(env,monkeypatch):
    args,_=env;meta={'source_public_sha256':'a'*64};(args.state_root/'setup.json').write_text(json.dumps({'baseline_source_set_sha256':digest(meta)}));(args.state_root/'setup.json').chmod(0o600)
    original={'full_records':[{'dataset':'officer_service_information.csv','fields':{'current_rank':'Sub Inspector of Police','service_status':'Active','current_unit_name':'CID'}}]}
    monkeypatch.setattr(M.F,'active_set',lambda workspace:meta);monkeypatch.setattr(M.F,'profile',lambda *a:original)
    class Transaction:
        def __enter__(self):return self
        def __exit__(self,*a):return False
    workspace=SimpleNamespace(clock=lambda:datetime(2026,10,16,tzinfo=timezone.utc).timestamp(),access=SimpleNamespace(transaction=Transaction,_directory=lambda c:{'source_public_sha256':'a'*64,'officers':[{'officer_uid':'11111111-1111-4111-8111-111111111111','nic':'000000001V'}]}))
    result=M.demo_csv(args,workspace,'fixture-origin');file=Path(result['file']);before=file.read_bytes();row=parse(before)[0]
    assert row['promotion_id'].startswith('CONTROLLED-UPLOAD-') and row['to_rank']=='Inspector of Police'
    assert 'Controlled generated report' in row['promotion_reason'] and original['full_records'][0]['fields']['current_rank']=='Sub Inspector of Police'
    assert M.demo_csv(args,workspace,'fixture-origin')['status']=='EXISTING_CONTROLLED_DEMO_PRESERVED' and file.read_bytes()==before

def test_configure_normalizes_checksummed_contract_to_the_adapter_address_contract(env,monkeypatch):
    args,_=env;root=args.state_root
    def save(file,value):file.parent.mkdir(parents=True,exist_ok=True,mode=0o700);file.write_text(json.dumps(value));file.chmod(0o600)
    args.backup_root=root.parent/'backup';args.wallet_root=root.parent/'wallet';args.wallet_backup=root.parent/'wallet-backup';args.existing_wallet=root.parent/'old-wallet';args.fabric_gateway=root/'gateway/promotions-gateway.json'
    meta={'source_public_sha256':'a'*64};monkeypatch.setattr(M.F,'active_set',lambda workspace:meta);monkeypatch.setattr(M,'source_pins',lambda repo:{'fixture_source':'a'*64})
    save(root/'setup.json',{'baseline_source_set_sha256':digest(meta),'importer_ids':['11111111-1111-4111-8111-111111111111']})
    for name in ['postgres','mongo']:save(root/(name+'-writer.json'),{'username':'police_promotion_writer','password':'x'*48})
    save(root/'STORAGE_READY.json',{'status':'PASSED','postgres_credential_sha256':M.sha(root/'postgres-writer.json',args.repository),'mongo_credential_sha256':M.sha(root/'mongo-writer.json',args.repository)})
    save(args.fabric_gateway,{'policy':'PROMOTIONS_AUTHENTICATED_GATEWAY_V2','destination':{'chaincode':'promotions-anchor-v1'}})
    save(args.fabric_gateway.parent/'PASSED.json',{'status':'PROMOTIONS_FABRIC_GATEWAY_VERIFIED','configuration_sha256':M.sha(args.fabric_gateway,args.repository)})
    save(args.network_file,{'policy':'PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1'})
    writer='0x'+'AB'*20;contract='0x'+'CD'*20
    save(args.wallet_root/'wallet-info.json',{'address':writer});save(args.existing_wallet/'wallet-info.json',{'address':'0x'+'11'*20})
    save(root/'deployment/PASSED.json',{'policy':'SEPOLIA_PROMOTIONS_CONTRACT_DEPLOYMENT_V1','status':'PASSED','finalized':True,'two_rpc_readback':True,'writer':writer,'contract_address':contract,'artifact':{'runtime_sha256':'e'*64},'config_sha256':M.sha(args.network_file,args.repository)})
    M.configure(args,SimpleNamespace(),'fixture-origin');value=json.loads((root/'runtime.json').read_bytes())
    assert value['chains']['destination']['contract']==contract.lower() and value['chains']['destination']['writer']==writer.lower()
