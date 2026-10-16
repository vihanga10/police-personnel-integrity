"""Append-only availability journal joining published promotion evidence to analysis.

This is an application observation, not an assertion of promotion authority.
Original signed packets and original blockchain journals are never rewritten.
"""
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.store import private
from app.access import research_policy as P
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.historical_source_claims import source_claims
from app.identity.reported_authority_actions import review_actions, ActionReview
from .core import canonical, check, digest, opaque, publication, COLUMNS
from .store import IntakeStore

POLICY='PUBLISHED_PROMOTION_ANALYSIS_V1'

class AvailabilityJournal:
    def __init__(self, root, key, *, repo, create=False):
        self.root=private(root,directory=True,repo=repo)
        self.path=self.root/'availability.sqlite3'
        self.aead=AESGCM(hmac.digest(key,POLICY.encode(),'sha256'))
        if create and not self.path.exists():
            with self.path.open('xb') as f:os.fchmod(f.fileno(),0o600)
            with sqlite3.connect(self.path) as c:
                c.executescript('''CREATE TABLE activations(batch TEXT PRIMARY KEY,value BLOB NOT NULL);
                CREATE TRIGGER immutable_update BEFORE UPDATE ON activations BEGIN SELECT RAISE(ABORT,'immutable analysis observation'); END;
                CREATE TRIGGER immutable_delete BEFORE DELETE ON activations BEGIN SELECT RAISE(ABORT,'immutable analysis observation'); END;
                PRAGMA user_version=1;''')
        private(self.path,repo=repo)
        with self.connection() as c:check(c.execute('PRAGMA user_version').fetchone()[0]==1,'ANALYSIS_SCHEMA_DIFFERS')

    def connection(self):
        c=sqlite3.connect(self.path,timeout=10);c.execute('PRAGMA synchronous=FULL');return c

    def open(self,batch,blob):
        value=json.loads(self.aead.decrypt(blob[:12],blob[12:],canonical([POLICY,batch])))
        check(value['batch_id']==batch and value['policy']==POLICY,'ANALYSIS_OBSERVATION_BINDING_DIFFERS')
        P.instant(value['available_at']);return value

    def get(self,batch):
        with self.connection() as c:row=c.execute('SELECT value FROM activations WHERE batch=?',(batch,)).fetchone()
        return None if row is None else self.open(batch,row[0])

    def identifiers(self):
        with self.connection() as c:return {r[0] for r in c.execute('SELECT batch FROM activations')}

    def append(self,batch,binding,now):
        with self.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            old=c.execute('SELECT value FROM activations WHERE batch=?',(batch,)).fetchone()
            if old:
                result=self.open(batch,old[0]);check(result['binding']==binding,'ANALYSIS_RECEIPT_CHANGED');return result
            previous=[self.open(b,v) for b,v in c.execute('SELECT batch,value FROM activations')]
            check(all(P.instant(p['available_at'])<now for p in previous),'ANALYSIS_CLOCK_MUST_ADVANCE')
            value={'policy':POLICY,'batch_id':batch,'available_at':now.isoformat(),'binding':binding}
            nonce=os.urandom(12);blob=nonce+self.aead.encrypt(nonce,canonical(value),canonical([POLICY,batch]))
            c.execute('INSERT INTO activations VALUES(?,?)',(batch,blob))
        return value

def verified_batch(store,batch):
    ident=batch['batch_id'];visible=store.phase(ident,'VISIBLE')
    check(visible is not None,'ANALYSIS_REQUIRES_VISIBLE_BATCH')
    receipt=store.phase(ident,'CHAINS_VERIFIED');storage=store.phase(ident,'STORAGE_VERIFIED')
    prepared=store.phase(ident,'DOCUMENTS_PREPARED')
    check(receipt is not None and storage is not None and prepared is not None,'ANALYSIS_PROOF_MISSING')
    payload,manifest=publication(store.key,batch)
    check(receipt['status']=='BOTH_CHAINS_VERIFIED' and receipt['fabric']['status']=='FINAL' and receipt['public']['status']=='FINAL','ANALYSIS_BOTH_CHAINS_REQUIRED')
    check(receipt['fabric']['payload']==payload,'ANALYSIS_FABRIC_BINDING_DIFFERS')
    expected={'policy':'PROMOTIONS_PUBLIC_ANCHOR_V1','namespace':'promotions-anchor-v1',
        'publication_id':payload['publication_id'],'public_sha256':payload['public_sha256'],
        'merkle_root':payload['merkle_root'],'fabric_destination_sha256':digest(receipt['fabric']['destination']),
        'fabric_transaction_id':receipt['fabric']['transaction_id'],'fabric_receipt_sha256':digest(receipt['fabric'])}
    check(receipt['public']['payload']==expected,'ANALYSIS_PUBLIC_BINDING_DIFFERS')
    check(visible=={'publication':payload,'manifest_sha256':digest(manifest),'receipt_sha256':digest(receipt),'storage':storage},'ANALYSIS_VISIBILITY_BINDING_DIFFERS')
    ready=[r for r in batch['rows'] if r['status']=='READY']
    check(storage=={'documents_sha256':digest(prepared['documents']),'row_count':len(ready)},'ANALYSIS_STORAGE_BINDING_DIFFERS')
    check(len(prepared['documents'])==len(ready),'ANALYSIS_ROW_COUNT_DIFFERS')
    for row,document in zip(ready,prepared['documents'],strict=True):
        blob=base64.b64decode(document['ciphertext'],validate=True)
        check(hashlib.sha256(blob).hexdigest()==document['ciphertext_sha256'],'ANALYSIS_DOCUMENT_DIGEST_DIFFERS')
        value=store.open('DELIVERY',document['record_id'],blob)
        check(document['batch_id']==ident and value['batch_id']==ident and value['source']==row['source'] and
            value['officer_uid']==row['officer_uid'] and value['source_row']==row['row'] and
            value['file_sha256']==batch['file_sha256'] and value['source_reference']==batch['source_reference'] and
            value['received_at']==batch['received_at'] and
            document['record_id']==opaque(store.key,'SOURCE_ID',row['source']['promotion_id'].strip()),'ANALYSIS_SOURCE_DOCUMENT_DIFFERS')
    return {'receipt_sha256':digest(receipt),'visible_sha256':digest(visible),'manifest_sha256':digest(manifest),
        'publication_id':payload['publication_id'],'merkle_root':payload['merkle_root'],
        'fabric_transaction_id':receipt['fabric']['transaction_id'],'public_transaction_id':receipt['public']['transaction_id'],
        'public_contract':receipt['public']['destination']['contract'],
        'verification_observed_at':receipt['verification_observed_at']}

class PromotionAnalysis:
    def __init__(self,workspace,config_file,*,create=False):
        self.workspace=workspace
        self.config_file=private(config_file,repo=workspace.repo)
        self.raw=self.config_file.read_bytes();self.config=json.loads(self.raw)
        check(set(self.config)=={'policy','intake_config','analysis_root'} and self.config['policy']==POLICY,'ANALYSIS_CONFIG_DIFFERS')
        self.runtime_file=private(self.config['intake_config'],repo=workspace.repo)
        self.runtime_raw=self.runtime_file.read_bytes();self.runtime=json.loads(self.runtime_raw)
        check(self.runtime['policy']=='PROMOTION_PIPELINE_RUNTIME_V1' and self.runtime['analysis_config']==str(self.config_file),'ANALYSIS_RUNTIME_BINDING_DIFFERS')
        self.intake=IntakeStore(self.runtime['state_root'],self.runtime['key_file'],self.runtime['backup_key_file'],repo=workspace.repo)
        self.journal=AvailabilityJournal(self.config['analysis_root'],self.intake.key,repo=workspace.repo,create=create)

    def guard(self):
        check(private(self.config_file).read_bytes()==self.raw and private(self.runtime_file).read_bytes()==self.runtime_raw,'ANALYSIS_CONFIG_CHANGED')
        from .configuration import source_files
        check(set(self.runtime['source_pins'])==set(source_files(self.workspace.repo)),'ANALYSIS_SOURCE_PIN_COVERAGE_DIFFERS')
        for relative,pin in self.runtime['source_pins'].items():
            file=Path(self.workspace.repo)/relative
            check(not file.is_symlink() and hashlib.sha256(file.read_bytes()).hexdigest()==pin,'ANALYSIS_SOURCE_CHANGED')

    def activate_visible(self,limit=20):
        self.guard();now=datetime.fromtimestamp(self.workspace.clock(),timezone.utc)
        with self.intake.transaction() as c:identifiers=[r[0] for r in c.execute("SELECT batch FROM phases WHERE phase='VISIBLE' ORDER BY rowid")]
        check(len(identifiers)<=1000,'ANALYSIS_BATCH_LIMIT')
        existing=self.journal.identifiers();created=[]
        for ident in [v for v in identifiers if v not in existing][:limit]:
            batch=self.intake.get(ident);binding=verified_batch(self.intake,batch)
            check(P.instant(batch['received_at'])<=P.instant(binding['verification_observed_at'])<=now,'ANALYSIS_OBSERVATION_CLOCK_DIFFERS')
            self.guard()
            recorded=datetime.fromtimestamp(self.workspace.clock(),timezone.utc)
            created.append(self.journal.append(ident,binding,recorded))
        return created

    def reports(self,officer,known=None):
        self.guard();now=datetime.fromtimestamp(self.workspace.clock(),timezone.utc)
        known=now if known is None else known
        check(known<=now,'ANALYSIS_FUTURE_KNOWLEDGE_FORBIDDEN')
        reports=[]
        for batch in self.intake.officer_batches(officer):
            activation=self.journal.get(batch['batch_id'])
            if activation is None or P.instant(activation['available_at'])>known:continue
            binding=verified_batch(self.intake,batch)
            check(activation['binding']==binding,'ANALYSIS_ACTIVATED_RECEIPT_CHANGED')
            for row in batch['rows']:
                if row['status']=='READY' and row['officer_uid']==officer:
                    reports.append({'officer_uid':officer,'batch_id':batch['batch_id'],'source_row':row['row'],
                        'raw_record_id':opaque(self.intake.key,'SOURCE_ID',row['source']['promotion_id'].strip()),
                        'fields':deepcopy(row['source']),'received_at':batch['received_at'],
                        'analysis_recorded_at':activation['available_at'],'source_reference_sha256':digest(batch['source_reference']),
                        'publication':deepcopy(binding),'activation_reference':digest(activation)})
        check(len(reports)<=1000,'ANALYSIS_OFFICER_ROW_LIMIT')
        return sorted(reports,key=lambda r:(r['analysis_recorded_at'],r['raw_record_id']))

    @staticmethod
    def catalog(report):
        raw=report['raw_record_id'];fields=report['fields']
        check(set(fields)==set(COLUMNS),'ANALYSIS_PROMOTION_COLUMNS_DIFFER')
        provenance={'reported_source':'PF_REGISTRY','source_custody':'UPLOADER_REPORTED',
            'batch_id':report['batch_id'],'source_row':report['source_row'],
            'received_at':report['received_at'],'analysis_recorded_at':report['analysis_recorded_at'],
            'activation_reference':report['activation_reference'],'publication':report['publication']}
        item={'raw_record_id':raw,'filename':'promotion_history.csv','classification':'UNASSESSED',
            'delivery':{'complete':True},'candidate_links':[{'officer_uid':report['officer_uid'],'role':'officer_nic_no','state':'CANDIDATE_NOT_ACCEPTED'}],
            'original':{'columns':list(COLUMNS),'values':[fields[k] for k in COLUMNS]},
            'provenance':provenance,'assertion':{'reported_row_sha256':digest(fields)}}
        return item,{'activation_reference':report['activation_reference'],'receipt_sha256':report['publication']['receipt_sha256']}

    def recording(self,packet,officer,reports):
        original=P.history(packet['history'],officer)
        if not reports:return original
        versions=list(original.versions)
        for report in reports:
            item,binding=self.catalog(report);raw=report['raw_record_id']
            claims=source_claims(officer,{raw:item},{raw:[binding]})
            # Full rows remain encrypted in intake; compact references bind them
            # without exceeding the historical query's bounded reference size.
            reference=canonical({'raw_record_id':raw,'filename':'promotion_history.csv',
                'provenance':item['provenance'],'assertion':item['assertion']}).decode()
            for claim in claims:
                claim=replace(claim,source_reference=reference)
                versions.append(EvidenceVersion(digest([POLICY,report['activation_reference'],claim.claim_id]),
                    claim,raw,P.instant(report['analysis_recorded_at']),report['activation_reference'],
                    report['publication']['receipt_sha256']))
        check(len(versions)<=20000,'ANALYSIS_VERSION_LIMIT')
        end=max(original.coverage_end,*(P.instant(r['analysis_recorded_at']) for r in reports))
        return RecordingHistory(officer,original.coverage_start,end,POLICY,
            digest({'original_coverage':original.coverage_digest,'activations':sorted({r['activation_reference'] for r in reports})}),tuple(versions))

    @staticmethod
    def summary(reports):
        return {'policy':POLICY,'reported_promotions':len(reports),
            'latest_recorded_at':max((r['analysis_recorded_at'] for r in reports),default=None),
            'latest_effective_on':max((r['fields']['effective_date'].strip() for r in reports if r['fields']['effective_date'].strip()),default=None),
            'evidence_digest':digest(reports),'accepted_current_rank_changed':False,
            'source_change_completeness_established':False,'fresh_chain_reads':False,
            'publication_basis':'RETAINED_BOTH_CHAIN_VERIFICATION'}

    def actions(self,packet,directory,reports):
        from app.access.operational_authority import action_reference
        candidates={}
        for officer in directory['officers']:
            candidates.setdefault(officer['nic'].strip().casefold(),[]).append(officer['officer_uid'])
        result={}
        for report in reports:
            item,binding=self.catalog(report);raw=report['raw_record_id'];fields=report['fields']
            item['candidate_links'] += [{'officer_uid':u,'role':'promotion_authority','state':'CANDIDATE_NOT_ACCEPTED'}
                for u in candidates.get(fields['promotion_authority'].strip().casefold(),[])]
            actions=review_actions({raw:item},{raw:[binding]})
            if not actions:
                actions=(ActionReview('AUTHORIZE_PROMOTION','CANNOT_VERIFY',
                    ('ACTOR_CLAIM_MISSING','REPORTED_DATE_MISSING','GOVERNING_RULE_UNASSESSED','DELEGATION_EVIDENCE_UNASSESSED'),
                    raw,(),None,'',canonical({'filename':'promotion_history.csv','provenance':item['provenance'],'assertion':item['assertion']}).decode(),digest(binding)),)
            for action in actions:result[action_reference(packet,action)]=action
        return result

def configured_analysis(workspace):
    file=getattr(workspace,'promotion_intake_config',None)
    if not file:return None
    config=json.loads(private(file,repo=workspace.repo).read_bytes())
    return PromotionAnalysis(workspace,config['analysis_config']) if 'analysis_config' in config else None
