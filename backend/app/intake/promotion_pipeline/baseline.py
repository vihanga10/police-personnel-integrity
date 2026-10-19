"""Index original signed promotion reports without changing their storage."""
from app.access import full_source_profiles as F
from .core import check, digest, opaque

def index_original(workspace, store):
    metadata=F.active_set(workspace)
    check(metadata is not None,'ORIGINAL_PROFILES_REQUIRED')
    pin=digest(metadata)
    with store.transaction() as c:
        previous=c.execute('SELECT value FROM baseline_meta WHERE id=1').fetchone()
        if previous:
            saved=store.open('BASELINE',1,previous[0])
            check(saved['source_set_sha256']==pin,'BASELINE_ALREADY_DIFFERS')
            entries=dict(c.execute('SELECT id,fingerprint FROM baseline'))
            check(saved['promotions']==len(entries) and saved['index_sha256']==digest(entries),'BASELINE_INDEX_CHANGED')
            return saved
    entries={};visited=set()
    with workspace.transaction() as connection:
        rows=connection.execute('SELECT id,value FROM source_profiles WHERE generation=?',(metadata['generation'],))
        for ident,blob in rows:
            check(ident in metadata['profiles'] and ident not in visited,'BASELINE_PROFILE_MEMBERSHIP_DIFFERS')
            envelope=workspace.open('SOURCE_PROFILE',[metadata['generation'],ident],blob)
            check(F.P.fingerprint(envelope)==metadata['profiles'][ident],'BASELINE_PROFILE_DIGEST_DIFFERS')
            p=F.validate_profile(envelope,workspace.keys,workspace.clock())
            check(workspace.index('SOURCE_PROFILE',p['officer_uid'])==ident,'BASELINE_OFFICER_BINDING_DIFFERS')
            check(p['source_public_sha256']==metadata['source_public_sha256'] and
                p['source_context_sha256']==metadata['source_context_sha256'],'BASELINE_BINDING_DIFFERS')
            visited.add(ident)
            for row in p['full_records']:
                if row['dataset']!='promotion_history.csv':continue
                key=opaque(store.key,'SOURCE_ID',row['fields']['promotion_id'].strip())
                check(key not in entries,'ORIGINAL_PROMOTION_ID_AMBIGUOUS')
                entries[key]=opaque(store.key,'SOURCE_ROW',[p['officer_uid'],row['fields']])
    check(visited==set(metadata['profiles']),'BASELINE_PROFILE_MISSING')
    check(digest(F.active_set(workspace))==pin,'BASELINE_CHANGED_DURING_INDEX')
    value={'source_set_sha256':pin,'promotions':len(entries),'index_sha256':digest(entries)}
    with store.transaction() as c:
        check(c.execute('SELECT COUNT(*) FROM baseline').fetchone()[0]==0,'PARTIAL_BASELINE_REFUSED')
        c.executemany('INSERT INTO baseline VALUES(?,?)',sorted(entries.items()))
        c.execute('INSERT INTO baseline_meta VALUES(1,?)',(store.seal('BASELINE',1,value),))
    return value
