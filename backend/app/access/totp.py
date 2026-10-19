"""RFC 6238 SHA-1/6-digit/30-second TOTP, encrypted seeds and atomic replay guard."""
import base64, hashlib, hmac, re, struct
from app.access.policy import require

SCHEMA='''CREATE TABLE IF NOT EXISTS totp_control(id INTEGER PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS totp_factors(id TEXT PRIMARY KEY,value BLOB NOT NULL);'''

def code(seed,counter):
    digest=hmac.new(base64.b32decode(seed),struct.pack('>Q',counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)

def required(store,c):
    tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'totp_control','totp_factors'}&tables:
        require(not getattr(store,'require_totp',False),'Required TOTP factors missing')
        return False
    require({'totp_control','totp_factors'}<=tables,'Incomplete TOTP setup')
    row=c.execute('SELECT value FROM totp_control WHERE id=1').fetchone()
    require(row is not None,'TOTP control missing')
    p=store.open('TOTP_CONTROL',1,1,row[0])
    require(p=={'policy':'APPLICATION_TOTP_V1','required':True},'TOTP control differs')
    return True

def verify(store,c,ident,user_id,value):
    if not required(store,c):return True
    if type(value) is not str or not re.fullmatch('[0-9]{6}',value):return False
    row=c.execute('SELECT value FROM totp_factors WHERE id=?',(ident,)).fetchone()
    if row is None:return False
    p=store.open('TOTP_FACTOR',ident,1,row[0])
    require(set(p)=={'policy','user_id','seed','last_counter'} and p['policy']=='APPLICATION_TOTP_V1' and
            p['user_id']==user_id and type(p['last_counter']) is int,'TOTP identity differs')
    current=int(store.clock())//30
    matches=[n for n in (current-1,current,current+1) if n>=0 and n>p['last_counter'] and hmac.compare_digest(code(p['seed'],n),value)]
    if not matches:return False
    fresh={**p,'last_counter':max(matches)}
    c.execute('UPDATE totp_factors SET value=? WHERE id=?',(store.seal('TOTP_FACTOR',ident,1,fresh),ident))
    return True
