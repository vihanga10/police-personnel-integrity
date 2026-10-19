"""Client-reported display events: authenticated and scoped, never human-read proof."""
from app.access.policy import AccessError,require,uid,projection,permitted
SECTIONS=('overview','history','authority','contradictions','reviews','anchoring','integrity')
def section_display(service,token,csrf,value):
    try:
        require(set(value)=={'officer_uid','section','event_id'} and value['section'] in SECTIONS)
        uid(value['officer_uid']);uid(value['event_id'])
    except Exception:raise AccessError(400,'INVALID_ACTIVITY_REPORT') from None
    # Check disclosure without consuming a second full workspace read or trusting client names.
    user,grant,packet,identity=service.authorized(token,value['officer_uid'],csrf=csrf,charge=False)
    with service.access.transaction() as c:
        current,session=service.access._session(c,token,csrf)
        if current!=user:raise AccessError(409,'ACCOUNT_CHANGED')
        service.access._limit(c,'SECTION_DISPLAY',session['user'],120)
    return {'received':True,'identity':identity,'section':value['section'],
            'observation_basis':'CLIENT_REPORTED_DISPLAY','human_read_confirmed':False}
