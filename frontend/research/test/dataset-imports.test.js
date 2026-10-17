const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {JSDOM,VirtualConsole}=require('jsdom');
const response=(value,status=200)=>({ok:status<400,status,json:async()=>value});
const wait=async predicate=>{for(let n=0;n<200;n++){if(predicate())return;await new Promise(r=>setTimeout(r,5));}throw Error('Dataset import UI timeout');};
const transfer={code:'TRANSFER_HISTORY',filename:'transfer_history.csv',label:'Transfers',columns:['transfer_id','officer_nic_no','from_station_code','to_station_code'],source_systems:['PF_REGISTRY','POLICE_HR_IS'],effect:'POSTING',evidence_role:'SOURCE_REPRESENTATION',multi_subject:false};
const intake=(extra={})=>({configured:true,can_upload:true,can_inspect:true,can_approve:false,requires_igp_approval:true,datasets:[transfer],maximum_bytes:2097152,maximum_rows:1000,...extra});
const pending={batch_id:'22222222-2222-4222-8222-222222222222',file_sha256:'f'.repeat(64),dataset:'TRANSFER_HISTORY',filename:'transfers.csv',status:'VISIBLE',ready_rows:1,
    rows:[{row:1,status:'READY',issues:[],subjects:[{officer_uid:'u',role:'officer_nic_no'}],fields:{transfer_id:'T-1',officer_nic_no:'000000001V',from_station_code:'ST-1',to_station_code:'ST-2'}}],
    processing_approval_version:2,processing_approval:{kind:'APPROVE',actor:{username:'research.igp',version:1},recorded_at:'2026-10-16T03:00:00Z',reason:'ok'},
    row_acceptance:[{row:1,status:'PENDING_REVIEW',reasons:['AUTHORITY_CANNOT_VERIFY'],effect:'POSTING',effective_on:'2024-01-01',evaluation_reference:'e'.repeat(64),evaluation_version:1,recorded_at:'2026-10-16T03:00:00Z',row_review:null,row_review_version:0,row_review_blocked:[]}]};
function setup(handler=()=>null,role='HQ_ADMIN'){
    const dom=new JSDOM(fs.readFileSync('imports.html','utf8'),{url:'https://access.test:9443/imports',runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:new VirtualConsole()});const calls=[];
    dom.window.fetch=async(url,options={})=>{calls.push({url,options});return handler(url,options)||response(url==='/api/auth/session'?{username:role==='IGP'?'research.igp':'research.hq',role,csrf_token:'fixture-csrf',server_time:Date.now()/1000,expires_at:Date.now()/1000+1800}:
        url.endsWith('/promotions/capabilities')?{configured:true,can_upload:true,can_inspect:true,maximum_bytes:2097152,maximum_rows:1000,columns:['promotion_id']}:url.endsWith('/intake/capabilities')?intake():url.includes('/batches')?{items:[]}:{can_read_access_logs:true});};
    dom.window.eval(fs.readFileSync('imports.js','utf8'));return {dom,d:dom.window.document,calls};
}
function choose(f,value){const select=f.d.getElementById('dataset-choice');select.value=value;select.dispatchEvent(new f.dom.window.Event('change',{bubbles:true}));}
function type(f,id,text){const input=f.d.getElementById(id);Object.getOwnPropertyDescriptor(f.dom.window.HTMLInputElement.prototype,'value').set.call(input,text);input.dispatchEvent(new f.dom.window.Event('input',{bubbles:true}));}
const click=(f,text)=>{const b=[...f.d.querySelectorAll('button')].find(b=>b.textContent===text);assert(b,'Missing button '+text);b.click();return b;};

test('dataset picker appears only when the dataset intake is configured and loads that dataset',async()=>{
    const f=setup();try{
        await wait(()=>f.d.getElementById('dataset-choice'));choose(f,'TRANSFER_HISTORY');
        await wait(()=>f.calls.some(c=>c.url==='/api/research/intake/datasets/TRANSFER_HISTORY/batches/0'));
        assert(f.d.body.textContent.includes('Transfers imports'));
        assert(f.d.getElementById('source-system'));assert(!f.calls.some(c=>c.options.method==='POST'));
    }finally{f.dom.window.close();}
    const g=setup(u=>u.endsWith('/intake/capabilities')?response({configured:false,datasets:[]}):null);
    try{await wait(()=>g.d.getElementById('promotion-file'));await new Promise(r=>setTimeout(r,30));assert.equal(g.d.getElementById('dataset-choice'),null);}finally{g.dom.window.close();}
});

test('dataset preview sends the dataset code and the declared represented source system',async()=>{
    let body;const f=setup((u,o)=>u.endsWith('/intake/preview')?(body=JSON.parse(o.body),response({...pending,status:'PREVIEW_READY',row_acceptance:undefined})):null);
    try{await wait(()=>f.d.getElementById('dataset-choice'));choose(f,'TRANSFER_HISTORY');await wait(()=>f.d.getElementById('source-system'));
        const select=f.d.getElementById('source-system');select.value='POLICE_HR_IS';select.dispatchEvent(new f.dom.window.Event('change',{bubbles:true}));
        const bytes=new TextEncoder().encode('transfer_id\nT-1\n'),file={name:'transfers.csv',size:bytes.length,arrayBuffer:async()=>bytes.buffer};Object.defineProperty(f.d.getElementById('promotion-file'),'files',{value:[file]});
        type(f,'promotion-reference','HQ/TRF/ORDER/1');await new Promise(r=>setTimeout(r,10));click(f,'Validate and preview');
        await wait(()=>body);assert.equal(body.dataset,'TRANSFER_HISTORY');assert.equal(body.source_system,'POLICE_HR_IS');assert.equal(body.filename,'transfers.csv');
        await wait(()=>f.d.body.textContent.includes('2 · Inspect the preview'));assert(f.d.body.textContent.includes('T-1'));
    }finally{f.dom.window.close();}
});

test('IGP row review sends the exact evaluation reference and requires a reason and evidence reference',async()=>{
    let body;const accepted={...pending,row_acceptance:[{...pending.row_acceptance[0],status:'ACCEPTED',acceptance_basis:'INDEPENDENT_IGP_ROW_REVIEW'}]};
    const f=setup((u,o)=>u.endsWith('/intake/capabilities')?response(intake({can_upload:false,can_approve:true})):u.includes('/batches/')?response({items:[body?accepted:pending]}):
        u.endsWith('/intake/review')?(body=JSON.parse(o.body),response(accepted)):null,'IGP');
    try{await wait(()=>f.d.getElementById('dataset-choice'));choose(f,'TRANSFER_HISTORY');await wait(()=>f.d.body.textContent.includes('Accept row 1'));
        click(f,'Accept row 1');await wait(()=>f.d.body.textContent.includes('evidence reference'));assert.equal(body,undefined);
        const key=pending.batch_id+':1';type(f,'row-reason-'+key,'Signed transfer order inspected');type(f,'row-evidence-'+key,'HQ/TRF/ORDER/1');await new Promise(r=>setTimeout(r,10));
        click(f,'Accept row 1');await wait(()=>body);
        assert.deepEqual({row:body.row,decision:body.decision,evaluation_reference:body.evaluation_reference,expected_version:body.expected_version,evidence_reference:body.evidence_reference},
            {row:1,decision:'ACCEPT',evaluation_reference:'e'.repeat(64),expected_version:0,evidence_reference:'HQ/TRF/ORDER/1'});
        await wait(()=>f.d.body.textContent.includes('Row review recorded'));assert(f.d.body.textContent.includes('Independent IGP row review'));
    }finally{f.dom.window.close();}
});

test('blocking evidence conflicts disable acceptance; HQ never sees review controls',async()=>{
    const blocked={...pending,row_acceptance:[{...pending.row_acceptance[0],reasons:['FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE'],row_review_blocked:['FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE']}]};
    const f=setup(u=>u.endsWith('/intake/capabilities')?response(intake({can_upload:false,can_approve:true})):u.includes('/batches/')?response({items:[blocked]}):null,'IGP');
    try{await wait(()=>f.d.getElementById('dataset-choice'));choose(f,'TRANSFER_HISTORY');await wait(()=>f.d.body.textContent.includes('Accept row 1'));
        assert.equal([...f.d.querySelectorAll('button')].find(b=>b.textContent==='Accept row 1').disabled,true);
        assert(f.d.body.textContent.includes('different station than the officer’s current accepted posting'));
    }finally{f.dom.window.close();}
    const g=setup(u=>u.includes('/batches/')?response({items:[pending]}):null);
    try{await wait(()=>g.d.getElementById('dataset-choice'));choose(g,'TRANSFER_HISTORY');await wait(()=>g.d.body.textContent.includes('transfers.csv'));
        assert(![...g.d.querySelectorAll('button')].some(b=>/row 1/.test(b.textContent)));}finally{g.dom.window.close();}
});
