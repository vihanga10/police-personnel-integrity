// Complete aggregation through the existing scoped browse endpoint. No persistence.
export async function collectDirectory({request,isCurrent,progress,pause,delay=1850}){
 const seen=new Set(),units=Object.create(null),divisions=Object.create(null),stations=Object.create(null);let offset=0,total=null,generation=null,available=0;
 const add=(counts,value)=>{const key=typeof value==='string'&&value.trim()?value:'Not recorded';counts[key]=(counts[key]||0)+1;};
 while(true){
  if(!isCurrent())return null;
  const result=await request({kind:'NAME',query:'',availability:'ALL',level:'ALL',scope_id:'',limit:50,offset});
  if(!isCurrent())return null;
  if(!result||!Array.isArray(result.items)||!Number.isSafeInteger(result.total)||result.total<0||result.total>10000||result.items.length>50)throw Error('Directory overview response failed validation.');
  if(total===null){total=result.total;generation=result.directory_generation;}
  if(result.total!==total||result.directory_generation!==generation||(result.offset!==undefined&&result.offset!==offset))throw Error('The directory changed during loading. Reload the complete overview.');
  const expected=Math.min(50,total-offset);
  if(result.items.length!==expected)throw Error('A directory page is incomplete. No complete overview was published.');
  for(const o of result.items){
   if(!o||typeof o.officer_uid!=='string'||!o.officer_uid||seen.has(o.officer_uid))throw Error('A directory identity was missing or repeated. Reload the complete overview.');
   seen.add(o.officer_uid);available+=o.details_available===true?1:0;
   add(units,o.unit_type);add(divisions,o.reported_posting?.division);add(stations,o.reported_posting?.station||o.reported_posting?.station_code);
  }
  offset+=result.items.length;
  progress({loaded:offset,total,available,stations:Object.keys(stations).filter(k=>k!=='Not recorded').length});
  if(offset===total)return {total,loaded:offset,available,units,divisions,stations,stationCount:Object.keys(stations).filter(k=>k!=='Not recorded').length};
  await pause(delay);
 }
}
