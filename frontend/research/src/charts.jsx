import React, {useState,useId} from 'react';
import {createRoot} from 'react-dom/client';
import {flushSync} from 'react-dom';

const roots=new Map();
const colors=['#2463a3','#167d75','#ba8130','#7a63aa','#bc5159','#65798f','#3e89bd','#989432'];
export function normalizeCounts(counts){
 if(!counts||typeof counts!=='object'||Array.isArray(counts))throw new Error('Chart counts are unavailable.');
 const values=Object.entries(counts);
 if(values.some(([k,v])=>!k||!Number.isSafeInteger(v)||v<0))throw new Error('Chart counts failed validation.');
 return values.sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));
}
export function countBy(items,key){const counts={};for(const item of items||[]){const label=String(item[key]??'Not recorded');counts[label]=(counts[label]||0)+1;}return counts;}
function CountsTable({entries,total}){return <details className="chart-data"><summary>View exact counts</summary><table><caption>Values used in this chart</caption><thead><tr><th scope="col">Category</th><th scope="col">Count</th><th scope="col">Share</th></tr></thead><tbody>{entries.map(([name,value])=><tr key={name}><th scope="row">{name.replaceAll('_',' ')}</th><td>{value}</td><td>{total?(value*100/total).toFixed(1)+'%':'—'}</td></tr>)}</tbody></table></details>;}
function Chart({counts,title,basis,type='bars'}){
 const entries=normalizeCounts(counts),total=entries.reduce((n,[,v])=>n+v,0),max=Math.max(1,...entries.map(([,v])=>v));
 const sortId=useId();const [selected,setSelected]=useState(null),[order,setOrder]=useState('count');
 const ordered=order==='name'?[...entries].sort((a,b)=>a[0].localeCompare(b[0])):entries;
 let cumulative=0;
 return <section className="data-chart" aria-label={title}><div className="chart-heading"><div><h4>{title}</h4><p>{basis}</p></div><strong className="chart-total">{total.toLocaleString()} <small>records</small></strong></div>
 {total===0?<p className="empty-text">No recorded values in this result. This does not establish an absence of evidence elsewhere.</p>:type==='donut'?<div className="donut-layout"><svg className="donut" viewBox="0 0 220 220" role="img" aria-label={title+': '+entries.map(([k,v])=>k+' '+v).join(', ')}><title>{title}</title><circle cx="110" cy="110" r="78" fill="none" stroke="#edf1f6" strokeWidth="26"/>{entries.filter(([,v])=>v>0).map(([k,v],i)=>{const length=v/total*490.088,offset=cumulative;cumulative+=length;return <circle key={k} cx="110" cy="110" r="78" fill="none" stroke={colors[i%colors.length]} strokeWidth={selected===k?32:26} strokeDasharray={`${length} ${490.088-length}`} strokeDashoffset={-offset} transform="rotate(-90 110 110)"><title>{k}: {v} ({(v*100/total).toFixed(1)}%)</title></circle>;})}<text x="110" y="107" textAnchor="middle" className="donut-total">{total}</text><text x="110" y="132" textAnchor="middle" className="donut-caption">reported records</text></svg><ul className="chart-legend">{entries.map(([name,value],i)=><li key={name}><button type="button" className={'legend-button palette-'+i%colors.length} aria-pressed={selected===name} onClick={()=>setSelected(selected===name?null:name)}><span className="legend-swatch" aria-hidden="true"/><span>{name.replaceAll('_',' ')}</span><strong>{value}</strong><small>{(value*100/total).toFixed(1)}%</small></button></li>)}</ul></div>:<><div className="chart-sort"><label htmlFor={sortId}>Sort ranks/categories<select id={sortId} value={order} onChange={e=>setOrder(e.target.value)}><option value="count">Count, highest first</option><option value="name">Name</option></select></label></div><div className="horizontal-bars">{ordered.map(([name,value],i)=><div className="bar-row" key={name}><span>{name.replaceAll('_',' ')}</span><svg viewBox="0 0 400 22" role="img" aria-label={name+': '+value}><title>{name}: {value}</title><rect width="400" height="22" rx="5" fill="#edf1f6"/><rect width={value/max*400} height="22" rx="5" fill={colors[i%colors.length]}/></svg><strong>{value}</strong></div>)}</div></>}
 <CountsTable entries={entries} total={total}/></section>;
}
export function clearChart(id){const r=roots.get(id);if(r){flushSync(()=>r.unmount());roots.delete(id);}const target=document.getElementById(id);if(target)target.replaceChildren();}
export function clearCharts(){for(const id of [...roots.keys()])clearChart(id);}
export function mountChart(id,counts,title,basis,type='bars'){
 const target=document.getElementById(id);if(!target)return;try{const values=normalizeCounts(counts);if(!Number.isSafeInteger(values.reduce((n,[,v])=>n+v,0)))throw new Error();}catch{clearChart(id);target.textContent='Chart unavailable: counts failed validation. Read the retained evidence below.';return;}
 // A new response resets chart selection and drops the preceding private values.
 clearChart(id);const root=createRoot(target);roots.set(id,root);
 try{flushSync(()=>root.render(<Chart counts={counts} title={title} basis={basis} type={type}/>));}
 catch{clearChart(id);target.textContent='Chart unavailable: counts failed validation. Read the retained evidence below.';}
}
