'use strict';
// Strict JSON parser for provider/configuration boundaries; rejects duplicate object keys.
function parseUnique(text){
  if(typeof text!=='string'||text.length>1000000)throw new Error('Bounded JSON required');
  let i=0;const space=()=>{while(/[\x20\t\r\n]/.test(text[i]||'')&&i<text.length)i++;};
  const fail=()=>{throw new Error('Invalid or duplicate JSON');};
  function string(){const start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"')return JSON.parse(text.slice(start,i));}fail();}
  function value(depth=0){if(depth>64)fail();space();const ch=text[i];if(ch==='"')return string();if(ch==='{'){i++;space();const obj={},seen=new Set();if(text[i]==='}'){i++;return obj;}while(true){space();if(text[i]!=='"')fail();const key=string();if(seen.has(key))fail();seen.add(key);space();if(text[i++]!==':')fail();Object.defineProperty(obj,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});space();const c=text[i++];if(c==='}')return obj;if(c!==',')fail();}}
    if(ch==='['){i++;space();const a=[];if(text[i]===']'){i++;return a;}while(true){a.push(value(depth+1));space();const c=text[i++];if(c===']')return a;if(c!==',')fail();}}
    const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));if(!match)fail();i+=match[0].length;return JSON.parse(match[0]);}
  const v=value();space();if(i!==text.length)fail();return v;
}
module.exports={parseUnique};
