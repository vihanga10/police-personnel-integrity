import {build} from 'vite';
import fs from 'node:fs/promises';
import {watch} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');process.chdir(root);
async function compile(){
await build();
const js=await fs.readFile('.vite-output/app.js');
for(const name of ['app','reviews','accountability'])await fs.writeFile(name+'.js',js);
for(const [leaf,page]of [['index','officers'],['reviews','reviews'],['accountability','accountability']]){
 const original=await fs.readFile('src/pages/'+leaf+'.template.html','utf8');
 const html=original.replace('<html lang="en">','<html lang="en" data-page="'+page+'">').replace('<body>','<body><div id="react-root">').replace('</body>','</div></body>');
 await fs.writeFile(leaf+'.html',html);
}
for(const leaf of ['styles','reviews','accountability']){
 const old=await fs.readFile('src/'+leaf+'.base.css','utf8'),modern=await fs.readFile('src/theme.css','utf8');
 await fs.writeFile(leaf+'.css',old+'\n'+modern);
}
console.log('Built all three React pages at the backend’s existing asset URLs.');
}
await compile();
if(process.argv.includes('--watch')){
 let timer,busy=false,queued=false;
 watch(path.join(root,'src'),{recursive:true},()=>{clearTimeout(timer);timer=setTimeout(async()=>{if(busy){queued=true;return;}busy=true;try{do{queued=false;await compile();}while(queued);}catch(e){console.error(e.message);}finally{busy=false;}},200);});
 console.log('Watching frontend sources. Restart the existing HTTPS server after a build to load its new static bytes.');
}
