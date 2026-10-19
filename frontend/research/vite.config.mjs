import {defineConfig} from 'vite';
export default defineConfig({define:{'process.env.NODE_ENV':'"production"'},build:{target:'es2022',minify:true,lib:{entry:'src/entry.jsx',name:'PolicePersonnelUI',formats:['iife'],fileName:()=> 'app.js'},outDir:'.vite-output',emptyOutDir:true}});
