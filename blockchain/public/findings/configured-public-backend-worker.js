'use strict';
// Fixed backend entry; runtime path and digest are administrative argv only,
// never pipe-job fields, environment imports or arbitrary executable modules.
const {main}=require('./findings-public-backend-worker');
const {loadLocalRuntime}=require('./configured-public-runtime');
if(require.main===module){
    if(process.argv.length!==4)process.exitCode=1;
    else main(job=>loadLocalRuntime({file:process.argv[2],sha256:process.argv[3],job})).catch(()=>{process.exitCode=1;});
}
