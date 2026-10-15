'use strict';
// Actual network requests from independent Chrome contexts; no router changes.
// Network enabled ONLY for these known public diagnostic URLs. No login/cookies.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const out=path.resolve(__dirname,'../dist/reliability');fs.mkdirSync(out,{recursive:true});
const targets=[
 {id:'gitlab',url:'https://gitlab.hotreload.net/assets/webpack/main.4e9cbf4e.chunk.js',bytes:1008147,hash:'5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777'},
 {id:'unitask',url:'https://download.openupm.com/verdaccio/com.cysharp.unitask/com.cysharp.unitask-2.5.11.tgz',bytes:180175,hash:'f502c3d1e56afee722c2707ba7370562446a6f3d4684a27afb74fd5817ab0a5b'},
 {id:'tavily',url:'https://app.tavily.com/home',bytes:25846,hash:'bb9228ba69540910159ef83d1fffb54fa90d329d39415da238e974a573886175'}];
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const rows=[];
 try {
  for(let repeat=0;repeat<3;repeat++){
   const context=await browser.newContext({ignoreHTTPSErrors:false});
   try{
    await context.route('**/*',route=>{
     if(targets.some(t=>route.request().url()===t.url))return route.continue();
     if(targets.some(t=>route.request().url()===new URL(t.url).origin+'/.zapret2-diagnostic-canary'))return route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Network diagnostic</title>'});
     return route.abort();
    });
    for(const target of targets){
     const page=await context.newPage(),cdp=await context.newCDPSession(page),meta=[];
     page.on('requestfailed',r=>meta.push({failed_url:r.url(),error:r.failure()?.errorText}));
     page.on('console',m=>{if(m.type()==='error')meta.push({console_error:m.text()});});
     await cdp.send('Network.enable');
     await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1});
     cdp.on('Network.responseReceived',e=>{if(e.response.url===target.url)meta.push({protocol:e.response.protocol,remoteIPAddress:e.response.remoteIPAddress,status:e.response.status,connectionReused:e.response.connectionReused});});
     const start=Date.now();let row={target:target.id,repeat,metadata:meta};
     try{
      await page.goto(new URL(target.url).origin+'/.zapret2-diagnostic-canary');
      const data=await page.evaluate(async url=>{
       const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),20000);
       try{
        const response=await fetch(url,{signal:ctrl.signal,cache:'no-store'});
        const bytes=new Uint8Array(await response.arrayBuffer());let text='';
        for(let i=0;i<bytes.length;i+=8192)text+=String.fromCharCode(...bytes.subarray(i,i+8192));
        return {status:response.status,base64:btoa(text)};
       }finally{clearTimeout(timer);}
      },target.url);
      const body=Buffer.from(data.base64,'base64');
      row={...row,status:data.status,bytes:body.length,sha256:crypto.createHash('sha256').update(body).digest('hex')};
      row.full_hash_match=row.status===200&&row.bytes===target.bytes&&row.sha256===target.hash;
     }catch(error){row.error=error.message;row.full_hash_match=false;}
     row.duration_ms=Date.now()-start;rows.push(row);fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify(rows,null,2));console.log(JSON.stringify(row));
     await page.close();
    }
   }finally{await context.close();}
  }
 }finally{await browser.close();}
 console.log(JSON.stringify({trials:rows.length,successes:rows.filter(r=>r.full_hash_match).length,failures:rows.filter(r=>!r.full_hash_match)}));
})().catch(e=>{console.error(e);process.exitCode=1;});
