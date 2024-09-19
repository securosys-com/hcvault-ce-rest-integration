!function(){"use strict"
let e=[],n=[]
var t
"serviceWorker"in navigator&&navigator.serviceWorker.register("/ui/sw.js",{scope:"/v1/sys/storage/raft/snapshot"}).then((function(n){let t=Promise.resolve()
for(let r=0,o=e.length;r<o;r++)t=t.then((function(){return e[r](n)}))
return t.then((function(){console.log("Service Worker registration succeeded. Scope is "+n.scope)}))})).catch((function(e){let t=Promise.resolve()
for(let r=0,o=n.length;r<o;r++)t=t.then((function(){return n[r](e)}))
return t.then((function(){console.log("Service Worker registration failed with "+e)}))})),t=function(e){window.addEventListener("unload",(function(){e.unregister()}))},e.push(t)}()
