define("@embroider/macros/es-compat",["exports"],(function(e){"use strict"
Object.defineProperty(e,"__esModule",{value:!0}),e.default=function(e){return e?.__esModule?e:{default:e}}})),define("@embroider/macros/runtime",["exports"],(function(e){"use strict"
function o(e){return n.packages[e]}function r(){return n.global}Object.defineProperty(e,"__esModule",{value:!0}),e.config=o,e.each=function(e){if(!Array.isArray(e))throw new Error("the argument to the each() macro must be an array")
return e},e.getGlobalConfig=r,e.isTesting=function(){let e=n.global,o=e&&e["@embroider/macros"]
return Boolean(o&&o.isTesting)},e.macroCondition=function(e){return e}
const n={packages:{"/Users/tomaszmadej/hashicorp-vault-integration/ui/node_modules/ember-basic-dropdown/node_modules/ember-get-config":{modulePrefix:"vault"}},global:{"@embroider/macros":{isTesting:!1}}}
let t="undefined"!=typeof window?window._embroider_macros_runtime_config:void 0
if(t){let e={config:o,getGlobalConfig:r,setConfig(e,o){n.packages[e]=o},setGlobalConfig(e,o){n.global[e]=o}}
for(let o of t)o(e)}}))
