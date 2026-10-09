// Run with node --test tests/dashboard.test.cjs; no browser or extra dependencies required.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(new URL('../trust/dashboard.html', `file://${__filename}`), 'utf8').split('<script>')[1].split('</script>')[0];
function harness({withArt=false, reducedMotion=true}={}) {
  const elements = new Map(), selectors = new Map(), posts = [], alerts = [], timers = [], frames = [];
  let lastQueue='', lastAttempts='';
  function element(dataset={}) { return {attrs:{},style:{},dataset, value:'', hidden:false, innerHTML:'', writes:0, textContent:'', classList:{add(){},remove(){},toggle(){}},setAttribute(k,v){this.attrs[k]=v;},removeAttribute(k){delete this.attrs[k];},scrollIntoView(){},focus(){}}; }
  const get = s => { if (!elements.has(s)) {const e=element();let html='';Object.defineProperty(e,'innerHTML',{get:()=>html,set:v=>{html=v;e.writes++}});elements.set(s,e);} return elements.get(s); };
  const nav = ['overview','fixes','decisions'].map(view=>element({view})); selectors.set('[data-view]', nav);
  const decisions=['retry','ship','hold'].map(d=>element({d}));selectors.set('#calls button',decisions);
  const parts = new Map();
  const part = key => {if(!parts.has(key))parts.set(key,element());return parts.get(key);};
  const art = {querySelector:s=>s.includes('jaw')?{querySelector:k=>part(s+' '+k)}:part(s),querySelectorAll:()=>[part('wing-left'),part('wing-right')]};
  const document = {hidden:false,addEventListener(){},querySelector:get, querySelectorAll:s=> {
    if(s==='.trap-art') return withArt?[art]:[];
    if(s==='[data-fix-index]' && get('#fixes').innerHTML !== lastQueue) {lastQueue=get('#fixes').innerHTML;selectors.set(s,[...lastQueue.matchAll(/data-fix-index="(\d+)"/g)].map(m=>element({fixIndex:m[1]})));}
    if(s==='[data-attempt]' && get('#evidence').innerHTML !== lastAttempts) {lastAttempts=get('#evidence').innerHTML;selectors.set(s,[...lastAttempts.matchAll(/data-attempt="(\d+)"/g)].map(m=>element({attempt:m[1]})));}
    return selectors.get(s)||[];
  }};
  let rows=[], ok=true, postOK=true, networkError=false;
  const context=vm.createContext({document,fetch:async(url,options)=>{
    if(options) {if(networkError) throw Error('offline');posts.push(JSON.parse(options.body));return {ok:postOK,json:async()=>({detail:'No escalation is waiting'})};}
    return {ok,json:async()=>url==='/api/config'?{}:{ledger:'test',rows}};
  },performance:{now:()=>0},requestAnimationFrame:fn=>{frames.push(fn);return frames.length;},cancelAnimationFrame(){},setInterval(){},setTimeout:(fn,delay)=>{fn.delay=delay;timers.push(fn);return fn;},clearTimeout:fn=>{const i=timers.indexOf(fn);if(i>=0)timers.splice(i,1);},alert:m=>alerts.push(m),window:{matchMedia:()=>({matches:reducedMotion}),location:{hash:"#workspace"},addEventListener(){},scrollTo(){}},Date,Map});
  vm.runInContext(source,context);
  return {get,nav,decisions,posts,alerts,context,timers,frames,parts,buttons:s=>document.querySelectorAll(s),setPostOK:v=>postOK=v,setNetworkError:v=>networkError=v,setRows:r=>rows=r,setOK:v=>ok=v,run:s=>vm.runInContext(s,context),refresh:()=>vm.runInContext('refresh()',context)};
}
const row = (id='users', changes={})=>({fix_id:id,file:`app/${id}.py`,rule_id:'sql.injection',vuln_class:'SQL injection',attempt:1,verdict:'proven',exploit_pre:true,exploit_post:false,semgrep_clear:true,suite_pass:true,scope_clean:true,evidence:'{"function":"search","diff":"<script>bad</script>"}',...changes});
test('selection, attempt history, escaped evidence, and stable polling',async()=>{
  const h=harness();h.setRows([row(),row('admin',{verdict:'failed',suite_pass:false}),row('admin',{attempt:2})]);await h.refresh();
  assert.equal(h.get('#count-total').textContent,2);assert.equal(h.get('#count-proven').textContent,2);
  assert.match(h.get('#evidence').innerHTML,/app\/admin.py/);assert.match(h.get('#evidence').innerHTML,/6 of 6 passed/);
  assert.match(h.get('#evidence').innerHTML,/&lt;script&gt;/);assert.doesNotMatch(h.get('#evidence').innerHTML,/<script>/);
  const writes=h.get('#evidence').writes;await h.refresh();assert.equal(h.get('#evidence').writes,writes,'polling preserves expanded details');
  h.buttons('[data-attempt]')[0].onclick();assert.match(h.get('#evidence').innerHTML,/5 of 6 passed/);assert.match(h.get('#evidence').innerHTML,/gate fail/);
  h.buttons('[data-fix-index]')[1].onclick();await h.refresh();assert.match(h.get('#evidence').innerHTML,/app\/users.py/);
  h.setRows([row(),row('new',{verdict:'failed'}),row('new',{verdict:'escalated',decision:''})]);await h.refresh();
  assert.match(h.get('#evidence').innerHTML,/app\/new.py/,'a new escalation gets attention');
});
test('pending decisions filter, selected fix payloads, and hint persistence',async()=>{
  const h=harness();h.setRows([row(),row('admin',{verdict:'failed'}),row('admin',{attempt:2,verdict:'escalated',decision:''})]);await h.refresh();
  assert.equal(h.get('#count-waiting').textContent,1);assert.equal(h.get('#call-section').hidden,false);
  h.get('#hint').value='keep this hint';await h.refresh();assert.equal(h.get('#hint').value,'keep this hint');
  for(const b of h.decisions){await b.onclick();assert.deepEqual(h.posts.at(-1),{fix_id:'admin',decision:b.dataset.d,hint:'keep this hint'});}
  h.nav[2].onclick();assert.equal(h.get('#stats').hidden,true);assert.equal(h.get('#queue-count').textContent,'1 fix');assert.doesNotMatch(h.get('#fixes').innerHTML,/app\/users.py/);
  h.setRows([row(),row('admin',{verdict:'failed'}),row('admin',{attempt:2,verdict:'escalated',decision:'hold'})]);await h.refresh();
  assert.equal(h.get('#call-section').hidden,true);assert.equal(h.get('#count-waiting').textContent,0);
  // Decided fixes stay on the Decisions tab as a record, with what was decided.
  assert.match(h.get('#fixes').innerHTML,/app\/admin.py/);assert.match(h.get('#fixes').innerHTML,/Decided: hold/);assert.doesNotMatch(h.get('#fixes').innerHTML,/app\/users.py/);
});
test('missing checks do not show pass, empty state, and disconnect keeps evidence',async()=>{
  const h=harness();await h.refresh();assert.match(h.get('#evidence').innerHTML,/Ready for the first repair/);
  assert.equal((h.get('#evidence').innerHTML.match(/gate unknown/g)||[]).length,6);
  h.setRows([row('users',{scope_clean:null,suite_pass:null})]);await h.refresh();assert.match(h.get('#evidence').innerHTML,/4 of 6 passed/);
  const html=h.get('#evidence').innerHTML;h.setOK(false);await h.refresh();assert.equal(h.get('#evidence').innerHTML,html);assert.match(h.get('#meta').textContent,/Server unreachable/);
});

test('multiple pending fixes submit to the selected fix; failed requests restore controls',async()=>{
  const h=harness();h.setRows([row('one',{verdict:'failed'}),row('one',{verdict:'escalated',decision:''}),row('two',{verdict:'failed'}),row('two',{verdict:'escalated',decision:''})]);await h.refresh();
  h.buttons('[data-fix-index]')[1].onclick();h.get('#hint').value='hint for one';await h.decisions[0].onclick();
  assert.equal(h.posts.at(-1).fix_id,'one');assert.equal(h.posts.at(-1).hint,'hint for one');
  h.setPostOK(false);await h.decisions[1].onclick();assert.equal(h.alerts.at(-1),'No escalation is waiting');assert(h.decisions.every(b=>!b.disabled));
  h.setNetworkError(true);await h.decisions[2].onclick();assert.match(h.alerts.at(-1),/Could not send the decision/);assert(h.decisions.every(b=>!b.disabled));
});

test('field guide and workspace navigation preserve the selected fix and hint',async()=>{
  const h=harness();h.setRows([row('admin',{verdict:'failed'}),row('admin',{verdict:'escalated',decision:''})]);await h.refresh();
  h.get('#hint').value='keep my draft';h.run('window.location.hash="#story";showPage()');
  assert.equal(h.get('#product').hidden,true);assert.equal(h.get('#story').hidden,false);
  h.run('window.location.hash="#workspace";showPage()');assert.equal(h.get('#product').hidden,false);assert.equal(h.get('#story').hidden,true);
  assert.match(h.get('#evidence').innerHTML,/app\/admin.py/);assert.equal(h.get('#hint').value,'keep my draft');
});
test('the voice widget gets the spoken brief, not raw evidence', async()=>{
  const h=harness();await new Promise(r=>setTimeout(r,0));h.run('agentId="agent_test"');  // after the startup config load
  const brief={fix_id:'admin',vuln_class:'SQL injection',file:'app/admin.py',failed_check:'the fix closes the hole but breaks the admin test for orders custom sort expression',attempts:2,failing_tests:'the admin test for orders custom sort expression'};
  h.setRows([row('admin',{verdict:'failed'}),row('admin',{attempt:2,verdict:'escalated',decision:'',failing_tests:['tests/test_admin.py::test_orders_custom_sort_expression'],evidence:JSON.stringify({reasons:['existing suite failed: tests/test_admin.py::test_orders_custom_sort_expression'],brief})})]);
  await h.refresh();
  const html=h.get('#calls').innerHTML;
  assert.match(html,/elevenlabs-convai/);
  assert.match(html,/the fix closes the hole but breaks the admin test/);
  assert.doesNotMatch(html,/dynamic-variables='[^']*::/);
  assert.match(html,/&quot;attempts&quot;:&quot;2&quot;/);
});

test('flytrap catches each new fix once, queues arrivals, and ignores initial history or retries',async()=>{
  const h=harness();h.setRows([row('existing')]);await h.refresh();assert.equal(h.timers.length,0);
  h.setRows([row('existing'),row('new',{verdict:'failed'}),row('another',{verdict:'failed'})]);await h.refresh();
  assert.equal(h.timers.length,1);assert.match(h.get('#capture-live').textContent,/new.py/);assert.equal(h.run('captureQueue.length'),1);
  await h.refresh();assert.equal(h.timers.length,1,'polling does not replay the catch');
  h.timers.shift()();assert.match(h.get('#capture-live').textContent,/another.py/);h.timers.shift()();assert.equal(h.run('captureActive'),false);assert.equal(h.run('trapAperture'),.14,'the trap stays closed after catching');
  h.setRows([row('existing'),row('new',{verdict:'failed'}),row('new',{attempt:2,verdict:'proven'}),row('another',{verdict:'failed'})]);await h.refresh();assert.equal(h.timers.length,0,'a retry is not a new finding');
});

test('articulated leaves retain volume, teeth remain visible, and the insect disappears after capture',()=>{
  const h=harness({withArt:true,reducedMotion:false});h.run('playCapture({file:"app/test.py"})');
  h.frames.shift()(650);assert(Number(h.parts.get('.trap-bug').style.opacity)>0,'insect approaches before the snap');
  h.frames.shift()(1005);
  for(const jaw of ['.upper-jaw','.lower-jaw']) {
    const movingTeeth=[...h.parts.get(jaw+' .leaf-teeth').attrs.d.matchAll(/M([\d.-]+) ([\d.-]+)L([\d.-]+) ([\d.-]+)/g)];
    for(const [,x,y,tx,ty] of movingTeeth) assert(Math.hypot(Number(tx)-Number(x),Number(ty)-Number(y))>=20,'teeth retain their length during the snap');
  }
  h.frames.shift()(1400);assert.equal(h.parts.get('.trap-bug').style.opacity,'0');assert.equal(h.parts.get('.upper-jaw .leaf-inner').style.opacity,'0');
  const outer=h.parts.get('.upper-jaw .leaf-outer').attrs.d;assert(!outer.includes('NaN'));assert.match(outer,/M84 173/);
  const lines=[...h.parts.get('.upper-jaw .leaf-teeth').attrs.d.matchAll(/M([\d.-]+) ([\d.-]+)L([\d.-]+) ([\d.-]+)/g)];
  assert.equal(lines.length,11);for(const [,x,y,tx,ty] of lines) assert(Math.hypot(Number(tx)-Number(x),Number(ty)-Number(y))>10,'teeth are not flattened with the leaves');
  h.timers.shift()();assert.equal(h.run('trapAperture'),.14);
});

test('diffs are coloured line by line and stay escaped', ()=>{
  const h=harness();
  const out=h.run(`diffHtml("--- a/app/x.py\\n+++ b/app/x.py\\n@@ -1 +1 @@\\n-rows = q + name\\n+rows = q(\\"?\\", <name>)\\n ctx\\n")`);
  assert.match(out,/<span class="d-file">--- a\/app\/x.py<\/span>/);
  assert.match(out,/<span class="d-hunk">@@ -1 \+1 @@<\/span>/);
  assert.match(out,/<span class="d-del">-rows = q \+ name<\/span>/);
  assert.match(out,/<span class="d-add">\+rows = q\(&quot;\?&quot;, &lt;name&gt;\)<\/span>/);
  assert.match(out,/<span class="d-ctx"> ctx<\/span>/);
});

test('call transcripts read as a conversation with tool steps', ()=>{
  const h=harness();
  const t=['agent: Hi, this is Trust Issues.','user: Which test broke?','agent: [read_ledger {"fix_id": "f1"}]',
    'agent: [calm] The admin sort test. Should I update it?','user: Yes. <b>now</b>',
    'agent: [write_decision {"decision": "retry", "fix_id": "f1", "hint": "update the admin sort test"}]','agent: [end_call {"reason": "done"}]'].join('\n');
  const out=h.run(`transcriptHtml(${JSON.stringify(t)})`);
  assert.match(out,/class="turn agent"><span class="who">Agent<\/span><p>Hi, this is Trust Issues.<\/p>/);
  assert.match(out,/class="turn user"><span class="who">On-call<\/span><p>Which test broke\?<\/p>/);
  assert.match(out,/↳ <b>Looked up the ledger<\/b>/);
  assert.match(out,/<p>The admin sort test. Should I update it\?<\/p>/, 'voice tags like [calm] are dropped');
  assert.match(out,/Recorded decision: retry · “update the admin sort test”/);
  assert.match(out,/↳ <b>Ended the call<\/b>/);
  assert.match(out,/Yes. &lt;b&gt;now&lt;\/b&gt;/, 'speech is escaped');
});

test('landing catches run automatically, pause outside the introduction, and never impersonate findings',async()=>{
  const h=harness({withArt:true,reducedMotion:false});await h.refresh();
  h.run('window.location.hash="#story";showPage()');
  assert.equal(h.timers.length,1);assert.equal(h.timers[0].delay,1800);
  const status=h.get('#trap-status').textContent, announcement=h.get('#capture-live').textContent;
  h.timers.shift()();assert.equal(h.run('captureActive'),true);assert.equal(h.posts.length,0);
  assert(h.timers.some(t=>t.delay>=8500&&t.delay<=12000),'repeat with a quiet, varying pause');
  h.timers.shift()();assert.equal(h.get('#trap-status').textContent,status);assert.equal(h.get('#capture-live').textContent,announcement);
  assert.equal(h.run('trapAperture'),1,'ambient catches do not change the live workspace pose');
  h.run('window.location.hash="#workspace";showPage()');assert.equal(h.timers.length,0);
  h.run('document.hidden=true;window.location.hash="#story";showPage()');assert.equal(h.timers.length,0,'hidden tabs stay quiet');
  const reduced=harness();reduced.run('window.location.hash="#story";showPage()');assert.equal(reduced.timers.length,0,'reduced-motion visitors get no ambient loop');
});

test('decisions tab keeps every human decision, waiting ones first', async()=>{
  const h=harness();
  h.setRows([
    row('old',{verdict:'failed'}),row('old',{attempt:2,verdict:'escalated',decision:'retry',hint:'update the sort test',ts:'2026-10-09T20:00:00'}),row('old',{attempt:3,verdict:'proven'}),
    row('new',{verdict:'failed'}),row('new',{attempt:2,verdict:'escalated',decision:'ship',ts:'2026-10-09T21:00:00'}),
    row('live',{verdict:'failed'}),row('live',{attempt:2,verdict:'escalated',decision:'',ts:'2026-10-09T19:00:00'}),
    row('quiet')]);
  await h.refresh();h.nav[2].onclick();
  const q=h.get('#fixes').innerHTML;
  assert.equal(h.get('#queue-count').textContent,'3 fixes');assert.doesNotMatch(q,/quiet.py/);
  assert(q.indexOf('live.py')<q.indexOf('new.py')&&q.indexOf('new.py')<q.indexOf('old.py'),'waiting first, then newest decision');
  assert.match(q,/Waiting on on-call/);assert.match(q,/Decided: ship/);assert.match(q,/Decided: retry · “update the sort test”/);
  assert.equal(h.get('#decision-count').textContent,3,'the badge counts every decision on the tab');
  assert.equal(h.get('#count-waiting').textContent,1,'the overview still shows what is waiting');
});
