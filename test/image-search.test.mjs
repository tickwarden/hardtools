import test from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicy } from '../dist/config.js';
import { imageSearch, thumbnailOK } from '../dist/image-search.js';

const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jWZkAAAAASUVORK5CYII=', 'base64');
const p = loadPolicy({ roots:[process.cwd()], override: {profile:'balanced'} });
const make = (over = {}, id = 17) => ({ pageid:id, index:id, title:'File:Deniz.png', imageinfo: [{ mime:'image/png', width:800, height:600, thumburl:'https://thumb.wikimedia.org/wikipedia/commons/thumb/a/ab/File.png/250px-File.png', extmetadata:{Artist:{value:'<span>Ada &amp; Deniz</span>'},LicenseShortName:{value:'CC BY 4.0'}}, ...over }] });
const response = (body, mime, status=200, truncated=false) => ({ response: {status, truncated, headers:{'content-type':mime}, body:Buffer.from(body)} });
function fake(pages, opts={}) {
  const calls=[];
  const get=async (policy, url, options) => {
    calls.push({ url, max:policy.net.maxBytes, options }); options.validateHop(url);
    if(url.hostname==='commons.wikimedia.org') return response(JSON.stringify({query:{pages},continue:{gsroffset:8}}),'application/json; charset=utf-8', opts.status);
    if(opts.redirect) options.validateHop(new URL(opts.redirect));
    return response(opts.body??png, opts.mime??'image/png', 200, opts.truncated);
  };
  return {calls,get};
}

test('image search: fixed API, original query encoded, rank/filter/page, attribution and displayable raster', async () => {
  const mock=fake([make({width:10,height:50},19),make({mime:'image/jpeg'},18),make()]);
  const r=await imageSearch(p,{query:'deniz & action=edit',limit:3,offset:5,orientation:'landscape',file_type:'png',thumbnail_width:250},mock.get);
  const u=mock.calls[0].url; assert.equal(u.origin,'https://commons.wikimedia.org'); assert.equal(u.searchParams.get('action'),'query'); assert.equal(u.searchParams.get('gsroffset'),'5'); assert.match(u.searchParams.get('gsrsearch'),/deniz & action=edit/);
  assert.deepEqual(r.content.map(c=>c.type),['text','text','image']); assert.match(r.content[0].text,/next_offset=8/);
  const m=JSON.parse(r.content[1].text); assert.equal(m.artist,'Ada & Deniz'); assert.equal(m.license,'CC BY 4.0'); assert.equal(m.source,'https://commons.wikimedia.org/?curid=17');
  assert.deepEqual(Buffer.from(r.content[2].data,'base64'),png); assert.ok(mock.calls[1].max<=256*1024);
});

test('image search: capped downloads, metadata-only mode, empty page, blocked provider',async()=>{
  const pages=Array.from({length:8},(_,i)=>make({},i+1));
  const a=fake(pages); const r=await imageSearch(p,{query:'x',limit:8},a.get); assert.equal(a.calls.length,4);assert.equal(r.content.filter(c=>c.type==='image').length,3);
  const b=fake(pages); await imageSearch(p,{query:'x',previews:false},b.get);assert.equal(b.calls.length,1);
  assert.match((await imageSearch(p,{query:'x'},fake([]).get)).content.at(-1).text,/No matching/);
  for(const net of [{enabled:false},{allowDomains:['example.org']},{requireAllowDomains:true}]){
    const c=fake(pages); await assert.rejects(imageSearch({...p,net:{...p.net,...net}},{query:'x'},c.get)); assert.equal(c.calls.length,0);
  }
  await assert.rejects(imageSearch(p,{query:'x'},fake([],{status:429}).get),/429/);
});

test('image search: no arbitrary image URLs, redirect destinations, active formats, truncated or oversized rasters',async()=>{
  const forbidden=['http://127.0.0.1/test','https://thumb.wikimedia.org.evil.test/x','https://user:pw@upload.wikimedia.org/x','https://upload.wikimedia.org:8080/x'];
  for(const thumburl of forbidden){ const c=fake([make({thumburl})]); const r=await imageSearch(p,{query:'x'},c.get); assert.equal(c.calls.length,1); assert.ok(!r.content.some(x=>x.type==='image')); }
  const huge=Buffer.from(png); huge.writeUInt32BE(99000,16);
  for(const opts of [{redirect:'https://other.example/x'},{mime:'image/svg+xml',body:'<svg/>'},{mime:'image/png',body:'<html>oops</html>'},{body:huge},{truncated:true}]){
    const r=await imageSearch(p,{query:'x'},fake([make()],opts).get); assert.ok(!r.content.some(x=>x.type==='image')); assert.match(r.content.at(-1).text,/source link/);
  }
  const r=await imageSearch({...p,net:{...p.net,allowDomains:['commons.wikimedia.org']}},{query:'x'},fake([make()]).get); assert.ok(!r.content.some(x=>x.type==='image'));
  assert.ok(!thumbnailOK(Buffer.alloc(1),'image/jpeg')); assert.ok(!thumbnailOK(Buffer.from('GIF89a'),'image/gif'));
});

// Original solid-gray PNG fixture, not a redistributed project logo.
const portrait = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAADQAAAA4CAAAAACX0YRMAAAAJElEQVR4nO3LMQ0AAAwDoDqv9XpYdsJPehBJkiRJkiRJkj7TAEXgpOxiMm8vAAAAAElFTkSuQmCC','base64');
test('project logo intent selects the official Fabric asset, respects filters and attributes the project, not a mod', async () => {
  for(const query of ['Fabric mod logo','Minecraft Fabric Loader LOGO','Fabric mod logosu']) {
    const c=fake([],{body:portrait});
    const r=await imageSearch(p,{query},c.get);
    assert.deepEqual(c.calls.map(c=>c.url.href),['https://fabricmc.net/assets/logo.png']);
    assert.ok(c.calls[0].max<=256*1024); assert.deepEqual(r.content.map(c=>c.type),['text','text','image']);
    const m=JSON.parse(r.content[1].text); assert.equal(m.source,'https://fabricmc.net/'); assert.equal(m.publisher,'FabricMC');
    assert.equal(m.license,null); assert.deepEqual([m.width,m.height],[52,56]); assert.deepEqual(Buffer.from(r.content[2].data,'base64'),portrait);
  }
  for(const a of [{offset:1},{orientation:'square'},{file_type:'jpeg'},{previews:false}]) {
    const c=fake([]);const r=await imageSearch(p,{query:'Fabric mod logo',...a},c.get); assert.equal(c.calls.length,0);assert.ok(!r.content.some(c=>c.type==='image'));
  }
  for(const query of ['Different Minecraft mod logo','Fabric API mod logo','Fabric furniture mod icon']) {
    const c=fake([]);const r=await imageSearch(p,{query},c.get); assert.equal(c.calls.length,0);assert.match(r.content[0].text,/No reliable/);
  }
});

test('Fabric logo never substitutes a Commons photo or an unapproved/unbounded preview', async () => {
  for(const opts of [{redirect:'https://other.example/logo.png'},{redirect:'https://fabricmc.net/user/file.png'},{mime:'text/html'},{body:png},{truncated:true}]) {
    const c=fake([],{body:portrait,...opts});const result=await imageSearch(p,{query:'Fabric mod logo'},c.get);
    assert.deepEqual(result.content.map(c=>c.type),['text']); assert.match(result.content[0].text,/No reliable.*Fabric/); assert.equal(c.calls.length,1);
  }
  for(const net of [{enabled:false},{allowDomains:['commons.wikimedia.org']},{requireAllowDomains:true}]) {
    const c=fake([]);await assert.rejects(imageSearch({...p,net:{...p.net,...net}}, {query:'Fabric mod logo',previews:false},c.get)); assert.equal(c.calls.length,0);
  }
});
