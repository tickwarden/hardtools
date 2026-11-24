// Ortak arayüz: tüm tarayıcı sayfaları (OAuth, davet, form, ayarlar) buradan geçer.
// - Koyu mod (varsayılan) ve "kör mod" (aşırı beyaz olmayan sıcak açık tema) localStorage'da saklanır.
// - Form gönderen butonlar tekrar basılmasın diye hemen devre dışı kalır, işlem bitince geri açılır.
// - Tek bir yerde tutulan CSS: sayfalar arasında tutarlılık ve bakım kolaylığı.

export const esc = (v: unknown): string =>
  String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

/** Sayfaların inline script çalıştırmasına izin veren, dış kaynak yüklemeyen CSP. */
export const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

const CSS = `
:root{--w:34rem;color-scheme:dark}
:root[data-theme="dark"]{--bg:#14171c;--panel:#1c212a;--panel2:#232936;--fg:#e7ebf2;--muted:#9aa4b6;--line:#2f3644;--accent:#7aa7ff;--accent-fg:#0e1420;--ok:#57c08a;--err:#ff8b8b;--warn:#e8c07d}
:root[data-theme="light"]{--bg:#e7e2d6;--panel:#f2eee3;--panel2:#e9e4d7;--fg:#241f18;--muted:#5e574b;--line:#cfc7b6;--accent:#2f4f7a;--accent-fg:#f6f2e8;--ok:#1f6b45;--err:#9c2b2b;--warn:#7a5a13}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;min-height:100vh}
a{color:var(--accent)}
.top{display:flex;align-items:center;gap:.6rem;padding:.7rem 1rem;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
.brand{font-weight:700;letter-spacing:.02em}
.brand small{font-weight:400;color:var(--muted);margin-left:.4rem}
.spacer{flex:1}
main{max-width:var(--w);margin:2.2rem auto 4rem;padding:0 1rem}
h1{font-size:1.45rem;margin:0 0 1rem}
h2{font-size:1.05rem;margin:1.8rem 0 .6rem;color:var(--fg)}
p{margin:.6rem 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:.8rem;padding:1rem 1.1rem;margin:1rem 0}
label{display:block;margin:.7rem 0 .3rem;font-size:.92rem;color:var(--muted)}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;padding:.6rem .7rem;border-radius:.5rem;border:1px solid var(--line);background:var(--panel2);color:var(--fg);font:inherit}
textarea{min-height:6rem;resize:vertical}
input:focus,textarea:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px}
button,.btn{font:inherit;padding:.55rem 1rem;border-radius:.5rem;border:1px solid var(--line);background:var(--panel2);color:var(--fg);cursor:pointer}
button:hover:not(:disabled){border-color:var(--accent)}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent);font-weight:600}
button.ghost{background:transparent}
button:disabled{opacity:.55;cursor:progress}
button[aria-pressed="true"]{outline:2px solid var(--accent);outline-offset:1px}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(13rem,1fr));gap:.5rem}
.chip{display:flex;align-items:center;gap:.5rem;background:var(--panel2);border:1px solid var(--line);border-radius:.6rem;padding:.45rem .6rem;font-size:.92rem}
.chip input{accent-color:var(--accent)}
code,kbd{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.95em;background:var(--panel2);border:1px solid var(--line);border-radius:.35rem;padding:.05rem .35rem}
.code{font-size:1.35em;letter-spacing:.16em}
.muted{color:var(--muted)}
.e{color:var(--err)}
.ok{color:var(--ok)}
.warn{color:var(--warn)}
ul.clean{list-style:none;padding:0;margin:.4rem 0}
ul.clean li{display:flex;gap:.5rem;align-items:center;padding:.35rem 0;border-bottom:1px solid var(--line)}
ul.clean li:last-child{border-bottom:0}
table{width:100%;border-collapse:collapse;font-size:.93rem}
th,td{text-align:left;padding:.45rem .3rem;border-bottom:1px solid var(--line);vertical-align:top}
.foot{max-width:var(--w);margin:0 auto 3rem;padding:0 1rem;color:var(--muted);font-size:.85rem}
.pill{font-size:.78rem;padding:.1rem .5rem;border-radius:1rem;border:1px solid var(--line);color:var(--muted)}
.pill.on{color:var(--ok);border-color:var(--ok)}
.pill.off{color:var(--err);border-color:var(--err)}
`;

// Tema: localStorage > sistem tercihi > koyu. "Kör mod" aşırı beyaz olmayan sıcak açık tema.
const THEME_JS = `
(function(){
  var KEY='ht-theme';
  function apply(t){document.documentElement.setAttribute('data-theme',t);
    var d=document.getElementById('b-dark'),l=document.getElementById('b-light');
    if(d&&l){d.setAttribute('aria-pressed',String(t==='dark'));l.setAttribute('aria-pressed',String(t==='light'));}}
  var saved=null;try{saved=localStorage.getItem(KEY)}catch(e){}
  var sys=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
  apply(saved||sys);
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-theme-set]');if(!b)return;
    var t=b.getAttribute('data-theme-set');apply(t);try{localStorage.setItem(KEY,t)}catch(err){}
  });
})();`;

// Tek gönderim: butona basıldığı anda disabled, iş bitince (veya hata olursa) geri açılır.
const GUARD_JS = `
(function(){
  function busy(btn){
    if(!btn||btn.disabled)return false;
    btn.dataset.label=btn.textContent;btn.disabled=true;btn.setAttribute('aria-busy','true');btn.textContent='İşleniyor…';
    setTimeout(function(){if(!btn.isConnected)return;btn.disabled=false;btn.removeAttribute('aria-busy');
      if(btn.dataset.label)btn.textContent=btn.dataset.label;},20000);
    return true;
  }
  document.addEventListener('submit',function(e){
    var f=e.target;if(!f||f.tagName!=='FORM')return;
    // Zaten gönderiliyorsa ikinci gönderimi engelle.
    if(f.dataset.sending==='1'){e.preventDefault();return;}
    var btn=f.querySelector('button[type="submit"],button:not([type]),input[type="submit"]');
    if(btn&&btn.disabled){e.preventDefault();return;}
    f.dataset.sending='1';
    busy(btn);
  },true);
  document.addEventListener('click',function(e){
    var b=e.target.closest('button[data-once]');if(b)busy(b);
  },true);
  // Sunucu hatası sayfayı yeniden basarsa form kilitli kalmasın.
  window.addEventListener('pageshow',function(){document.querySelectorAll('form[data-sending="1"]').forEach(function(f){
    delete f.dataset.sending;f.querySelectorAll('button[aria-busy]').forEach(function(b){b.disabled=false;b.removeAttribute('aria-busy');if(b.dataset.label)b.textContent=b.dataset.label;});});});
})();`;

export interface PageOptions {
  title: string;
  body: string;
  /** Sayfaya özel ek stil. */
  css?: string;
  /** Sayfaya özel ek script (inline). */
  script?: string;
  /** Üst çubukta "hardtools" yanında gösterilecek küçük yazı. */
  subtitle?: string;
  /** Üst çubukta sağa eklenen HTML (ör. kullanıcı adı, çıkış). */
  actions?: string;
}

export function page(o: PageOptions): string {
  return `<!doctype html>
<html lang="tr" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>${esc(o.title)} · hardtools</title>
<style>${CSS}${o.css ?? ""}</style>
</head>
<body>
<div class="top">
  <span class="brand">hardtools${o.subtitle ? `<small>${esc(o.subtitle)}</small>` : ""}</span>
  <span class="spacer"></span>
  ${o.actions ?? ""}
  <button type="button" class="ghost" id="b-dark" data-theme-set="dark" title="Koyu mod">Koyu</button>
  <button type="button" class="ghost" id="b-light" data-theme-set="light" title="Kör mod: aşırı beyaz olmayan açık tema">Kör mod</button>
</div>
<main>${o.body}</main>
<div class="foot">hardtools · sayfa verisi çerezde tutulmaz; kimlik bilgileri yalnızca sunucuda doğrulanır.</div>
<script>${THEME_JS}</script>
<script>${GUARD_JS}</script>
${o.script ? `<script>${o.script}</script>` : ""}
</body>
</html>`;
}

/** Basit ortak başlık + açıklama bloğu. */
export function heading(title: string, note?: string): string {
  return `<h1>${esc(title)}</h1>${note ? `<p class="muted">${esc(note)}</p>` : ""}`;
}
