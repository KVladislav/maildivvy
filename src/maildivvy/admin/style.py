"""The interface's one stylesheet.

`DESIGN` is the predecessor's approved design system, its stylesheet taken unchanged: the
tokens in `:root`, the shell, boxes and tables, badges, buttons and inputs, flashes and
zones, and the bare sign-in page. A screen's markup is written to its classes.

`MAILDIVVY` follows it, marked, and holds only what the design never had. It speaks in the
design's tokens: a colour in it is a `var(--...)`, never a value of its own.

`page()` inlines `STYLESHEET` into every page: no static route, no web font, no dark
scheme, and nothing the stylesheet fetches.
"""

DESIGN = """:root{
  color-scheme: light;
  --bg:#ffffff; --bg-subtle:#f6f7f9; --bg-inset:#eceef1;
  --border:#d3d8de; --border-strong:#b9c1ca;
  --fg:#1b1f24; --fg-muted:#59636e; --fg-subtle:#6b7480;
  --accent:#1a5fd0; --accent-hover:#164fae; --accent-soft:#e8f0fc; --accent-border:#b7cdf3;
  --danger:#c2262e; --danger-hover:#a51f26; --danger-soft:#fbeaea; --danger-border:#e9a5a8;
  --attn:#8a5b00; --attn-soft:#fff5d6; --attn-border:#e6c76a;
  --ok:#15712f; --ok-soft:#e6f4ea; --ok-border:#a6d7b3;
  --radius:6px; --control:32px;
  --font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{font-family:var(--font);font-size:14px;line-height:1.5;color:var(--fg);background:var(--bg);
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased;caret-color:var(--accent)}
body{margin:0;min-height:100vh;background:var(--bg)}
::selection{background:var(--accent-soft);color:var(--fg)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
[hidden]{display:none!important}
a{color:var(--accent);text-decoration:none;text-underline-offset:.18em}
a:hover{text-decoration:underline}
h1,h2,h3{margin:0;font-weight:600;letter-spacing:-.01em;text-wrap:balance}
h1{font-size:24px;line-height:1.25}
h2{font-size:16px;line-height:1.3}
h3{font-size:14px}
p{margin:0}
code,.mono{font-family:var(--mono);font-size:.93em}
small,.muted{color:var(--fg-muted)}
.subtle{color:var(--fg-subtle)}
hr{border:0;border-top:1px solid var(--border);margin:0}

/* shell */
.topbar{height:48px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;
  border-bottom:1px solid var(--border);background:var(--bg);position:sticky;top:0;z-index:5}
.brand{font-weight:600;color:var(--fg);letter-spacing:-.01em}
.brand:hover{text-decoration:none;color:var(--accent)}
.session{display:flex;align-items:center;gap:14px;color:var(--fg-muted)}
.session form{margin:0}
.shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:calc(100vh - 48px)}
.nav{border-right:1px solid var(--border);background:var(--bg-subtle);padding:16px 12px}
.nav ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 10px;border-radius:var(--radius);
  color:var(--fg);transition:background .15s ease-out}
.nav a:hover{background:var(--bg-inset);text-decoration:none}
.nav a[aria-current="page"]{background:var(--bg);box-shadow:inset 3px 0 0 var(--accent);font-weight:600}
.nav .n{color:var(--fg-subtle);font-size:12px}
.nav .sep{height:1px;background:var(--border);margin:8px 6px}
main{padding:28px 32px 96px;max-width:1104px;width:100%;min-width:0}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:20px}
.page-head .lede{margin-top:4px;color:var(--fg-muted);max-width:70ch}
.page-head .actions{display:flex;gap:8px;flex-shrink:0;padding-top:2px}
.crumbs{font-size:13px;color:var(--fg-muted);margin-bottom:6px}
.crumbs a{color:var(--fg-muted)}
.stack{display:flex;flex-direction:column;gap:20px}
.narrow{max-width:640px}

/* boxes and tables */
.box{border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);overflow:hidden}
.box-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 16px;background:var(--bg-subtle);border-bottom:1px solid var(--border)}
.box-head h2{font-size:14px}
.box-body{padding:16px}
.box-body + .box-body{border-top:1px solid var(--border)}
.count{display:inline-block;min-width:20px;padding:0 6px;border-radius:10px;background:var(--bg-inset);color:var(--fg-muted);font-size:12px;font-weight:600;text-align:center;margin-left:6px;line-height:20px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:500;color:var(--fg-muted);font-size:12px;padding:8px 16px;background:var(--bg-subtle);border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:10px 16px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr{transition:background .15s ease-out}
tbody tr:hover{background:#fafbfc}
td.acts,th.acts{text-align:right;white-space:nowrap}
td.acts .muted{white-space:normal;display:inline-block;max-width:16ch;text-align:right}
.compact td,.compact th{padding-left:12px;padding-right:12px}
.compact .row-sub{max-width:24ch}
td.acts form{display:inline}
td code,th code{white-space:nowrap}
td:first-child{white-space:nowrap}
td.wrap,td.wrap code{white-space:normal;overflow-wrap:anywhere}
.row-sub{white-space:normal}
td.num,th.num{text-align:right}
.row-sub{display:block;color:var(--fg-muted);font-size:13px;margin-top:2px}
.list{list-style:none;margin:0;padding:0}
.list li{display:flex;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);align-items:flex-start}
.list li:last-child{border-bottom:0}
.list .ico{flex-shrink:0;margin-top:3px}
dl.facts{display:grid;grid-template-columns:max-content 1fr;gap:6px 20px;margin:0}
dl.facts dt{color:var(--fg-muted)}
dl.facts dd{margin:0}
.kv{display:flex;flex-wrap:wrap;gap:8px 32px;margin:12px 0 4px}
.kv b{font-size:20px;font-weight:600;display:block;line-height:1.2}
.kv span{color:var(--fg-muted);font-size:13px}

/* badges */
.badge{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 8px;border-radius:11px;border:1px solid var(--border-strong);
  font-size:12px;font-weight:500;color:var(--fg-muted);background:var(--bg);white-space:nowrap;vertical-align:middle}
.badge.ok{color:var(--ok);border-color:var(--ok-border);background:var(--ok-soft)}
.badge.bad{color:var(--danger);border-color:var(--danger-border);background:var(--danger-soft)}
.badge.attn{color:var(--attn);border-color:var(--attn-border);background:var(--attn-soft)}
.badge.off{color:var(--fg-muted);border-color:var(--border);background:var(--bg-subtle)}
.switch{display:inline-flex;align-items:center;gap:8px;height:26px;padding:0;border:0;background:none;font:inherit;font-weight:500;color:var(--fg);cursor:pointer;border-radius:13px;white-space:nowrap;text-align:left}
.switch .knob{width:34px;height:20px;border-radius:10px;background:var(--border-strong);position:relative;flex-shrink:0;transition:background .15s ease-out}
.switch .knob::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(27,31,36,.25);transition:left .15s ease-out}
.switch.on .knob{background:var(--ok)} .switch.on .knob::after{left:16px}
.switch.asked .knob{background:var(--attn)} .switch.asked .knob::after{left:9px}
.switch[disabled]{cursor:default;opacity:1}
.switch:hover:not([disabled]) .knob{filter:brightness(.92)}
.state-bad{color:var(--danger)}
.state-attn{color:var(--attn)}
.state-ok{color:var(--ok)}

/* buttons and inputs */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:var(--control);padding:0 12px;border-radius:var(--radius);
  border:1px solid var(--border-strong);background:var(--bg-subtle);color:var(--fg);font:inherit;font-weight:500;cursor:pointer;
  transition:background .15s ease-out,border-color .15s ease-out,color .15s ease-out;white-space:nowrap}
.btn:hover{background:var(--bg-inset);border-color:#a3acb6;text-decoration:none}
.btn:active{background:#e3e6ea}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn-danger{color:var(--danger);background:var(--bg)}
.btn-danger:hover{background:var(--danger);border-color:var(--danger);color:#fff}
.btn-danger-solid{background:var(--danger);border-color:var(--danger);color:#fff}
.btn-danger-solid:hover{background:var(--danger-hover);border-color:var(--danger-hover)}
.btn-sm{height:26px;padding:0 10px;font-size:13px}
.btn-link{border-color:transparent;background:transparent;color:var(--accent);padding:0 6px}
.btn-link:hover{background:var(--accent-soft);border-color:transparent}
.btn[disabled],.btn[aria-disabled="true"]{opacity:.55;cursor:not-allowed;pointer-events:none}
.btn-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
form{margin:0}
.field{display:flex;flex-direction:column;gap:4px;margin-bottom:16px}
.field:last-child{margin-bottom:0}
.field label,.field .lbl{font-weight:600}
.field .help{color:var(--fg-muted);font-size:13px;max-width:62ch}
.field .help.warn{color:var(--attn)}
input[type=text],input[type=password],input[type=number],input[type=date],select,textarea{
  font:inherit;height:var(--control);padding:0 10px;border:1px solid var(--border-strong);border-radius:var(--radius);
  background:var(--bg);color:var(--fg);width:100%;max-width:420px;transition:border-color .15s ease-out,box-shadow .15s ease-out}
textarea{height:auto;min-height:72px;padding:8px 10px;resize:vertical}
input:hover,select:hover,textarea:hover{border-color:#a3acb6}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
input[readonly]{background:var(--bg-subtle);color:var(--fg-muted)}
input.short{max-width:120px}
input.mid{max-width:220px}
.mono-input{font-family:var(--mono)}
.inline-fields{display:flex;gap:12px;flex-wrap:wrap}
.inline-fields .field{flex:1 1 180px;margin-bottom:0}
.choice{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:8px;cursor:pointer;transition:border-color .15s ease-out,background .15s ease-out}
.choice:hover{border-color:var(--border-strong);background:var(--bg-subtle)}
.choice input{margin-top:3px;flex-shrink:0;accent-color:var(--accent)}
.field label.choice,.choice{font-weight:400}
.choice b{display:block;font-weight:600}
.choice span{color:var(--fg-muted);font-size:13px}
.checkline{display:flex;gap:10px;align-items:flex-start}
.checkline input{margin-top:3px;accent-color:var(--accent)}
.checkline span{color:var(--fg-muted);font-size:13px;display:block}
.form-foot{display:flex;gap:8px;align-items:center;margin-top:16px}
.settings{display:flex;flex-direction:column;gap:20px}
.setting{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);gap:12px 40px;padding:20px 0;border-top:1px solid var(--border)}
.setting:first-child{border-top:0;padding-top:0}
.setting h2.st{font-size:14px;margin-bottom:4px}
.setting .about{color:var(--fg-muted);font-size:13px;max-width:44ch}

/* flashes and zones */
.flash{display:flex;gap:10px;align-items:flex-start;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-subtle);margin-bottom:20px}
.flash .ico{flex-shrink:0;margin-top:2px}
.flash.ok{border-color:var(--ok-border);background:var(--ok-soft)}
.flash.attn{border-color:var(--attn-border);background:var(--attn-soft)}
.flash.bad{border-color:var(--danger-border);background:var(--danger-soft)}
.flash.info{border-color:var(--accent-border);background:var(--accent-soft)}
.danger-zone{border:1px solid var(--danger-border);border-radius:var(--radius);overflow:hidden}
.danger-zone .box-head{background:var(--danger-soft);border-color:var(--danger-border)}
.danger-zone .box-head h2{color:var(--danger)}
.zone-row{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;padding:16px}
.zone-row + .zone-row{border-top:1px solid var(--danger-border)}
.zone-row p{max-width:62ch}
.zone-row .btn{flex-shrink:0}
.attn-box{border-color:var(--attn-border)}
.attn-box .box-head{background:var(--attn-soft);border-color:var(--attn-border)}
.attn-box .box-head h2{color:var(--attn)}
.icon{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex-shrink:0}
.icon.bad{color:var(--danger)} .icon.attn{color:var(--attn)} .icon.ok{color:var(--ok)} .icon.info{color:var(--accent)}

/* bare pages */
.bare-wrap{min-height:100vh;display:grid;place-items:center;background:var(--bg-subtle);padding:24px}
.card{width:100%;max-width:380px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:28px;
  box-shadow:0 1px 2px rgba(27,31,36,.06),0 8px 24px rgba(27,31,36,.06)}
.card h1{font-size:20px;margin-bottom:6px}
.card .lede{color:var(--fg-muted);margin-bottom:20px}
.card input{max-width:none}
.card .btn{width:100%;margin-top:4px}
.card .foot{margin-top:16px;font-size:13px;color:var(--fg-muted)}


@media (max-width:900px){
  .shell{grid-template-columns:minmax(0,1fr)}
  .nav{border-right:0;border-bottom:1px solid var(--border);padding:8px 12px;overflow-x:auto}
  .nav ul{flex-direction:row;gap:4px}
  .nav a{white-space:nowrap;padding:6px 10px}
  .nav a[aria-current="page"]{box-shadow:inset 0 -2px 0 var(--accent);background:transparent}
  .nav .sep{display:none}
  .nav .n{display:none}
  main{padding:20px 16px 120px}
  .page-head{flex-direction:column;gap:12px}
  .setting{grid-template-columns:1fr;gap:8px}
}
@media (max-width:600px){
  .session span{display:none}
  td,th{padding:8px 12px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

MAILDIVVY = """
/* Maildivvy: what the design never had, in the design's tokens */
/* the icon sprite: its symbols are drawn by <use>, the sprite itself takes no room */
.sprite{position:absolute;width:0;height:0;overflow:hidden}
/* a setting row's button sits close under its field: the design wrote this inline */
.setting .form-foot{margin-top:8px}
/* a choice among names is no wider than a name: the design wrote this inline too */
select.mid{max-width:260px}
/* what follows a row of fields sits a field's distance below it: the design wrote this inline */
.inline-fields + *{margin-top:16px}
/* the header's health badge when the machine fails, or nothing is known: the one solid
   badge, and the one red outside the fence, since every page must shout it */
.badge.bad.solid{color:var(--bg);background:var(--danger);border-color:var(--danger);font-weight:600}
/* a checkbox line inside a field reads like the design's own: only its <b> is bold */
.field label.checkline{font-weight:400}
/* two boxes in one form stand apart as in a stack: the design wrote this inline */
form.narrow > .box + .box{margin-top:20px}
/* the sign-in card has no host line under its heading, so the form keeps that room */
.card > h1 + *{margin-top:14px}
/* Health's check tables: one badge column, the same width in every subsystem's box */
.checks td.state{width:120px}
/* in one column the sidebar's row is as tall as its links, not stretched to the viewport */
@media (max-width:900px){.shell{grid-template-rows:auto 1fr}}
"""

STYLESHEET = DESIGN + MAILDIVVY
