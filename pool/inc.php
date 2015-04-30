<?php
#
function GBaseJS()
{
 $g = "function hasCan(){var c0=document.getElementById('can0');c=document.getElementById('can');return !!(c0&&c&&c.getContext&&c.getContext('2d'));}
function sep(d){ans={};var ar=d.split('\\t');var l=ar.length;for(var i=0;i<l;i++){var e=ar[i].indexOf('=');ans[ar[i].substr(0,e)]=ar[i].substr(e+1)};return ans}
function dfmt(c,e){var d=new Date(e*1000);var DD,HH,MM;if(c['utc']){DD=d.getUTCDate();HH=d.getUTCHours();MM=d.getUTCMinutes()}else{DD=d.getDate();HH=d.getHours();MM=d.getMinutes()}var ans=''+DD+'/';if(HH<10){ans+='0'}ans+=''+HH+':';if(MM<10){ans+='0'}ans+=''+MM;return ans}
function ccb(c,n){var e=document.getElementById(n);c[n]=(e&&e.checked)}
function gch(z,zm){if(z<0.5){return 0.5}if(z>(zm-0.5)){return(zm-0.5)}return z}
function gchx(c,x){return gch(x*c['xm']+c['xo'],c['ctx'].canvas.width)}
function gchy(c,y){return gch((1-y)*c['ym']+c['yo'],c['ctx'].canvas.height)}
function gx0(c){return -c['xo']/c['xm']};
function gy0(c){return -c['yo']/c['ym']};
function gto(c,xo,yo){c['xo']+=xo;c['yo']+=yo}
function gts(c,xs,ys){c['xm']*=xs;c['ym']*=ys}
function gtso(c,xs,ys){gto(c,c['xm']*(1.0-xs)/2.0,c['ym']*(1.0-ys)/2.0);gts(c,xs,ys)}
function gfs(c,bg){c['ctx'].fillStyle=bg}
function gss(c,fg){c['ctx'].strokeStyle=fg}
function glw(c,w){c['ctx'].lineWidth=w}
function gfz(c,x,y,ox,oy,t,co,a){gfs(c,co);c['ctx'].textAlign=a;c['ctx'].fillText(t,gchx(c,x)+ox,gchy(c,y)-oy)}
function gbe(c,x,y){c['ctx'].beginPath();c['ctx'].moveTo(gchx(c,x),gchy(c,y))}
function gln(c,x,y){c['ctx'].lineTo(gchx(c,x),gchy(c,y))}
function gct(c,x1,y1,x2,y2,x3,y3){c['ctx'].bezierCurveTo(gchx(c,x1),gchy(c,y1),gchx(c,x2),gchy(c,y2),gchx(c,x3),gchy(c,y3))}
function glm(c,x,y){c['ctx'].moveTo(gchx(c,x),gchy(c,y))}
function gle(c){c['ctx'].closePath()}
function gfl(c){c['ctx'].fill()}
function gst(c){c['ctx'].stroke()}
function gfi(c){gle(c);gst(c)}
function gbd(c){gbe(c,0,0);gln(c,1,0);gln(c,1,1);gln(c,0,1);gle(c);gfl(c);gst(c)}
function ggr(c,xs,ys,yt,xn,x0,x1,y0,y1,ar,nx,vx,vy,av,w,cols){
gtso(c,xs,ys);
gss(c,'black');glw(c,1.5);
gbe(c,0,1);gln(c,0,0);gln(c,1,0);gst(c);
glw(c,0.2);
var hi=c['ctx'].measureText('M').width, wi=c['ctx'].measureText('1').width;
for(var i=0;i<11;i++){var y=i/10.0;gbe(c,-0.01,y);gln(c,1,y);gst(c);var t=''+(((y1-y0)*i/10+y0).toFixed(2));gfz(c,0,y,-wi,0,t,'black','end')}
gfz(c,gx0(c),0.55,wi,0,yt,'#0080ff','left');
var m=Math.round(0.5+xn/20.0);
for(var i=0;i<xn;i++){var n=ar[nx+i];var x=ar[vx+i];var xo=(x-x0)/(x1-x0);if(c['skey']&&(i<(xn-1))&&(i%m)==0){gbe(c,xo,0);gln(c,xo,-0.01);gst(c);gfz(c,xo,0,0,-hi*1.5,n,'#00a050','center')}if(c['slines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}}
var xhr=3600+x1-(x1%3600);
gss(c,'brown');
if(c['tkey']||c['tlines']){var hlv=c['hln'][c['hl']];hrs=c['hrs'][c['hr']]*3600/hlv;
var l=0;tpos=2.7;if(c['over']){tpos=1.5}
for(var i=xhr;i>=x0;i-=hrs){var n=dfmt(c,i);var xo=(i-x0)/(x1-x0);if(xo<=1&&c['tkey']&&((l%hlv)==0)){gbe(c,xo,0);gln(c,xo,-0.02);gst(c);gfz(c,xo,0,0,-hi*tpos,n,'brown','center')}if(xo<=1&&c['tlines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}l++}}
glw(c,1);
if(c['smooth']){for(var j=1;j<w.length;j++){var f=1;gss(c,cols[j-1]);
var xa=0,ya=0,xb=0,yb=0;
for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[w[j]+vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0;xb=xo;yb=yo}else{gct(c,(xa+xb)/2,(ya+yb)/2,xb,yb,(xb+xo)/2,(yb+yo)/2)}xa=xb;ya=yb;xb=xo;yb=yo}gct(c,(xa+xb)/2,(ya+yb)/2,xo,yo,xo,yo);gst(c);}}
else{for(var j=1;j<w.length;j++){var f=1;gss(c,cols[j-1]);
for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[w[j]+vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0}else{gln(c,xo,yo)}}gst(c);}}
glw(c,1);
for(var j=1;j<w.length;j++){if(av[j-1]>0){gss(c,'red');var y=(av[j-1]-y0)/(y1-y0);gbe(c,0,y);gln(c,1,y);gst(c);
var t=''+av[j-1].toFixed(2)+'av';gfz(c,1,y,1,0,t,cols[j-1],'left')}}
if(c['tkey']){var col,hrl=c['hrs'].length;for(var i=0;i<hrl;i++){if(c['hr']==i){col='red'}else{col='black'}gfz(c,1,0,c['xo']-c['pxe'],hi*(i+1)*2,''+c['hrs'][i],col,'end')}for(var i=0;i<c['hln'].length;i++){if(c['hl']==i){col='red'}else{col='black'}gfz(c,1,0,c['xo']-c['pxe'],hi*(i+2+hrl)*2,''+c['hrs'][i],col,'end')}}
}
function sn(i,shi){if(shi.indexOf(' Shift ')<0){return ''+(i%10)}else{return shi.replace(/.* ([a-z])[a-z]*$/,'$1')}}
function gc(c){var div=document.getElementById('can0');while(div.firstChild){div.removeChild(div.firstChild)}c['can']=document.createElement('canvas');c['can'].id='can';c['wx']=window.innerWidth;c['wy']=window.innerHeight;c['xm']=Math.max(Math.round(c['wx']*0.9+0.5),400);c['ym']=Math.max(Math.round(c['wy']*0.8+0.5),400);if(c['ym']>c['xm']){c['ym']=c['xm']}c['xo']=0.0;c['yo']=0.0;c['ctx']=c['can'].getContext('2d');c['ctx'].canvas.width=c['xm']+1;c['ctx'].canvas.height=c['ym']+1;div.appendChild(c['can']);c['pxe']=Math.max(Math.round(c['xm']/250),1)}
function opts(t,i){var e=document.getElementById(i);if(t.checked){e.style.visibility='visible'}else{e.style.visibility='hidden'}}
function ghrs(c){c['hrs']=[1,2,3,4,6,8,12,24,48];c['hln']=[1,2,3,4,6]}
function ghg(c,dx){var tl=dx/(gchx(c,1)/50)/3600;for(var j=c['hrs'].length-1;j>=0;j--){if(tl<c['hrs'][j]){c['hr']=j}else{break}}if(tl<0.5){var tb=1/tl;for(var k=0;k<c['hln'].length;k++){if(c['hln'][k]<tb){c['hl']=k}else{break}}}else{c['hl']=1}}
function gopt(c,cbx){for(var i=0;i<cbx.length;i++){ccb(c,cbx[i])}}
function doinit(cbx,xon){for(var i=0;i<cbx.length;i++){var e=document.getElementById(cbx[i]);if(e){var n=gcn(cbx[i]);if(n==''){if(xon[cbx[i]]){e.checked=true}else{e.checked=false}}else{if(n=='1'){e.checked=true}else{e.checked=false}}}}}
";
 return $g;
}
#
function TipsJS()
{
 $t = "function untip(e){if(e){if(typeof e.tmo!='undefined'){clearTimeout(e.tmo);delete e.tmo}e.style.opacity=0;e.style.visibility='hidden'}}
function tip(i,n){var e=document.getElementById(i);if(e){if(e.style.visibility=='visible'){untip(e)}else{e.style.visibility='visible';e.style.opacity=0.95;e.tmo=setTimeout(function(){untip(e)},n)}}}
";
 return $t;
}

function TipsCSS()
{
 $c = "span.tip0 {position:absolute;z-index:42;pointer-events:none;font-size:smaller;text-align:left;}
span.notip {position:relative;color:#0077ee;background:#bbffff;border-style:solid;border-color:black;border-width:1px;left:-10px;width:200px;padding:2px;float:left;transition:visibility 0.5s,opacity 0.5s;visibility:hidden;opacity:0}
span.tip {visibility: visibile;}
span.q {position: relative; width: 16px; height: 16px; display: inline-block; background-color: #0077ee; line-height: 16px; color: White; font-size: 13px; font-weight: bold; border-radius: 8px; text-align: center; cursor: pointer;}
ul.tip {margin-top:0;margin-bottom:0;list-style:disc inside none;margin-left:0;padding-left:0.5em;display:block}
li {padding-left:0.5em;}
";
 return $c;
}
#
function HeadJS()
{
 $h = "function gcn(n){var ans='',d=document.cookie;if(d){var c0=d.indexOf(n+'='),cs=d.indexOf(' '+n+'=');if(c0==0||cs>0){if(cs>0){c0=cs+1}var c=d.substr(c0).split(';',1);var e=c[0].indexOf('=');if(e>0){ans=c[0].substr(e+1)}}}return ans}
function scnv(n,v){var d=new Date();d.setTime(d.getTime()+(864*Math.pow(10,8)));document.cookie=n+'='+v+'; expires='+d.toUTCString()+'; path=/'}
function ni(e,o){if(e){if(o==0){e.defd=e.style.display;e.style.display='none'}else{e.style.display=e.defd}}}
function domin(o){var e=document.getElementById('minicb');if(e){if(o==0){e.checked=true}else{e.checked=false}};for(var i=0;i<10;i++){e=document.getElementById('mini'+i);ni(e,o)}}
function mini(){var hm=gcn('mini');if(hm==''){domin(1)}else{domin(0)}}
function md(e){var c='';if(e.checked){c='y'}scnv('mini',c);mini()}
function tim(){var e=document.getElementById('ftr');if(e){var now=new Date(),t=document.createTextNode(now.toLocaleString());e.appendChild(t)}}
function jst(){var e=document.getElementById('jst');if(e){e.style.visibility='hidden'}}";
 return $h;
}
#
function HeadCSS($iCrap = false)
{
 $h = "input[type=checkbox] {vertical-align: -2px;}
form {display: inline-block;}
html, body {height: 100%; font-family:Arial, Verdana, sans-serif; font-size:12pt; background-color:#eeffff; text-align: center; background-repeat: no-repeat; background-position: center;}
.page {min-height: 100%; height: auto !important; height: 100%; margin: 0 auto -50px; position: relative;}
div.jst {color:red; font-weight: bold; font-size: 8; text-align: center; vertical-align: top;}
div.accwarn {color:red; font-weight: bold; font-size: 8; text-align: center; vertical-align: top;}
div.topd {background-color:#cff; border-color: #cff; border-style: solid; border-width: 9px;}
.topdes {color:blue; text-align: right;}
.topdesl {color:blue; text-align: left;}
.topwho {color:black; font-weight: bold; margin-right: 8px;}
.topdat {margin-left: 8px; margin-right: 24px; color:green; font-weight: bold;}
span.nb {white-space: pre;}
span.login {float: right; margin-left: 8px; margin-right: 24px;}
span.hil {color:blue;}
span.user {color:green;}
span.addr {color:brown;}
span.warn {color:orange; font-weight:bold;}
span.urg {color:red; font-weight:bold;}
span.err {color:red; font-weight:bold; font-size:120%;}
span.alert {color:red; font-weight:bold; font-size:250%;}
input.tiny {width: 0px; height: 0px; margin: 0px; padding: 0px; outline: none; border: 0px;}
#n42 {margin:0; position: relative; color:#ffffff; background:#0077ee;}
#n42 a {color:#fff; text-decoration:none; padding: 6px; display:block;}
#n42 td {min-width: 100px; float: left; vertical-align: top; padding: 0px 2px;}
#n42 td.navboxr {float: right;}
#n42 td.nav {position: relative;}
#n42 td.ts {border-width: 1px; border-color: #0022ee; border-style: solid none none none;}";
 if (!$iCrap)
 {
  $h .= "
#n42 div.sub {left: 0px; z-index: 42; position: absolute; visibility: hidden;}
#n42 td.nav:hover {background:#0099ee;}
#n42 td.nav:hover div.sub {background:#0077ee; visibility: visible;}";
 }
 $h .= "
h1 {margin-top: 20px; float:middle; font-size: 20px;}
.foot, .push {height: 50px;}
.title {background-color: #909090;}
.even {background-color: #cccccc;}
.odd {background-color: #a8a8a8;}
.hid {display: none;}
.dl {text-align: left; padding: 2px 8px;}
.dr {text-align: right; padding: 2px 8px;}
.dc {text-align: center; padding: 2px 8px;}
.dls {text-align: left; padding: 2px 8px; text-decoration:line-through; font-weight:lighter;}
.drs {text-align: right; padding: 2px 8px; text-decoration:line-through; font-weight:lighter;}
.dcs {text-align: center; padding: 2px 8px; text-decoration:line-through; font-weight:lighter;}
.st0 {font-weight:bold;}
.st1 {color:red; font-weight:bold;}
.st2 {color:green; font-weight:bold;}
.st3 {color:blue; font-weight:bold;}
.fthi {color:red; font-size:7px;}
.ftlo {color:green; font-size:7px;}
.ft {color:blue; font-size:7px;}
.ftl {text-align: left; color:blue; font-size:7px; display:inline-block; width:20%; white-space: nowrap;}
.ftm {text-align: middle; font-size:10pt; display:inline-block; width:60%; white-space: nowrap;}
.ftr {text-align: rigth; color:blue; font-size:7px; display:inline-block; width:20%; white-space: nowrap;}";
 return $h;
}
#
?>
