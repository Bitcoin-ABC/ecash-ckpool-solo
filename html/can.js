function hasCan(){var c0=document.getElementById('can0');c=document.getElementById('can');return !!(c0&&c&&c.getContext&&c.getContext('2d'));}
function sep(d){ans={};var ar=d.split("\t");var l=ar.length;for(var i=0;i<l;i++){var e=ar[i].indexOf('=');ans[ar[i].substr(0,e)]=ar[i].substr(e+1)};return ans}
function dfmt(e){var d=new Date(e*1000);var DD=d.getUTCDate();var HH=d.getUTCHours();var MM=d.getUTCMinutes();var ans=''+DD+'/';if(HH<10){ans+='0'}ans+=''+HH+':';if(MM<10){ans+='0'}ans+=''+MM;return ans}
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
function glw(c,pct){c['ctx'].lineWidth=pct*c['ym']/100.0}
function glwr(c,rat){c['ctx'].lineWidth*=rat}
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
function ggr(c,xs,ys,yt,xn,x0,x1,y0,y1,ar,nx,vx,vy,av){
gtso(c,xs,ys);
gss(c,'black');glw(c,0.2);
gbe(c,0,1);gln(c,0,0);gln(c,1,0);gst(c);
glw(c,0.01);
var hi=c['ctx'].measureText('M').width, wi=c['ctx'].measureText('1').width;
for(var i=0;i<11;i++){var y=i/10.0;gbe(c,-0.01,y);gln(c,1,y);gst(c);var t=''+(((y1-y0)*i/10+y0).toFixed(2));gfz(c,0,y,-wi,0,t,'black','end')}
gfz(c,gx0(c),0.55,wi,0,yt,'#0080ff','left');
var m=Math.round(0.5+xn/20.0);
var f=1;
for(var i=0;i<xn;i++){var n=ar[nx+i];var x=ar[vx+i];var xo=(x-x0)/(x1-x0);if(c['skey']&&(i<(xn-1))&&(i%m)==0){gbe(c,xo,0);gln(c,xo,-0.01);gst(c);gfz(c,xo,0,0,-hi*1.5,n,'#00a050','center')}if(c['slines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}}
var xhr=x1-(x1%3600);
gss(c,'brown');
var tpos=2.7;if(c['over']){tpos=1.5}
for(var i=xhr;i>=x0;i-=(6*3600)){var n=dfmt(i);var xo=(i-x0)/(x1-x0);if(c['tkey']){gbe(c,xo,0);gln(c,xo,-0.02);gst(c);gfz(c,xo,0,0,-hi*tpos,n,'brown','center')}if(c['tlines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}}
glw(c,0.1);
gss(c,'black');
if(c['smooth']){var xa=0,ya=0,xb=0,yb=0;
for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0;xb=xo;yb=yo}else{gct(c,(xa+xb)/2,(ya+yb)/2,xb,yb,(xb+xo)/2,(yb+yo)/2)}xa=xb;ya=yb;xb=xo;yb=yo}gct(c,(xa+xb)/2,(ya+yb)/2,xo,yo,xo,yo);gst(c);}
else{for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0}else{gln(c,xo,yo)}}gst(c);}
glw(c,0.2);
gss(c,'red');
var y=(av-y0)/(y1-y0);
gbe(c,0,y);gln(c,1,y);gst(c);
var t=''+av.toFixed(2);gfz(c,1,y,1,0,t,'red','left')
}
function sn(i,shi){if(shi.indexOf(' Shift ')<0){return ''+(i%10)}else{return shi.replace(/.* ([a-z])[a-z]*$/,'$1')}}
function gc(c){var div=document.getElementById('can0');while(div.firstChild){div.removeChild(div.firstChild)}c['can']=document.createElement('canvas');c['can'].id='can';c['wx']=window.innerWidth;c['wy']=window.innerHeight;c['xm']=Math.round(c['wx']*0.9+0.5);c['ym']=Math.round(c['wy']*0.8+0.5);if(c['ym']>c['xm']){c['ym']=c['xm']}c['xo']=0.0;c['yo']=0.0;c['ctx']=c['can'].getContext('2d');c['ctx'].canvas.width=c['xm']+1;c['ctx'].canvas.height=c['ym']+1;div.appendChild(c['can']);div=document.getElementById('smooth');c['smooth']=(div&&div.checked);div=document.getElementById('over');c['over']=(div&&div.checked);div=document.getElementById('skey');c['skey']=(div&&div.checked);div=document.getElementById('slines');c['slines']=(div&&div.checked);div=document.getElementById('tkey');c['tkey']=(div&&div.checked);div=document.getElementById('tlines');c['tlines']=(div&&div.checked);div=document.getElementById('zerob');c['zerob']=(div&&div.checked)}
function gdrw(d){var c={};gc(c);
gfs(c,'white');gss(c,'#0000c0');glw(c,0.5);gbd(c);
var rows=d['rows'],ymin=-1,ymax=0,xmin=-1,xmax=0;
var tda=0;
for(var i=0;i<rows;i++){var s=parseFloat(d['start:'+i]);var e=parseFloat(d['end:'+i]);var da=parseFloat(d['diffacc:'+i]);tda+=da;var ths=(da/(e-s))*Math.pow(2,32)/Math.pow(10,12);d['ths:'+i]=ths;if(ymin==-1||ymin>ths){ymin=ths}if(ths>ymax)ymax=ths;d['nx:'+i]=sn(i,d['shift:'+i]);if(xmin==-1||xmin>s){xmin=s}if(xmax<e){xmax=e}d['vx:'+i]=(s+e)/2.0};
var tav=(tda/(xmax-xmin))*Math.pow(2,32)/Math.pow(10,12);
var p5=(ymax-ymin)*0.05;ymax+=p5;ymin-=p5;if(ymin<0){ymin=0}
if(c['zerob']){ymin=0}
ggr(c,0.9,0.9,'THs',rows,xmin,xmax,ymin,ymax,d,'nx:','vx:','ths:',tav);
}
function dodrw(data){if(hasCan()){gdrw(sep(data))}}
