import{t}from'./i18n.mjs';

const key='sharefolder-theme';
export function theme(){try{return localStorage.getItem(key)==='dark'?'dark':'light';}catch{return'light';}}
export function setupTheme(){document.documentElement.dataset.theme=theme();}
export function themeControl(){
 const control=document.createElement('button');
 control.type='button';control.className='theme-toggle';
 const icon=document.createElement('span');icon.className='theme-icon';icon.setAttribute('aria-hidden','true');
 const label=document.createElement('span');label.className='theme-label';
 control.append(icon,label);
 function update(){const dark=theme()==='dark';const action=t(dark?'Tema terang':'Tema gelap');icon.textContent=dark?'☀':'☾';label.textContent=action;control.setAttribute('aria-label',action);control.setAttribute('aria-pressed',String(dark));control.title=action;document.documentElement.dataset.theme=dark?'dark':'light';}
 control.addEventListener('click',()=>{try{localStorage.setItem(key,theme()==='dark'?'light':'dark');}catch{}update();});
 update();return control;
}
