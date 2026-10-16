import { useTranslation } from 'react-i18next';
export interface ProNetTrafficDetail {
 originGuid: string; inboundTag: string; email: string; rateParts: number;
 rawUp: number; rawDown: number; billedUp: number; billedDown: number;
}
export default function ProNetTrafficCards({rows}: {rows: ProNetTrafficDetail[]}) {
 const {i18n} = useTranslation(); const fa = i18n.language.startsWith('fa');
 const bytes = (n:number) => `${(n / 1073741824).toLocaleString(fa?'fa-IR':'en-US',{maximumFractionDigits:3})} GB`;
 if(!rows.length) return null;
 return <section style={{marginBlock:20}} aria-label={fa?'جزئیات مصرف':'Traffic breakdown'}>
 <h3>{fa?'جزئیات مصرف ثبت‌شده':'Recorded traffic breakdown'}</h3>
 <p style={{opacity:0.65,fontSize:12}}>{fa?'مصرف خام و کسرشده به تفکیک ضریب؛ سابقه با تمدید یا تغییر ضریب پاک نمی‌شود.':'Raw and billed lifetime usage by coefficient; quota resets do not erase this history.'}</p>
 <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(240px,1fr))',gap:12}}>
 {rows.map(r=><article key={`${r.originGuid}:${r.inboundTag}:${r.email}:${r.rateParts}`} style={{padding:16,border:'1px solid var(--ant-color-border, #49515d)',borderRadius:14,background:'var(--ant-color-fill-quaternary, transparent)'}}>
 <strong dir="auto">{r.inboundTag}</strong><div dir="auto" style={{opacity:0.65,fontSize:12}}>{r.email}</div>
 <dl style={{display:'grid',gridTemplateColumns:'1fr auto',gap:8}}>
 <dt>{fa?'مصرف واقعی':'Actual usage'}</dt><dd style={{margin:0}} dir="ltr">{bytes(r.rawUp+r.rawDown)}</dd>
 <dt>{fa?'ضریب مصرف':'Coefficient'}</dt><dd style={{margin:0}} dir="ltr">× {r.rateParts/1000000}</dd>
 <dt>{fa?'کسرشده از اشتراک':'Charged to quota'}</dt><dd style={{margin:0,fontWeight:700}} dir="ltr">{bytes(r.billedUp+r.billedDown)}</dd>
 </dl></article>)}
 </div></section>;
}
