import { useTranslation } from 'react-i18next';
import { useState, useRef } from 'react';
import { Button, DatePicker, Alert, Space } from 'antd';
import { HistoryOutlined } from '@ant-design/icons';
export interface ProNetTrafficDetail {
 inboundName?: string; originGuid: string; inboundTag: string; email: string; rateParts: number;
 rawUp: number; rawDown: number; billedUp: number; billedDown: number;
}
export default function ProNetTrafficCards({rows, history = false}: {rows: ProNetTrafficDetail[]; history?: boolean}) {
 const {i18n} = useTranslation(); const fa = i18n.language.startsWith('fa');
 const bytes = (n:number) => `${(n / 1073741824).toLocaleString(fa?'fa-IR':'en-US',{maximumFractionDigits:3})} GB`;
 const [open, setOpen] = useState(false);
 const [filtered, setFiltered] = useState<ProNetTrafficDetail[] | null>(null);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(false);
 const [start, setStart] = useState(0);
 const [selectedRange, setSelectedRange] = useState<[string, string] | null>(null);
 const request = useRef(0);
 if(!rows.length && !history) return null;
 const shown = filtered ?? rows;
 return <section style={{marginBlock:20}} aria-label={fa?'جزئیات مصرف':'Traffic breakdown'}>
 <h3>{fa?'جزئیات مصرف ثبت‌شده':'Recorded traffic breakdown'}</h3>
 <p style={{opacity:0.65,fontSize:12}}>{fa?'مصرف خام و کسرشده به تفکیک ضریب؛ سابقه با تمدید یا تغییر ضریب پاک نمی‌شود.':'Raw and billed lifetime usage by coefficient; quota resets do not erase this history.'}</p>
 {history && <Space orientation="vertical" style={{width:'100%',marginBottom:16}}>
 <Button icon={<HistoryOutlined />} onClick={()=>setOpen(!open)}>{fa?'بازه مصرف: ':'Usage range: '}{filtered === null ? (fa?'کل':'All time') : selectedRange?.join(' – ')}</Button>
 {open && <DatePicker.RangePicker disabled={loading} onChange={async range=>{
  const id = ++request.current;
  if(!range?.[0] || !range[1]) { setFiltered(null); setError(false); setStart(0); setSelectedRange(null); return; }
  setLoading(true); setError(false);
  try {
   const url = new URL(window.location.href); url.searchParams.set('format','info');
   url.searchParams.set('trafficFrom',String(range[0].startOf('day').valueOf()));
   url.searchParams.set('trafficUntil',String(range[1].add(1,'day').startOf('day').valueOf()));
   const res=await fetch(url,{cache:'no-store'}); if(!res.ok) throw new Error();
   const data=await res.json(); if(id===request.current){setFiltered(data.detailedTraffic || []);setStart(data.trafficHistoryStart || 0);setSelectedRange([range[0].format('YYYY-MM-DD'),range[1].format('YYYY-MM-DD')]);}
  } catch { if(id===request.current) setError(true); }
  finally { if(id===request.current) setLoading(false); }
 }} />}
 <small style={{opacity:.65}}>{fa?'بازه‌ها از زمان ارتقا ثبت می‌شوند؛ دقت زمانی مطابق همگام‌سازی نود است. حداکثر بازه: ۳۶۶ روز.':'History starts after upgrading; timing follows node synchronization. Maximum range: 366 days.'}{start > 0 && ` ${new Date(start).toLocaleString(fa?'fa-IR':'en-US')}`}</small>
 {error && <Alert type="error" title={fa?'دریافت بازه ممکن نشد؛ بازه را حداکثر ۳۶۶ روز انتخاب کنید.':'Could not load history. Select at most 366 days.'} />}
 </Space>}
 {shown.length === 0 && <p>{fa?'مصرف ثبت‌شده‌ای در این بازه نیست.':'No recorded usage in this range.'}</p>}
 <div aria-busy={loading} style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(240px,1fr))',gap:12}}>
 {shown.map(r=><article key={`${r.originGuid}:${r.inboundTag}:${r.email}:${r.rateParts}`} style={{padding:16,border:'1px solid var(--ant-color-border, #49515d)',borderRadius:14,background:'var(--ant-color-fill-quaternary, transparent)'}}>
 <strong dir="auto">{r.inboundName || r.inboundTag}</strong><div dir="auto" style={{opacity:0.65,fontSize:12}}>{r.email}</div>
 <dl style={{display:'grid',gridTemplateColumns:'1fr auto',gap:8}}>
 <dt>{fa?'مصرف واقعی':'Actual usage'}</dt><dd style={{margin:0}} dir="ltr">{bytes(r.rawUp+r.rawDown)}</dd>
 <dt>{fa?'ضریب مصرف':'Coefficient'}</dt><dd style={{margin:0}} dir="ltr">× {r.rateParts/1000000}</dd>
 <dt>{fa?'کسرشده از اشتراک':'Charged to quota'}</dt><dd style={{margin:0,fontWeight:700}} dir="ltr">{bytes(r.billedUp+r.billedDown)}</dd>
 </dl></article>)}
 </div></section>;
}
