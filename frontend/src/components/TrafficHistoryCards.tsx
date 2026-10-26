import { useTranslation } from 'react-i18next';
import { useState, useRef } from 'react';
import type { Dayjs } from 'dayjs';
import { Button, Alert, Space } from 'antd';
import { HistoryOutlined } from '@ant-design/icons';
import DateTimePicker from './form/DateTimePicker';
import './TrafficHistoryCards.css';

export interface ProNetTrafficDetail {
 inboundName?: string; originGuid: string; inboundTag: string; email: string; rateParts: number;
 rawUp: number; rawDown: number; billedUp: number; billedDown: number;
}
export default function TrafficHistoryCards({rows, history = false}: {rows: ProNetTrafficDetail[]; history?: boolean}) {
 const {i18n} = useTranslation(); const fa = i18n.language.startsWith('fa');
 const bytes = (n:number) => `${(n / 1073741824).toLocaleString(fa?'fa-IR':'en-US',{maximumFractionDigits:3})} GB`;
 const [open,setOpen]=useState(false),[loading,setLoading]=useState(false),[error,setError]=useState(false);
 const [filtered,setFiltered]=useState<ProNetTrafficDetail[]|null>(null);
 const [from,setFrom]=useState<Dayjs|null>(null),[until,setUntil]=useState<Dayjs|null>(null);
 const [selectedRange,setSelectedRange]=useState<[number,number]|null>(null);
 const [historyStart,setHistoryStart]=useState(0);
 const request=useRef(0);
 const date=(ms:number)=>new Intl.DateTimeFormat(fa?'fa-IR-u-ca-persian':'en-US-u-ca-persian').format(ms);
 const invalid=!from || !until || until.startOf('day').isBefore(from.startOf('day')) || until.startOf('day').diff(from.startOf('day'),'day')>365;
 const allTime=()=>{++request.current;setLoading(false);setFiltered(null);setSelectedRange(null);setFrom(null);setUntil(null);setError(false);setHistoryStart(0);};
 const load=async()=>{
  if(invalid || !from || !until)return;
  const id=++request.current;setLoading(true);setError(false);
  try{
   const url=new URL(window.location.href);url.searchParams.set('format','info');
   url.searchParams.set('trafficFrom',String(from.startOf('day').valueOf()));
   url.searchParams.set('trafficUntil',String(until.add(1,'day').startOf('day').valueOf()));
   const res=await fetch(url,{cache:'no-store'});if(!res.ok)throw new Error();
   const data=await res.json();
   if(id===request.current){setFiltered(data.detailedTraffic||[]);setHistoryStart(data.trafficHistoryStart||0);setSelectedRange([from.valueOf(),until.valueOf()]);}
  }catch{if(id===request.current)setError(true);}
  finally{if(id===request.current)setLoading(false);}
 };
 if(!rows.length && !history)return null;
 const shown=(filtered??rows).filter(r=>r.billedUp+r.billedDown>=10*1024*1024);
 return <section className="traffic-cards" aria-label={fa?'جزئیات مصرف':'Traffic breakdown'}>
  <h3>{fa?'جزئیات مصرف ثبت‌شده':'Recorded traffic breakdown'}</h3>
  <p style={{opacity:.65,fontSize:12}}>{fa?'مصرف واقعی و کسرشده به تفکیک ضریب؛ ریست ترافیک سابقه را از نو آغاز می‌کند و تمدید آن را پاک نمی‌کند.':'Raw and billed usage by coefficient. A traffic reset starts a new report; renewal preserves usage.'}</p>
  {history && <Space orientation="vertical" style={{width:'100%',marginBottom:16}}>
   <Button icon={<HistoryOutlined/>} onClick={()=>setOpen(!open)}>{fa?'بازه مصرف: ':'Usage range: '}{selectedRange?selectedRange.map(date).join(' – '):(fa?'کل':'All time')}</Button>
   {open && <div className="traffic-range-fields">
    <label><span>{fa?'شروع بازه':'Start date'}</span><DateTimePicker calendar="jalalian" showTime={false} value={from} onChange={setFrom} disabled={loading} placeholder={fa?'انتخاب تاریخ شروع':'Select start date'}/></label>
    <label><span>{fa?'پایان بازه':'End date'}</span><DateTimePicker calendar="jalalian" showTime={false} value={until} onChange={setUntil} disabled={loading} placeholder={fa?'انتخاب تاریخ پایان':'Select end date'}/></label>
    <div className="traffic-range-actions"><Button type="primary" loading={loading} disabled={invalid} onClick={load}>{fa?'نمایش مصرف':'Show usage'}</Button><Button onClick={allTime}>{fa?'کل مصرف':'All time'}</Button></div>
   </div>}
   <small style={{opacity:.65}}>{fa?'دقت زمانی مطابق همگام‌سازی نود است. حداکثر بازه: ۳۶۶ روز.':'Timing follows node synchronization. Maximum range: 366 days.'}{historyStart>0&&` ${date(historyStart)}`}</small>
   {error&&<Alert type="error" title={fa?'دریافت مصرف این بازه ممکن نشد.':'Could not load usage for this range.'}/>}
  </Space>}
  {shown.length===0&&<p>{fa?'مصرف ثبت‌شده‌ای در این بازه نیست.':'No recorded usage in this range.'}</p>}
  <div aria-busy={loading} className="traffic-cards-grid">{shown.map(r=><article key={`${r.originGuid}:${r.inboundTag}:${r.email}:${r.rateParts}`}>
   <strong dir="auto">{r.inboundName||(fa?'اینباند حذف‌شده':'Deleted inbound')}</strong><div dir="auto" style={{opacity:.65,fontSize:12}}>{r.email}</div>
   <dl><dt>{fa?'مصرف واقعی':'Actual usage'}</dt><dd dir="ltr">{bytes(r.rawUp+r.rawDown)}</dd><dt>{fa?'ضریب مصرف':'Coefficient'}</dt><dd dir="ltr">× {r.rateParts/1000000}</dd><dt>{fa?'کسرشده از اشتراک':'Charged to quota'}</dt><dd dir="ltr" style={{fontWeight:700}}>{bytes(r.billedUp+r.billedDown)}</dd></dl>
  </article>)}</div>
 </section>;
}
