import { useState } from 'react'
import { activateModel, shadowModel, getWorkbench, workbenchRequest } from '../api/client'
import { usePoll } from '../lib/usePoll'
import { fmtNum } from '../lib/format'

export function TrainingWorkbench({onSelectRun}: {onSelectRun: (id:string) => void}) {
  const state = usePoll(getWorkbench, 3000)
  const [task, setTask] = useState('attack')
  const [selected, setSelected] = useState<string[]>([])
  const [name, setName] = useState('Network behavior candidate')
  const [epochs, setEpochs] = useState(30)
  const [width, setWidth] = useState(128)
  const [falseCost, setFalseCost] = useState(2)
  const [missedCost, setMissedCost] = useState(2)
  const [label, setLabel] = useState('normal')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const data = state.data
  const corpora = data?.corpora.filter(c => c.task === task) ?? []
  const labels = (task === 'attack' ? data?.attack_classes : data?.application_classes)?.classes ?? []
  async function perform(action: () => Promise<unknown>, success: string) {
    setBusy(true); setMessage('')
    try { await action(); setMessage(success) } catch(e) { setMessage(String(e)) } finally { setBusy(false) }
  }
  return <section className="workbench viz-panel">
    <div className="panel-heading"><div><div className="eyebrow">NEURAL NETWORK WORKBENCH</div><h2>From labeled traffic to a candidate.</h2></div><span className={`tr-pill ${data?.worker_online ? 'tr-running' : 'tr-stale'}`}>{data?.worker_online ? 'Training worker online' : 'Training worker offline'}</span></div>
    <p className="viz-caption">Two independent networks: threat behavior and application type. Training uses 160 timing, packet, protocol and recent-host inputs. Your current classifier keeps running while a candidate trains.</p>
    {state.error && <p role="alert" className="err">{state.error}</p>}
    <div className="wb-steps"><b>01 · Choose trusted labels</b><span>→</span><b>02 · Train & evaluate</b><span>→</span><b>03 · Activate explicitly</b></div>
    <div className="wb-grid">
      <div><h3>1. Select training data</h3><label>Classification task<select value={task} onChange={e => {setTask(e.target.value);setSelected([]);setLabel(e.target.value === 'attack' ? 'normal' : 'unknown')}}><option value="attack">Attack / threat behavior</option><option value="application">Application / traffic type</option></select></label>
        <div className="wb-corpora">{corpora.map(c => <label key={c.id} className="wb-corpus"><input type="checkbox" checked={selected.includes(c.id)} onChange={e => setSelected(e.target.checked ? [...selected,c.id] : selected.filter(id => id !== c.id))}/><span><b>{c.name}</b><small>{fmtNum(c.rows)} labeled flows · {Object.entries(c.classes).map(([k,v]) => `${k}: ${fmtNum(v)}`).join(' · ')}</small><small>{c.source}</small><small className="dim">{c.limitations}</small></span></label>)}</div>
        {!corpora.length && <p className="viz-caption">No prepared data for this task yet. Import a verified capture below, or prepare a licensed dataset with the offline extractor.</p>}
        {task === 'attack' && <div><p className="viz-caption">Correct or confirm detections in Review, then turn those decisions into a new corpus. This includes retained temporal vectors and excludes unsure or ignored traffic.</p><button disabled={busy} onClick={() => perform(() => workbenchRequest('reviews',{}),'Reviewed flows exported as a new corpus. Select it above when it appears.')}>Use reviewed flows</button></div>}
        <details><summary>Import a labeled PCAP / PCAPNG</summary><p className="viz-caption">This labels every flow in the file with your selection. Use a capture you have verified, with a known application or attack. Mixed captures need per-flow labels prepared offline. Maximum 128 MiB.</p><label>Capture<input type="file" accept=".pcap,.pcapng,.cap" onChange={e => setFile(e.target.files?.[0] ?? null)} /></label><label>Verified label<select value={label} onChange={e => setLabel(e.target.value)}>{labels.map(c => <option key={c.name}>{c.name}</option>)}</select></label><button disabled={busy || !file || !data?.worker_online} onClick={() => perform(async () => {const upload = await workbenchRequest<{capture_id:string}>('upload',file!);await workbenchRequest('',{kind:'prepare',name:file!.name.replace(/\.[^.]+$/,''),task,label,capture_id:upload.capture_id,corpora:[]})},'Capture queued for offline preparation.')}>Prepare labeled capture</button></details>
      </div>
      <div><h3>2. Set training priorities</h3><label>Candidate name<input value={name} maxLength={100} onChange={e => setName(e.target.value)}/></label><div className="wb-grid"><label>Training epochs<input type="number" min={1} max={100} value={epochs} onChange={e => setEpochs(Number(e.target.value))}/></label><label>Network size<select value={width} onChange={e => setWidth(Number(e.target.value))}><option value={64}>Compact · 160 → 64 → 32</option><option value={128}>Balanced · 160 → 128 → 64</option><option value={256}>Larger · 160 → 256 → 128</option></select></label></div>
        {task === 'attack' && <><label>False-positive cost <b>{falseCost}×</b><input type="range" min={.25} max={10} step={.25} value={falseCost} onChange={e => setFalseCost(Number(e.target.value))}/><small>Increase the penalty for misclassifying normal training traffic.</small></label><label>Missed-attack cost <b>{missedCost}×</b><input type="range" min={.25} max={10} step={.25} value={missedCost} onChange={e => setMissedCost(Number(e.target.value))}/><small>Increase the penalty for mistakes on labeled attack traffic.</small></label></>}
        <p className="viz-caption">Training and evaluation keep each conversation together, use chronological partitions and remove traffic near time boundaries. Small captures have weaker evaluation; the report states this. Normalization is fitted only on the training partition.</p>
        <button className="primary" disabled={busy || !selected.length || !data?.worker_online} onClick={() => perform(() => workbenchRequest('',{kind:'train',task,name,corpora:selected,epochs,width,max_rows:50000,false_positive_cost:falseCost,missed_attack_cost:missedCost}),'Training queued. Follow progress in the run list below.')}>Train candidate →</button>
      </div>
    </div>
    {message && <p className="viz-notice" role="status">{message}</p>}
    <h3>3. Review candidates and jobs</h3>
    <div className="src-scroll"><table className="mini"><thead><tr><th>Job</th><th>Task</th><th>Status</th><th>Next step</th></tr></thead><tbody>{data?.jobs.slice(0,12).map(j => <tr key={j.id}><td><b>{j.request.name || j.request.kind}</b><small className="wb-message">{j.message}</small></td><td>{j.request.task}</td><td>{j.status}</td><td>{j.run_id && <button onClick={() => onSelectRun(j.run_id!)}>Evaluate run ↗</button>}{['queued','running'].includes(j.status) && <button disabled={busy} onClick={() => perform(() => workbenchRequest(`${j.id}/cancel`,{}),'Cancellation requested.')}>Cancel</button>}{j.status === 'completed' && j.model_id && j.request.task === 'attack' && <button disabled={busy} onClick={() => perform(() => shadowModel(j.model_id!),'Shadow network running. Open Live inference and select the experimental model.')}>Run in shadow</button>}{j.status === 'completed' && j.model_id && <button disabled={busy} onClick={() => perform(() => activateModel(j.model_id!),`Candidate activated for ${j.request.task} classification.`)}>Activate candidate</button>}</td></tr>)}</tbody></table></div>
    <p className="viz-caption">Classes without training examples are masked from the network output. A candidate’s accuracy describes its held-out captures, not guaranteed detection on your network. Review its coverage and confusion matrix before activation.</p>
  </section>
}
