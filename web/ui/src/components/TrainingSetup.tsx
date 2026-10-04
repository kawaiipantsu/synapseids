import { useState } from 'react'
import { datasetDownloadURL, getDatasets } from '../api/client'
import { DEFAULT_HIDDEN, normalizeHidden } from '../lib/arch'
import type { HiddenLayer } from '../lib/arch'
import { fmtInt } from '../lib/format'
import { Link } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'
import {
  buildRecipe,
  trainingCommands,
  type TrainingPreset,
} from '../lib/trainingRecipe'
import { usePoll } from '../lib/usePoll'
import { NeuralDiagram } from './NeuralDiagram'

function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob),
    anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export function TrainingSetup() {
  const { data, error } = usePoll(getDatasets, 10000)
  const [ref, setRef] = useState('')
  const [preset, setPreset] = useState<TrainingPreset>('balanced')
  const [name, setName] = useState('traffic-classifier')
  const [epochs, setEpochs] = useState(50)
  const [lr, setLR] = useState(0.001)
  const [stored] = usePersistedState<HiddenLayer[]>(
    'architecture.hidden',
    DEFAULT_HIDDEN,
  )
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const selected = data?.datasets.find((d) => `${d.id}@${d.version}` === ref)
  let recipe: ReturnType<typeof buildRecipe> | null = null,
    validation = ''
  try {
    recipe = buildRecipe({
      id: selected?.id ?? '',
      version: selected?.version ?? '',
      name,
      preset,
      epochs,
      learningRate: lr,
      hidden: normalizeHidden(Array.isArray(stored) ? stored : DEFAULT_HIDDEN),
    })
  } catch (e) {
    validation = String(e instanceof Error ? e.message : e)
  }
  const classes = Object.entries(selected?.label_counts ?? {}).filter(
    ([, n]) => n > 0,
  )
  const commands = recipe ? trainingCommands(name, window.location.origin) : ''
  const downloadDataset = async () => {
    if (!selected) return
    setBusy(true)
    setMessage('')
    try {
      const response = await fetch(
        datasetDownloadURL(selected.id, selected.version),
      )
      if (!response.ok)
        throw new Error(`Dataset download failed (${response.status})`)
      download(await response.blob(), 'dataset.csv')
      setMessage(
        'Dataset downloaded. Keep dataset.csv and training-recipe.json in the same folder.',
      )
    } catch (e) {
      setMessage(String(e instanceof Error ? e.message : e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="training-setup viz-panel">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">BUILD A BETTER CLASSIFIER</div>
          <h2>Start a training run</h2>
        </div>
        <Link to="/architecture">Architecture builder ↗</Link>
      </div>
      <div className="setup-columns">
        <div className="setup-step">
          <span className="step-number">01</span>
          <h3>Choose your evidence</h3>
          <p>
            Use reviewed, representative traffic with a pinned dataset version.
          </p>
          <label>
            Dataset version
            <select
              value={ref}
              onChange={(e) => {
                setRef(e.target.value)
                setMessage('')
              }}
            >
              <option value="">Select a dataset…</option>
              {data?.datasets.map((d) => (
                <option
                  key={`${d.id}@${d.version}`}
                  value={`${d.id}@${d.version}`}
                >
                  {d.name || d.id} · {d.version} · {fmtInt(d.flow_count)} flows
                </option>
              ))}
            </select>
          </label>
          {error && (
            <p className="err" role="alert">
              {error}
            </p>
          )}
          {data && !data.datasets.length && (
            <p>
              No datasets yet. <Link to="/datasets">Create a dataset →</Link>
            </p>
          )}
          {selected && (
            <>
              <div className="dataset-summary">
                <b>{fmtInt(selected.flow_count)}</b> labeled flows ·{' '}
                {classes.length} classes
              </div>
              <div
                className="split-bar"
                aria-label="70 percent training, 15 percent validation, 15 percent test"
              >
                <span style={{ width: '70%' }}>70% train</span>
                <span style={{ width: '15%' }}>15%</span>
                <span style={{ width: '15%' }}>15%</span>
              </div>
              <p className="foot">
                Validation 15% · held-out test 15% · fixed seed 1337
              </p>
              {selected.labeling_source !== 'human_review' && (
                <p className="warning-chip">
                  Labels include model predictions. Review errors before
                  training.
                </p>
              )}
              {classes.length < 2 && preset !== 'anomaly' && (
                <p className="warning-chip">
                  Only one class is present. Add representative attack and
                  normal examples.
                </p>
              )}
              {preset === 'anomaly' && !(selected.label_counts.normal > 0) && (
                <p className="err">
                  Anomaly training requires NORMAL examples.
                </p>
              )}
              <button disabled={busy} onClick={() => void downloadDataset()}>
                {busy ? 'Downloading…' : 'Download dataset.csv'}
              </button>
            </>
          )}
          <Link className="setup-link" to="/review">
            Review uncertain classifications →
          </Link>
        </div>
        <div className="setup-step">
          <span className="step-number">02</span>
          <h3>Choose a model</h3>
          <p>
            A practical preset gets you started. Tune it as your dataset grows.
          </p>
          <label>
            Training preset
            <select
              value={preset}
              onChange={(e) => {
                const p = e.target.value as TrainingPreset
                setPreset(p)
                setEpochs(p === 'quick' ? 20 : 50)
              }}
            >
              <option value="balanced">Balanced classifier · 64 → 32</option>
              <option value="quick">Quick experiment · 32 → 16</option>
              <option value="anomaly">Anomaly detector · 32 → 12 → 32</option>
              <option value="custom">My Architecture Builder draft</option>
            </select>
          </label>
          <label>
            Model name
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={80}
            />
          </label>
          <div className="field-pair">
            <label>
              Maximum epochs
              <input
                type="number"
                min={1}
                max={10000}
                value={Number.isNaN(epochs) ? '' : epochs}
                onChange={(e) => setEpochs(e.target.valueAsNumber)}
              />
            </label>
            <label>
              Learning rate
              <input
                type="number"
                min={0.000001}
                max={1}
                step={0.0001}
                value={Number.isNaN(lr) ? '' : lr}
                onChange={(e) => setLR(e.target.valueAsNumber)}
              />
            </label>
          </div>
          <p className="foot">
            Early stopping after 8 epochs without validation-loss improvement.{' '}
            {preset === 'anomaly'
              ? 'Reconstructs 48 inputs; trains on NORMAL examples only.'
              : '48 behavioral inputs → 7 traffic classes.'}
          </p>
        </div>
        <div className="setup-step">
          <span className="step-number">03</span>
          <h3>Train, evaluate, activate</h3>
          <p>
            Training runs on your Python worker. Its progress appears below.
          </p>
          {recipe && (
            <NeuralDiagram
              widths={[
                48,
                ...recipe.architecture.hidden.map((h) => h.width),
                recipe.architecture.output_size,
              ]}
            />
          )}
          <button
            className="primary"
            disabled={
              !recipe ||
              busy ||
              (preset === 'anomaly' && !(selected?.label_counts.normal! > 0))
            }
            onClick={() => {
              if (recipe)
                download(
                  new Blob([JSON.stringify(recipe, null, 2) + '\n'], {
                    type: 'application/json',
                  }),
                  'training-recipe.json',
                )
            }}
          >
            Download training recipe
          </button>
          {validation && <p className="foot">{validation}</p>}
          {commands && (
            <details className="training-commands" open>
              <summary>Run on the training worker</summary>
              <p className="foot">
                Install the trainer, put both downloads in one folder, then
                validate and train:
              </p>
              <pre>{commands}</pre>
              <button
                onClick={() => {
                  void navigator.clipboard?.writeText(commands).then(
                    () => setMessage('Commands copied.'),
                    () =>
                      setMessage(
                        'Clipboard unavailable; select and copy the commands above.',
                      ),
                  )
                  if (!navigator.clipboard)
                    setMessage('Select and copy the commands above.')
                }}
              >
                Copy commands
              </button>
              <p className="foot">
                Use a daemon URL reachable from the worker. For authenticated
                reporting, set SYNAPSE_API_TOKEN in the worker environment.
              </p>
            </details>
          )}
          <Link className="setup-link" to="/models">
            Evaluate the bundle, then activate explicitly →
          </Link>
        </div>
      </div>
      {message && (
        <div className="viz-notice" role="status">
          {message}
        </div>
      )}
    </section>
  )
}
