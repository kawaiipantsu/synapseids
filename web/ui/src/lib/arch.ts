// flow-classifier-v1 architecture model — the editable hidden stack plus the
// locked 48-in / 7-out edges (PROJECT.md §10, §19.9). The parameter / size /
// FLOP formulas below are a line-for-line mirror of internal/schema/architecture.go
// and trainer/synapse_trainer/architecture.py, so the client-side estimate a
// user sees while typing matches what POST /api/v1/architecture/estimate — and,
// later, the trainer — will report.

export const INPUT_SIZE = 48
export const OUTPUT_SIZE = 7

/** Activations internal/nn can execute (see internal/nn/nn.go). */
export const ACTIVATIONS = ['relu', 'leaky_relu', 'sigmoid', 'tanh'] as const
export type Activation = (typeof ACTIVATIONS)[number]

export interface HiddenLayer {
  width: number
  activation: Activation
  dropout: number
  batchnorm: boolean
  residual: boolean
}

/** The exported shape — identical to schema.Architecture and a training recipe's `architecture` field. */
export interface Architecture {
  input_size: number
  output_size: number
  hidden: HiddenLayer[]
}

export interface LayerParams {
  name: string
  in: number
  out: number
  params: number
}

export const DEFAULT_HIDDEN: HiddenLayer[] = [
  { width: 64, activation: 'relu', dropout: 0.3, batchnorm: true, residual: false },
  { width: 32, activation: 'relu', dropout: 0.2, batchnorm: false, residual: false },
]

export function newLayer(width = 32): HiddenLayer {
  return { width, activation: 'relu', dropout: 0, batchnorm: false, residual: false }
}

/** Dense prev->w is w*prev + w; an affine BatchNorm1d(w) adds 2*w. */
export function parameterCount(hidden: HiddenLayer[]): number {
  let total = 0
  let prev = INPUT_SIZE
  for (const h of hidden) {
    total += prev * h.width + h.width
    if (h.batchnorm) total += 2 * h.width
    prev = h.width
  }
  return total + prev * OUTPUT_SIZE + OUTPUT_SIZE
}

/** Raw fp32 storage: 4 bytes per parameter. */
export function approxBytes(hidden: HiddenLayer[]): number {
  return parameterCount(hidden) * 4
}

/** ~2*in*out multiply-accumulates per Dense layer, batch 1. */
export function roughFlops(hidden: HiddenLayer[]): number {
  let flops = 0
  let prev = INPUT_SIZE
  for (const h of hidden) {
    flops += 2 * prev * h.width
    prev = h.width
  }
  return flops + 2 * prev * OUTPUT_SIZE
}

/** One row per Dense layer (each hidden block, then the locked output); rows sum to parameterCount. */
export function layerBreakdown(hidden: HiddenLayer[]): LayerParams[] {
  const rows: LayerParams[] = []
  let prev = INPUT_SIZE
  hidden.forEach((h, i) => {
    let p = prev * h.width + h.width
    if (h.batchnorm) p += 2 * h.width
    rows.push({ name: `hidden_${i + 1}${h.batchnorm ? ' (+bn)' : ''}`, in: prev, out: h.width, params: p })
    prev = h.width
  })
  rows.push({ name: 'output', in: prev, out: OUTPUT_SIZE, params: prev * OUTPUT_SIZE + OUTPUT_SIZE })
  return rows
}

/** Width feeding layer i: the input for the first layer, else the previous layer's width. */
export function prevWidth(hidden: HiddenLayer[], i: number): number {
  return i === 0 ? INPUT_SIZE : hidden[i - 1]!.width
}

/** A residual skip is only meaningful when the previous width equals this layer's width. */
export function residualEligible(hidden: HiddenLayer[], i: number): boolean {
  return prevWidth(hidden, i) === hidden[i]!.width
}

/** Clamp one layer's fields to the ranges the validator enforces and clear an
 *  ineligible residual, so the working draft is always exportable. */
export function normalizeHidden(hidden: HiddenLayer[]): HiddenLayer[] {
  const out = hidden.map((h) => ({
    width: Math.max(1, Math.floor(Number.isFinite(h.width) ? h.width : 1)),
    activation: (ACTIVATIONS as readonly string[]).includes(h.activation) ? h.activation : 'relu',
    dropout: Math.min(0.99, Math.max(0, Number.isFinite(h.dropout) ? h.dropout : 0)),
    batchnorm: !!h.batchnorm,
    residual: !!h.residual,
  })) as HiddenLayer[]
  for (let i = 0; i < out.length; i++) {
    if (out[i]!.residual && !residualEligible(out, i)) out[i]!.residual = false
  }
  return out
}

export function toArchitecture(hidden: HiddenLayer[]): Architecture {
  return { input_size: INPUT_SIZE, output_size: OUTPUT_SIZE, hidden }
}

/** Parse an imported/pasted architecture document into a clean hidden stack.
 *  Throws with a short reason on anything that is not shaped like schema.Architecture. */
export function hiddenFromUnknown(raw: unknown): HiddenLayer[] {
  const obj = raw as Record<string, unknown> | null
  if (!obj || typeof obj !== 'object') throw new Error('not a JSON object')
  const hiddenRaw = Array.isArray(obj.hidden) ? obj.hidden : Array.isArray(raw) ? (raw as unknown[]) : null
  if (!hiddenRaw) throw new Error('missing a "hidden" array')
  const hidden = hiddenRaw.map((l, i) => {
    const h = l as Record<string, unknown>
    if (!h || typeof h !== 'object') throw new Error(`hidden[${i}] is not an object`)
    const width = Number(h.width)
    if (!Number.isFinite(width)) throw new Error(`hidden[${i}].width is not a number`)
    return {
      width,
      activation: String(h.activation ?? 'relu'),
      dropout: Number(h.dropout ?? 0),
      batchnorm: !!h.batchnorm,
      residual: !!h.residual,
    } as HiddenLayer
  })
  return normalizeHidden(hidden)
}

// ---- "obviously excessive" heuristic (PROJECT.md §19.9 — warn, do not block) --

export const MAX_SANE_WIDTH = 2048
/** ~50x the default 48→64→32→7(+bn) net's parameter count. */
export const EXCESSIVE_PARAM_FACTOR = 50
const BASELINE_PARAMS = parameterCount(DEFAULT_HIDDEN)
export const EXCESSIVE_PARAM_LIMIT = BASELINE_PARAMS * EXCESSIVE_PARAM_FACTOR

export function excessiveReasons(hidden: HiddenLayer[]): string[] {
  const out: string[] = []
  const wide = hidden.filter((h) => h.width > MAX_SANE_WIDTH)
  if (wide.length > 0) {
    out.push(
      `${wide.length} hidden layer${wide.length === 1 ? '' : 's'} wider than ${MAX_SANE_WIDTH} units ` +
        `(${wide.map((h) => h.width).join(', ')}) for only ${INPUT_SIZE} input features`,
    )
  }
  const params = parameterCount(hidden)
  if (params > EXCESSIVE_PARAM_LIMIT) {
    out.push(
      `~${params.toLocaleString('en-US')} parameters is over ${EXCESSIVE_PARAM_FACTOR}x the ` +
        `${BASELINE_PARAMS.toLocaleString('en-US')}-parameter baseline net`,
    )
  }
  return out
}
