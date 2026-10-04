import type { HiddenLayer } from './arch'

export type TrainingPreset = 'balanced' | 'quick' | 'anomaly' | 'custom'
export interface RecipeSettings {
  id: string
  version: string
  name: string
  preset: TrainingPreset
  epochs: number
  learningRate: number
  hidden: HiddenLayer[]
}
export function buildRecipe(settings: RecipeSettings) {
  if (!settings.id || !settings.version)
    throw new Error('Choose a versioned dataset.')
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(settings.name))
    throw new Error(
      'Use 1–80 letters, digits, dots, underscores or hyphens for the model name.',
    )
  if (
    !Number.isInteger(settings.epochs) ||
    settings.epochs < 1 ||
    settings.epochs > 10000
  )
    throw new Error('Epochs must be between 1 and 10,000.')
  if (
    !Number.isFinite(settings.learningRate) ||
    settings.learningRate <= 0 ||
    settings.learningRate > 1
  )
    throw new Error('Learning rate must be greater than 0 and at most 1.')
  const anomaly = settings.preset === 'anomaly'
  const widths = anomaly
    ? [32, 12, 32]
    : settings.preset === 'quick'
      ? [32, 16]
      : [64, 32]
  const hidden =
    settings.preset === 'custom'
      ? settings.hidden
      : widths.map((width) => ({
          width,
          activation: 'relu',
          dropout: anomaly ? 0 : 0.2,
          batchnorm: false,
          residual: false,
        }))
  return {
    name: settings.name,
    objective: anomaly ? 'reconstruction' : 'classification',
    datasets: [
      {
        id: `${settings.id}@${settings.version}`,
        path: 'dataset.csv',
        weight: 1,
      },
    ],
    architecture: {
      family: anomaly ? 'flow-anomaly-v1' : 'flow-classifier-v1',
      input_size: 48,
      output_size: anomaly ? 48 : 7,
      hidden,
    },
    normalizer: 'standard',
    optimizer: 'adam',
    lr: settings.learningRate,
    batch_size: settings.preset === 'quick' ? 128 : 256,
    epochs: settings.epochs,
    early_stopping: { patience: 8, metric: 'val_loss' },
    class_weighting: anomaly ? 'none' : 'balanced',
    scheduler: 'cosine',
    seed: 1337,
    split: { train: 0.7, val: 0.15, test: 0.15 },
  }
}

/** Keep shell metacharacters inert, including packet-derived dataset labels. */
export function shellQuote(value: string): string {
  return "'" + value.replace(/'/g, "'\\''") + "'"
}
export function trainingCommands(name: string, reportURL: string): string {
  const base = `synapse-trainer train --recipe training-recipe.json --data . --out ${shellQuote(`./bundles/${name}`)}`
  return `${base} --dry-run\n${base} --report-to ${shellQuote(reportURL)}`
}
