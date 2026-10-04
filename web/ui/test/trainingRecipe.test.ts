import assert from 'node:assert/strict'
import test from 'node:test'
import { buildRecipe, shellQuote, trainingCommands, type RecipeSettings } from '../src/lib/trainingRecipe.js'
const settings: RecipeSettings = { id: 'lab/reviewed', version: 'v2', name: 'example-model', preset: 'balanced', epochs: 50, learningRate: .001, hidden: [] }
test('classifier recipes pin the dataset version and retain evaluation splits', () => {
  const recipe = buildRecipe(settings)
  assert.equal(recipe.datasets[0]!.id, 'lab/reviewed@v2')
  assert.equal(recipe.datasets[0]!.path, 'dataset.csv')
  assert.equal(recipe.architecture.output_size, 7)
  assert.deepEqual(recipe.split, { train: .7, val: .15, test: .15 })
})
test('anomaly recipe uses reconstruction, 48 outputs and no class weighting', () => {
  const recipe = buildRecipe({ ...settings, preset: 'anomaly' })
  assert.equal(recipe.objective, 'reconstruction')
  assert.equal(recipe.architecture.family, 'flow-anomaly-v1')
  assert.equal(recipe.architecture.output_size, 48)
  assert.equal(recipe.class_weighting, 'none')
})
test('invalid form values are rejected before downloading or constructing commands', () => {
  for (const change of [{ name: 'bad; command' }, { epochs: NaN }, { epochs: 0 }, { learningRate: Infinity }, { learningRate: -1 }, { id: '' }]) assert.throws(() => buildRecipe({ ...settings, ...change }))
})
test('worker commands validate first and quote shell-sensitive input literally', () => {
  assert.equal(shellQuote("a'b"), "'a'\\''b'")
  const cmd = trainingCommands('example-model', 'https://example.invalid/$(ignored)')
  assert.ok(cmd.split('\n')[0]!.endsWith('--dry-run'))
  assert.ok(cmd.includes("--report-to 'https://example.invalid/$(ignored)'"))
  assert.ok(!cmd.includes('activate'))
})
