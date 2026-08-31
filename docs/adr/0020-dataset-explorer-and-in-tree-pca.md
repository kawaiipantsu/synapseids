# 0020 — Dataset Explorer statistics and an in-tree PCA

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §19.11 asks the Dataset Explorer to visualise "feature distributions;
label distributions; correlations; outliers; protocol/port distributions;
location differences; PCA/UMAP projections where useful." Issue #37 tracks it
(Phase 4); issue #67 ("Idea: PCA / UMAP feature-space views") is the same need
stated separately and closes here too.

Constraints that shape the design:

- **Zero third-party Go dependencies** (PROJECT.md §27, §28.16). No BLAS/LAPACK,
  no gonum. Whatever numerics the explorer needs, we write with `math`.
- **Datasets are immutable** (ADR 0015). A written version's `dataset.csv` never
  changes; `manifest.json` carries a `content_hash` over the schema identity and
  the exact CSV bytes.
- **The data plane must not be touched.** The explorer is an offline, read-only
  view of already-materialised files; it has nothing to do with the packet path.
- The bundle is large (a 48×48 matrix, 48 histograms, a per-row projection) and
  must stay bounded regardless of dataset size.

## Decision

### One endpoint, computed from the CSV on disk, cached by content hash

`GET /api/v1/datasets/{ref}/stats` returns the whole bundle:
`feature_stats[48]`, `label_distribution`, `correlation`, `ports`, `protocols`,
`outliers`, `pca`. `internal/dataset.Manager.Stats` reads the version's
`dataset.csv` from disk, computes everything, and stores the result in a
process-lifetime map keyed by the version's `content_hash`. Because the CSV for
a given hash can never change, a cache hit is always valid and there is no
invalidation logic. The endpoint is read-only and needs no auth gate.

### PCA by cyclic Jacobi, stdlib-only, no UMAP

The covariance of the standardised 48-feature matrix **is** the Pearson
correlation matrix, so the explorer builds the correlation matrix once (one pass
for the means, one for the covariances) and reuses it as the eigenproblem input.
A symmetric 48×48 eigendecomposition by **cyclic Jacobi rotation** is a few
dozen lines of `math`: sweep every `p<q` pair, rotate to zero `A_pq`, accumulate
the rotations into `V`. It is bounded (a fixed sweep cap and a fixed
off-diagonal threshold), deterministic (fixed sweep order, no RNG), and for a
matrix this small it converges in well under ten sweeps and agrees with a LAPACK
symmetric solver to about 1e-10 — far tighter than a visualisation needs. The
top three eigenvectors become the loadings (sign-fixed so the
largest-magnitude component is positive, since eigenvectors are otherwise
sign-ambiguous), their eigenvalues over the trace become the explained-variance
ratios, and every row is projected onto them.

**UMAP is deferred.** A faithful UMAP needs a real numerical stack (nearest
neighbours, spectral init, stochastic gradient optimisation) and a good RNG
story; reimplementing it stdlib-only would be a large, hard-to-verify block of
code for a second projection. PCA already delivers the "feature-space view"
#67 asks for — structure, clusters and outliers are visible in the PC1/PC2
scatter. UMAP can be revisited if and when the trainer's Python side is a
natural home for it.

### Bounded everywhere

- **Histograms:** a fixed 24 buckets per feature. Edges are linear, or
  log1p-spaced when the schema `norm` hint is `log1p` and all values are ≥ 0.
  A degenerate (constant) feature reports `degenerate: true` and no histogram.
- **Correlation:** always 48×48, returned as a row-major flat `[]float32` plus
  the feature-name order. Zero-variance features correlate 0 with everything
  (and 0 on their own diagonal); any non-finite value is clamped to 0.
- **Outliers:** a row is an outlier when its largest per-feature `|z-score|`
  (population mean/stddev, zero-variance columns skipped) exceeds `6.0`. The
  list is capped at 100, worst first, each with its top three offending
  features. `count` reports the true total.
- **PCA projection:** capped at 5000 rows. A larger dataset is sampled with a
  fixed stride (`ceil(rows/5000)`) and `projection_sampled: true` is set. The
  loadings and explained variance are always computed over every row.
- Rows in `outliers` and `pca.projection` are identified by their 0-based index
  into `dataset.csv` — the CSV carries no flow-id column (ADR 0015), and rows
  are written in flow-id order, so the index is the stable handle.

### SPA

A new `#/dataset-explorer?ref=<id>@<version>` route (ML group). Each row on
ML ▸ Datasets gets an **explore** link. The view draws the label bar, a 48×48
canvas correlation heatmap (the §19.11 centrepiece), a grid of 48 mini
histograms that expand with quartile markers on click, a hand-rolled SVG PCA
scatter with a PC-axis selector, small protocol/port bars, and the outlier
table. All PCA maths is server-side, so the client stays small (~+4 KB gzip).

## Consequences

- The explorer is exact and dependency-free, and reproducible: identical CSV
  bytes always produce an identical bundle (a test asserts it).
- "Location differences" from §19.11 are **not** built here. A dataset is cut
  from one selection and its manifest records one `location`; comparing two
  locations means diffing two `stats` bundles, which is a follow-up (and a
  natural fit once training recipes mix datasets). The endpoint shape does not
  need to change for it.
- The Jacobi loop is the one piece of non-obvious numerics in `internal/dataset`.
  It is kept short and commented; `unparam`/`gocyclo`-style pressure on it was
  resolved by splitting the rotation into its own function rather than by
  cleverness.
- Every call recomputes on a cold process (no on-disk cache). The bundle for a
  ~1k-row dataset is ~300 KB of JSON and computes in a few milliseconds; a very
  large dataset pays a one-time O(rows·48²) correlation pass, still well within
  an HTTP handler.

**Revisit when:** a location/□-vs-□ comparison view is scheduled, the trainer
grows a Python-side embedding step (UMAP/t-SNE could live there), or datasets
get large enough that the stats bundle wants an on-disk cache next to
`manifest.json`.

---

⟦THUGS⟧ (c) 2026
