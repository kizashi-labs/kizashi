import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

// The 予測的セキュリティ分析 screen fetched two endpoints and read neither.
//
//   const [models, setModels] = useState<PredictionModel[]>([])
//   const { data: _models } = useQuery(...)   // never read; setModels never called
//
// so the model grid rendered from an array nothing ever filled — permanently
// empty — while the request that would have filled it ran on every mount. The
// prediction query was bound to `_predictions` and read only for a
// `volume_forecast` key that this API has never returned.
//
// The card body then read fields the server does not send. It renders
// {m.accuracy}% and sizes a progress bar from the same value; /predictive/models
// returns id, name, version, algorithm, status, description, feature_count,
// training_samples, last_trained and next_retrain — no accuracy. Its status is
// "active", which is outside the page's ModelStatus union, so the status chip's
// colour and label both resolved to undefined.
//
// The generate button posted to /admin/predictive/generate. The route is
// /admin/predictive/predictions/generate, so every click 404'd — and the handler
// swallowed it with `catch {}` while a setInterval driven by Math.random() ran a
// progress bar to 100% and displayed 「予測完了」. The button reported success for
// a request that could not succeed.
//
// Finally every chart computes its axis with Math.max(...data.map(...)). On the
// empty arrays they are routinely given that is -Infinity, the x scale divides
// by (length - 1) = -1, and the axis labels render the string "-Infinity".

const page = readFileSync(
  path.join(process.cwd(), 'app/admin/predictive-analytics/page.tsx'),
  'utf-8',
)

// Strip comments so a comment quoting the defect is not mistaken for it.
const src = page
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/.*$/gm, '$1')

describe('predictive analytics page reads what it fetches', () => {
  it('renders the models the server returns rather than an empty local array', () => {
    expect(src).not.toMatch(/setModels/)
    expect(src).toMatch(/modelsResp\?\.models/)
    expect(src).toMatch(/\.map\(adaptModel\)/)
  })

  it('renders the predictions the server returns', () => {
    expect(src).toMatch(/predictionsResp\?\.predictions/)
  })

  it('does not read response keys the API never sends', () => {
    // volume_forecast is not part of any predictive response.
    expect(src).not.toMatch(/\?\.volume_forecast/)
    // accuracy is not a field of /predictive/models.
    expect(src).not.toMatch(/m\.accuracy/)
  })

  it('adapts the server model shape instead of assuming it', () => {
    expect(src).toMatch(/function adaptModel/)
    // The server's "active" must be mapped into the page's status union.
    expect(src).toMatch(/status === 'active'/)
  })
})

describe('predictive analytics page reports failure', () => {
  it('posts the generate request to the route that exists', () => {
    expect(src).toMatch(
      /'\/api\/v1\/admin\/predictive\/predictions\/generate'/,
    )
    expect(src).not.toMatch(/'\/api\/v1\/admin\/predictive\/generate'/)
  })

  it('does not swallow a failed generate request', () => {
    // `catch {}` with no body is what let a 404 read as 「予測完了」.
    expect(src).not.toMatch(/catch\s*\{\s*\}/)
    expect(src).toMatch(/setGenerateError/)
  })

  it('surfaces a failed model or prediction fetch', () => {
    expect(src).toMatch(/modelsError/)
    expect(src).toMatch(/predictionsError/)
  })

  it('does not drive the progress bar from Math.random()', () => {
    expect(src).not.toMatch(/Math\.random\(\)/)
  })
})

describe('predictive analytics charts refuse empty data', () => {
  // Each chart must bail before it computes an axis, or the labels read
  // "-Infinity" next to an empty plot.
  for (const chart of ['VolumeChart', 'AccuracyChart', 'VulnTrendChart']) {
    it(`${chart} declines to plot fewer than two points`, () => {
      const start = src.indexOf(`function ${chart}`)
      expect(start).toBeGreaterThan(-1)
      const body = src.slice(start, start + 600)
      const guardAt = body.indexOf('data.length < 2')
      const axisAt = body.indexOf('Math.max(')
      expect(guardAt).toBeGreaterThan(-1)
      expect(guardAt).toBeLessThan(axisAt)
    })
  }
})

describe('prediction severity vocabulary matches the server', () => {
  // vulnSeverity and incidentSeverity default to "low" and only step up at
  // 0.4/0.7 and 0.3/0.6, so "low" is what a healthy deployment reports. It was
  // missing from all three lookup maps, which made every lookup resolve to
  // undefined for exactly the common case.
  for (const map of ['priorityColor', 'priorityBadge', 'priorityLabel']) {
    it(`${map} covers low`, () => {
      const line = src.split('\n').find(l => l.startsWith(`const ${map}`))
      expect(line, `${map} not found`).toBeTruthy()
      expect(line).toMatch(/\blow:/)
    })
  }
})
