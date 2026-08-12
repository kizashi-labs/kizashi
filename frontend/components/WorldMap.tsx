'use client'

import { memo, useState, useRef, useEffect } from 'react'
import {
  ComposableMap,
  Geographies,
  Geography,
  Graticule,
  Sphere,
} from 'react-simple-maps'

// Natural Earth 110m world topology — served locally to avoid CDN dependency
const GEO_URL = '/countries-110m.json'

interface WorldMapProps {
  /** SVG viewBox width (default 800) */
  width?: number
  /** SVG viewBox height (default 400) */
  height?: number
  /** Fill colour for land areas */
  landFill?: string
  /** Stroke colour for country borders */
  borderStroke?: string
  /** Stroke width for borders */
  borderWidth?: number
  /** Fill opacity for land */
  landOpacity?: number
  /** Additional className on the wrapper div */
  className?: string
  /** Children rendered on top of the map (pins, arcs, etc.) */
  children?: React.ReactNode
  /** Called when a country is hovered, with its ISO-3 code */
  onCountryHover?: (code: string | null) => void
}

/**
 * Reusable accurate world map background using react-simple-maps.
 * Uses Natural Earth 110m resolution — country borders are geographically correct.
 *
 * The map uses an equirectangular projection so that lat/lon coordinates map
 * directly to percentage positions consistent with the existing
 * `latLonToPercent` helper:
 *   x% = ((lon + 180) / 360) * 100
 *   y% = ((90 - lat) / 180) * 100
 */
export const WorldMap = memo(function WorldMap({
  width = 800,
  height = 400,
  landFill = '#1a2d44',
  borderStroke = '#2d4a6b',
  borderWidth = 0.5,
  landOpacity = 1,
  className = '',
  children,
  onCountryHover,
}: WorldMapProps) {
  const [hovered, setHovered] = useState<string | null>(null)
  const wrapperRef = useRef<HTMLDivElement>(null)

  // Force preserveAspectRatio="none" so the SVG stretches to fill the container
  // exactly. Without this, react-simple-maps defaults to "xMidYMid meet" which
  // letterboxes the map and offsets any absolute-positioned overlays.
  useEffect(() => {
    const svg = wrapperRef.current?.querySelector('svg')
    if (svg) svg.setAttribute('preserveAspectRatio', 'none')
  })

  return (
    <div ref={wrapperRef} className={`relative w-full h-full ${className}`}>
      <ComposableMap
        projection="geoEquirectangular"
        projectionConfig={{ scale: width / (2 * Math.PI), center: [0, 0] }}
        width={width}
        height={height}
        style={{ width: '100%', height: '100%' }}
      >
        {/* Ocean background */}
        <Sphere
          id="sphere"
          fill="transparent"
          stroke="#1e2d42"
          strokeWidth={0.3}
        />

        {/* Graticule (grid lines) */}
        <Graticule stroke="#1e2d42" strokeWidth={0.3} />

        {/* Countries */}
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map(geo => {
              const isHovered = hovered === geo.rsmKey
              return (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  onMouseEnter={() => {
                    setHovered(geo.rsmKey)
                    onCountryHover?.(String(geo.properties?.['ISO_A3'] ?? geo.rsmKey))
                  }}
                  onMouseLeave={() => {
                    setHovered(null)
                    onCountryHover?.(null)
                  }}
                  style={{
                    default: {
                      fill: landFill,
                      fillOpacity: landOpacity,
                      stroke: borderStroke,
                      strokeWidth: borderWidth,
                      outline: 'none',
                    },
                    hover: {
                      fill: isHovered ? '#243d5a' : landFill,
                      fillOpacity: landOpacity,
                      stroke: borderStroke,
                      strokeWidth: borderWidth * 1.5,
                      outline: 'none',
                    },
                    pressed: {
                      fill: landFill,
                      fillOpacity: landOpacity,
                      stroke: borderStroke,
                      strokeWidth: borderWidth,
                      outline: 'none',
                    },
                  }}
                />
              )
            })
          }
        </Geographies>
      </ComposableMap>

      {/* Overlays (pins, arcs, labels) rendered in a positioned layer */}
      {children && (
        <div className="absolute inset-0 pointer-events-none">
          {children}
        </div>
      )}
    </div>
  )
})

/**
 * Converts lat/lon to percentage position on an equirectangular map.
 * Consistent with react-simple-maps' geoEquirectangular projection.
 */
export function latLonToPercent(lat: number, lon: number): { x: number; y: number } {
  const x = ((lon + 180) / 360) * 100
  const y = ((90 - lat) / 180) * 100
  return { x, y }
}
