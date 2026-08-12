declare module 'react-simple-maps' {
  import { ReactNode, SVGProps, MouseEvent } from 'react'

  interface ComposableMapProps {
    projection?: string
    projectionConfig?: Record<string, unknown>
    width?: number
    height?: number
    style?: React.CSSProperties
    className?: string
    children?: ReactNode
  }

  interface GeographiesProps {
    geography: string | object
    children: (args: { geographies: Geography[] }) => ReactNode
  }

  interface Geography {
    rsmKey: string
    properties: Record<string, string | number>
    geometry: object
  }

  interface GeographyProps extends SVGProps<SVGPathElement> {
    key?: string
    geography: Geography
    style?: {
      default?: React.CSSProperties
      hover?: React.CSSProperties
      pressed?: React.CSSProperties
    }
    onMouseEnter?: (e: MouseEvent<SVGPathElement>) => void
    onMouseLeave?: (e: MouseEvent<SVGPathElement>) => void
    onClick?: (e: MouseEvent<SVGPathElement>) => void
  }

  interface SphereProps extends SVGProps<SVGPathElement> {
    id: string
    fill?: string
    stroke?: string
    strokeWidth?: number
  }

  interface GraticuleProps extends SVGProps<SVGPathElement> {
    stroke?: string
    strokeWidth?: number
  }

  interface MarkerProps {
    coordinates: [number, number]
    children?: ReactNode
    style?: {
      default?: React.CSSProperties
      hover?: React.CSSProperties
      pressed?: React.CSSProperties
    }
  }

  interface LineProps extends SVGProps<SVGPathElement> {
    from: [number, number]
    to: [number, number]
    stroke?: string
    strokeWidth?: number
    fill?: string
    strokeLinecap?: string
  }

  export function ComposableMap(props: ComposableMapProps): JSX.Element
  export function Geographies(props: GeographiesProps): JSX.Element
  export function Geography(props: GeographyProps): JSX.Element
  export function Sphere(props: SphereProps): JSX.Element
  export function Graticule(props: GraticuleProps): JSX.Element
  export function Marker(props: MarkerProps): JSX.Element
  export function Line(props: LineProps): JSX.Element
  export function ZoomableGroup(props: { children?: ReactNode; center?: [number, number]; zoom?: number }): JSX.Element
}
