const paths: Record<string, string> = {
  dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  network:
    'M5 6l14 1M5 6l7 13M19 7l-7 12 M3 4h4v4H3z M17 5h4v4h-4z M10 17h4v4h-4z',
  brain:
    'M9 3a4 4 0 0 0-4 4 4 4 0 0 0-2 7 4 4 0 0 0 6 6h3V4L9 3z M15 3a4 4 0 0 1 4 4 4 4 0 0 1 2 7 4 4 0 0 1-6 6h-3 M5 7l4 3M3 14h5M19 7l-4 3M21 14h-5',
  flow: 'M3 7h15l-3-3M18 7l-3 3M21 17H6l3-3M6 17l3 3',
  chart: 'M3 3v18h18 M6 15l4-6 5 3 5-8',
  shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3z M8 12l3 3 5-6',
  layers: 'M12 3l10 5-10 5L2 8l10-5z M2 12l10 5 10-5M2 16l10 5 10-5',
  search: 'M16 16l5 5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  play: 'M7 3l14 9L7 21V3z',
  host: 'M3 4h18v13H3z M8 21h8M12 17v4',
}
export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name] ?? paths.layers} />
    </svg>
  )
}
