// traffic-classes-v1 (frozen, 7 classes). The canonical order/names come from
// GET /api/v1/schemas/classes at runtime; this is the offline fallback and the
// source of the per-class accent colours carried over from the old shell.

export const CLASS_NAMES = [
  'normal',
  'scan',
  'dos_ddos',
  'brute_force',
  'botnet_c2',
  'web_attack',
  'suspicious',
] as const

export type ClassName = (typeof CLASS_NAMES)[number]

/** CSS custom-property name that colours each class (see styles.css). */
export const CLASS_VAR: Record<string, string> = {
  normal: 'var(--normal)',
  scan: 'var(--scan)',
  dos_ddos: 'var(--dos)',
  brute_force: 'var(--brute)',
  botnet_c2: 'var(--c2)',
  web_attack: 'var(--web)',
  suspicious: 'var(--suspicious)',
}

export function classColor(name: string): string {
  return CLASS_VAR[name] ?? 'var(--dim)'
}

/** Short role tag used in the rolling-log "models" column, e.g. "P" for primary. */
export function roleInitial(role: string): string {
  return role ? role[0]!.toUpperCase() : '?'
}

export const LOW_CONFIDENCE = 0.6
