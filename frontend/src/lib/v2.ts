// Small shared helpers for the v2 pages (graph colours, tier / threat-type colours).
import type { GraphNode, Tier, ThreatType } from '../api/client_v2'
import { VERDICT_COLOR, isVerdict } from './format'

/** Colour per graph node type (infrastructure nodes). Domain/URL nodes are filled by verdict instead. */
export const NODE_TYPE_COLOR: Record<string, string> = {
  domain: '#6366f1',
  url: '#8b5cf6',
  ip: '#06b6d4',
  asn: '#0ea5e9',
  ns: '#14b8a6',
  registrar: '#f59e0b',
  brand: '#f43f5e',
  tracker: '#84cc16',
  country: '#64748b',
  favicon: '#ec4899',
  redirect: '#a855f7',
}

export const NODE_TYPE_LABEL: Record<string, string> = {
  domain: 'Domain',
  url: 'URL',
  ip: 'IP address',
  asn: 'ASN',
  ns: 'Name server',
  registrar: 'Registrar',
  brand: 'Brand',
  tracker: 'Tracker',
  country: 'Country',
  favicon: 'Favicon',
  redirect: 'Redirect',
}

export const typeColor = (type: string) => NODE_TYPE_COLOR[type] ?? '#94a3b8'
export const typeLabel = (type: string) => NODE_TYPE_LABEL[type] ?? type

/** Domain and URL nodes are coloured by verdict; everything else by type. */
export function nodeFill(n: GraphNode): string {
  if ((n.type === 'domain' || n.type === 'url') && isVerdict(n.verdict)) return VERDICT_COLOR[n.verdict]
  return typeColor(n.type)
}

/** Node ids look like "ip:1.2.3.4" - this returns the part after the type prefix. */
export function nodeValue(n: GraphNode): string {
  const i = n.id.indexOf(':')
  return i >= 0 ? n.id.slice(i + 1) : n.label
}

export const TIER_COLOR: Record<Tier, string> = {
  Trusted: '#10b981',
  Favorable: '#84cc16',
  Neutral: '#64748b',
  Questionable: '#f59e0b',
  Untrusted: '#f43f5e',
}

export const THREAT_COLOR: Record<ThreatType, string> = {
  malware: '#be123c',
  social_engineering: '#f43f5e',
  unwanted_software: '#f59e0b',
  none: '#10b981',
}
