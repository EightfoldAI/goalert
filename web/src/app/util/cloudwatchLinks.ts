// Matches a "<Label>: <url>" line whose value is a CloudWatch console link.
// The whole rest of the line is taken as the URL -- emitters commonly leave the
// alarm name unencoded, so it can contain spaces.
const CONSOLE_LINE =
  /^([^\n:]{1,40}:[ \t]*)(https?:\/\/\S*console\.aws\.amazon\.com\/cloudwatch\/[^\n]*?)[ \t]*$/gm

const ALARMS_V2 = 'alarmsV2:alarm/'

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

// encodeURIComponent leaves parens alone; they would terminate a markdown href.
function encodeName(s: string): string {
  return encodeURIComponent(s).replace(/\(/g, '%28').replace(/\)/g, '%29')
}

function alarmName(fragment: string): string {
  if (fragment.startsWith(ALARMS_V2)) return fragment.slice(ALARMS_V2.length)

  // Legacy console route: #s=Alarms&alarm=<name>, name always last.
  return /(?:^|&)alarm=(.*)$/.exec(fragment)?.[1] ?? ''
}

function rebuild(url: string): string | null {
  const hash = url.indexOf('#')
  if (hash < 0) return null

  const fragment = url.slice(hash + 1)

  // Already canonical and whitespace-free (the native SNS ingress builds these
  // with url.PathEscape) -- leave byte-for-byte alone rather than round-tripping.
  if (fragment.startsWith(ALARMS_V2) && !/\s/.test(url)) return null

  const name = safeDecode(alarmName(fragment)).trim()
  if (!name) return null

  const head = url.slice(0, hash)
  const region =
    /[?&]region=([\w-]+)/.exec(head)?.[1] ??
    /^https?:\/\/([\w-]+)\.console\.aws\.amazon\.com/.exec(head)?.[1]
  if (!region) return null

  return `https://${region}.console.aws.amazon.com/cloudwatch/home?region=${region}#${ALARMS_V2}${encodeName(name)}`
}

// normalizeCloudWatchLinks rewrites CloudWatch console links in alert details to
// the canonical, percent-encoded alarmsV2 form. Unencoded alarm names (spaces,
// brackets) otherwise truncate at the first space when autolinked, and the
// legacy #s=Alarms route no longer selects the alarm.
//
// Lines that don't parse are left untouched rather than replaced with a guess.
export function normalizeCloudWatchLinks(details: string): string {
  return details.replace(CONSOLE_LINE, (line, label, url) => {
    const fixed = rebuild(url)
    return fixed ? label + fixed : line
  })
}
