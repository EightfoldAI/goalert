import { normalizeCloudWatchLinks } from './cloudwatchLinks'

const canonical =
  'https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#alarmsV2:alarm/'

test('rewrites a legacy, unencoded console link', () => {
  expect(
    normalizeCloudWatchLinks(
      'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#s=Alarms&alarm=[us-west-2] Stuck File Ingest',
    ),
  ).toBe('Console: ' + canonical + '%5Bus-west-2%5D%20Stuck%20File%20Ingest')
})

test('is a no-op on an already canonical link', () => {
  const line =
    'Console: ' + canonical + '%5Bus-west-2%5D%20Too%20Many%20Write%20Errors'
  expect(normalizeCloudWatchLinks(line)).toBe(line)
})

test('leaves the native SNS ingress output byte-for-byte alone', () => {
  // Mirrors cloudwatch/payload.go alarmConsoleURL, incl. its unescaped colon.
  const lines = [
    'Console: ' + canonical + 'x',
    'Console: ' + canonical + '%5Bus-west-2%5D%20Too%20Many%20Write%20Errors',
    'Console: ' + canonical + 'svc:sub-alarm',
  ].join('\n')
  expect(normalizeCloudWatchLinks(lines)).toBe(lines)
})

test('leaves Azure portal links alone', () => {
  const lines = [
    'Investigate: https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AlertDetails.ReactView/alertId/x',
    'Portal: https://portal.azure.com/#@/resource/subscriptions/1/resourceGroups/rg/providers/x',
  ].join('\n')
  expect(normalizeCloudWatchLinks(lines)).toBe(lines)
})

test('derives region from the subdomain when the query param is absent', () => {
  expect(
    normalizeCloudWatchLinks(
      'Console: https://us-west-2.console.aws.amazon.com/cloudwatch/home#s=Alarms&alarm=Stuck File Ingest',
    ),
  ).toBe('Console: ' + canonical + 'Stuck%20File%20Ingest')
})

test('encodes parens so they cannot terminate a markdown href', () => {
  expect(
    normalizeCloudWatchLinks(
      'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#s=Alarms&alarm=Ingest (p99)',
    ),
  ).toBe('Console: ' + canonical + 'Ingest%20%28p99%29')
})

test('tolerates a literal percent in the alarm name', () => {
  expect(
    normalizeCloudWatchLinks(
      'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#s=Alarms&alarm=CPU > 90%',
    ),
  ).toBe('Console: ' + canonical + 'CPU%20%3E%2090%25')
})

test('only touches the console line', () => {
  const details = [
    'State: OK -> ALARM',
    'Region: us-west-2',
    'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#s=Alarms&alarm=A B',
    'Alarm ARN: arn:aws:cloudwatch:us-west-2:1:alarm:A B',
  ].join('\n')

  expect(normalizeCloudWatchLinks(details)).toBe(
    [
      'State: OK -> ALARM',
      'Region: us-west-2',
      'Console: ' + canonical + 'A%20B',
      'Alarm ARN: arn:aws:cloudwatch:us-west-2:1:alarm:A B',
    ].join('\n'),
  )
})

test('leaves unparseable links alone', () => {
  const noFragment =
    'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2'
  expect(normalizeCloudWatchLinks(noFragment)).toBe(noFragment)

  const noRegion =
    'Console: https://console.aws.amazon.com/cloudwatch/home#s=Alarms&alarm=A B'
  expect(normalizeCloudWatchLinks(noRegion)).toBe(noRegion)

  const noName =
    'Console: https://console.aws.amazon.com/cloudwatch/home?region=us-west-2#s=Alarms'
  expect(normalizeCloudWatchLinks(noName)).toBe(noName)
})
