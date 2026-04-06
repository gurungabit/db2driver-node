const fs = require('node:fs')

const expected = [
  'db2-node.darwin-arm64.node',
  'db2-node.darwin-x64.node',
  'db2-node.linux-arm64-gnu.node',
  'db2-node.linux-arm64-musl.node',
  'db2-node.linux-x64-gnu.node',
  'db2-node.linux-x64-musl.node',
  'db2-node.win32-arm64-msvc.node',
  'db2-node.win32-x64-msvc.node',
]

const missing = expected.filter((file) => !fs.existsSync(file))

if (missing.length > 0) {
  console.error('Refusing to publish without the full prebuilt binary set.')
  console.error('Missing files:')
  for (const file of missing) {
    console.error(`- ${file}`)
  }
  process.exit(1)
}

console.log(`Found ${expected.length} prebuilt binaries; ready to publish.`)
