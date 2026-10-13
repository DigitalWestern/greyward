'use strict'
// npm's own workspace member set, from the @npmcli/map-workspaces bundled
// with the npm ward runs. ward starts this in its network-denied sandbox:
//
//   node map_workspaces.cjs <npm's node_modules> <project> <request> <out>
//
// <request> holds the package.json `workspaces` value; <out> gets a JSON
// array of [name, directory] pairs, each directory relative to <project>
// and `/`-separated, as map-workspaces found it. Pairs, not an object, so
// a member named `__proto__` is kept like any other.
const fs = require('fs')
const path = require('path')

const [modules, root, request, out] = process.argv.slice(2)
const mapWorkspaces = require(path.join(modules, '@npmcli', 'map-workspaces'))
const workspaces = JSON.parse(fs.readFileSync(request, 'utf8'))

mapWorkspaces({ cwd: root, pkg: { workspaces } }).then(found => {
  const members = []
  for (const [name, dir] of found) {
    members.push([name, path.relative(root, dir).split(path.sep).join('/')])
  }
  fs.writeFileSync(out, JSON.stringify(members))
}, error => {
  process.stderr.write(`${(error && error.message) || error}\n`)
  process.exit(1)
})
