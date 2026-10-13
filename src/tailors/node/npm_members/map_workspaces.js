'use strict'
// npm's own workspace member set, from the @npmcli/map-workspaces bundled
// with the npm ward runs. ward starts this in its network-denied sandbox:
//
//   node map_workspaces.js <npm's node_modules> <project> <request> <out>
//
// <request> holds the package.json `workspaces` value; <out> gets a JSON
// object from each member's name to its directory, relative to <project>
// and `/`-separated, as map-workspaces found it.
const fs = require('fs')
const path = require('path')

const [modules, root, request, out] = process.argv.slice(2)
const mapWorkspaces = require(path.join(modules, '@npmcli', 'map-workspaces'))
const workspaces = JSON.parse(fs.readFileSync(request, 'utf8'))

mapWorkspaces({ cwd: root, pkg: { workspaces } }).then(found => {
  const members = {}
  for (const [name, dir] of found) {
    members[name] = path.relative(root, dir).split(path.sep).join('/')
  }
  fs.writeFileSync(out, JSON.stringify(members))
}, error => {
  process.stderr.write(`${(error && error.message) || error}\n`)
  process.exit(1)
})
