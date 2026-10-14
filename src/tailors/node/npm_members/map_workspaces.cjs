'use strict'
// npm's own workspace member set, from the @npmcli/map-workspaces bundled
// with the npm ward runs. ward starts this in its network-denied sandbox:
//
//   node map_workspaces.cjs <npm's node_modules> <project> <request> <out>
//
// <request> holds the package.json `workspaces` value. <out> gets one JSON
// object: `{"members": [[name, directory], ...]}` in npm's order, each
// directory relative to <project> and `/`-separated, as map-workspaces
// found it (pairs, not an object, so a member named `__proto__` is kept),
// or `{"error": CODE}` when npm could not read the list.
//
// An error is only ever a code from the fixed list below. npm's messages
// quote the file they failed on, and a member's package.json can be a
// symlink to any file the user can read, so no message text, path or file
// content leaves this process. ward discards its stdout and stderr too.
// ward never prints the code or anything else it gets here: every failure
// is one fixed message, and the code is shown only when the user sets
// GREYWARD_DEBUG_NPM_MEMBERS. Each directory and name in a success is
// checked by ward against the member's own package.json, read beneath the
// project, before any of it is kept.
const fs = require('fs')
const path = require('path')

const CODES = new Set([
  'EJSONPARSE', 'ENOENT', 'EACCES', 'EPERM', 'ENOTDIR', 'EISDIR', 'ELOOP',
  'ENAMETOOLONG', 'EMFILE', 'ENFILE', 'EIO',
])
const [modules, root, request, out] = process.argv.slice(2)

function fail (error) {
  const code = error && typeof error.code === 'string' && CODES.has(error.code)
    ? error.code
    : 'EUNKNOWN'
  fs.writeFileSync(out, JSON.stringify({ error: code }))
}

// Every exception, in the success path too (a `name` nested too deep for
// JSON.stringify), ends as a fixed code: `.catch` comes after `.then`, so a
// throw while writing the answer reaches `fail`, never Node's own exit.
try {
  const mapWorkspaces = require(path.join(modules, '@npmcli', 'map-workspaces'))
  const workspaces = JSON.parse(fs.readFileSync(request, 'utf8'))
  mapWorkspaces({ cwd: root, pkg: { workspaces } }).then(found => {
    const members = []
    for (const [name, dir] of found) {
      members.push([name, path.relative(root, dir).split(path.sep).join('/')])
    }
    fs.writeFileSync(out, JSON.stringify({ members }))
  }).catch(fail)
} catch (error) {
  fail(error)
}
