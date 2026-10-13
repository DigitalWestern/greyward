#!/usr/bin/env node
// Fill in the `expected` member list of every case in
// src/tailors/node/workspace_glob/corpus.json by running npm's own
// @npmcli/map-workspaces over a tree built from the case, so the Rust
// matcher (src/tailors/node/workspace_glob/) is checked against npm
// rather than against a reading of its source.
//
//   node tools/npm_workspace_corpus.js <npm's node_modules directory>
//
// for example the `lib/node_modules/npm/node_modules` of a Node install.
// Each case names `dirs` (each gets a package.json), `bare` directories
// (no package.json) and `links` ([path, symlink text]); `expected` is the
// member directories npm finds, relative to the root and sorted.
'use strict'
const fs = require('fs')
const os = require('os')
const path = require('path')

const npmModules = process.argv[2]
if (!npmModules) {
  console.error('usage: node tools/npm_workspace_corpus.js <npm node_modules dir>')
  process.exit(2)
}
const mapWorkspaces = require(path.join(npmModules, '@npmcli/map-workspaces'))
const corpusPath = path.join(__dirname, '..', 'src/tailors/node/workspace_glob/corpus.json')

async function run (testCase) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-ws-corpus-'))
  try {
    for (const dir of testCase.dirs || []) {
      fs.mkdirSync(path.join(root, dir), { recursive: true })
      const name = 'm-' + dir.replace(/[^A-Za-z0-9]/g, '_')
      fs.writeFileSync(path.join(root, dir, 'package.json'), JSON.stringify({ name }))
    }
    for (const dir of testCase.bare || []) {
      fs.mkdirSync(path.join(root, dir), { recursive: true })
    }
    for (const [link, text] of testCase.links || []) {
      fs.mkdirSync(path.dirname(path.join(root, link)), { recursive: true })
      fs.symlinkSync(text, path.join(root, link))
    }
    const pkg = { name: 'root', workspaces: testCase.workspaces }
    const found = await mapWorkspaces({ cwd: root, pkg })
    return [...found.values()]
      .map(dir => path.relative(root, dir).split(path.sep).join('/'))
      .sort()
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

async function main () {
  const corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'))
  for (const testCase of corpus) {
    testCase.expected = await run(testCase)
  }
  fs.writeFileSync(corpusPath, JSON.stringify(corpus, null, 2) + '\n')
}

main().catch(error => {
  console.error(error)
  process.exit(1)
})
