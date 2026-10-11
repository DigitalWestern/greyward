# Editors

An editor sees a Greyward project through two things: the interpreter path inside
`.venv`, and whether the shell it was launched from has the projected
environment. Nothing else needs configuring, and nothing Greyward does is
editor-specific.

Sync first (`ward`), so `.venv` and `node_modules` exist to point at.

## Python interpreter

The interpreter is always at:

```
<project>/.venv/bin/python
```

**VS Code** finds it on its own: the Python extension discovers a `.venv` in
the workspace root and offers it as the interpreter. If it does not, run
*Python: Select Interpreter* and enter that path.

**PyCharm**: Settings → Project → Python Interpreter → Add Interpreter →
Add Local Interpreter → Existing, then pick `<project>/.venv/bin/python`.
Do not let PyCharm create a new virtualenv for the project — it would write
its own `.venv` over the projection, and the next `ward status` would report
it as a real directory written over one.

The interpreter behind that path is a symlink into the immutable store, so
it is read-only. Everything that only *reads* the environment — completion,
go-to-definition, type checking, the debugger, running tests — works
normally.

## Node

`node_modules/.bin` is where the ESLint, Prettier and TypeScript extensions
look for their binaries, and the projection puts them exactly there, so
those extensions work with no configuration.

The `node` binary itself is a different matter: it lives in the store, not
on the system PATH, because Greyward provisions the runtime the closure recorded
rather than whatever Node the machine has. An editor's integrated terminal
and task runner inherit the environment of the process that launched the
editor, so give them the projection one of two ways:

- launch the editor from a shell that has it:

  ```sh
  cd your-project
  eval "$(ward env)"
  code .          # or: pycharm .
  ```

- or use direnv, and the direnv extension for your editor, so entering the
  directory is enough:

  ```sh
  echo 'eval "$(ward env)"' > .envrc && direnv allow
  ```

`ward env` prints the same PATH and variables `ward run` gives a child; see
[CLI.md](CLI.md) for the syntax and the `--shell` rule. Without either, use
`ward run` inside the terminal (`ward run npm test`, `ward run pytest`), which
needs no setup at all.

## The buttons that will not work

A projection is a symlink into a read-only, content-addressed store object,
so nothing can be installed into it. The editor features that try are:

- PyCharm's *Python Packages* tool window, and its Install button;
- VS Code's "pip install" quick fix on an unresolved import, and any
  extension that offers to install a missing package for you;
- the npm Scripts view's *install*, and any "install dependencies?" prompt;
- PyCharm's offer to create a virtualenv or install `requirements.txt`.

They fail — some with a permissions error, some by silently replacing the
projection with a real directory. Use Greyward instead:

```sh
ward add requests        # edits the manifest, re-locks, syncs
ward remove requests
ward update              # re-lock within the manifest's constraints
```

`ward status` reports a projection something has written over, and the next
sync moves it aside — saying where it went — and re-projects, so a
misfired button is recoverable.
