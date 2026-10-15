//! The helper script the pinned Elixir runs for the tailor. Its sha256 is
//! pinned in the host-local tripwire (`ELIXIR_HELPER_SHA256`), so an edit
//! here is an edit to that reviewed table too.

/// Helper executed BY the pinned Elixir. Mode "lock": strict-grammar AST
/// parse of mix.lock (Code.string_to_quoted with a static atom encoder —
/// never evaluated), accepting ONLY current 8-field :hex entries and
/// 4-field :git entries pinned to a full commit, emitting JSON. Mode
/// "hexmark": writes the binary .hex marker for a dep dir.
pub(super) const HELPER: &str = r##"
mode = hd(System.argv())
args = tl(System.argv())
case mode do
  "lock" ->
    [lockfile] = args
    source = File.read!(lockfile)
    if byte_size(source) > 4_000_000, do: raise("mix.lock too large")
    encoder = fn string, _meta ->
      if byte_size(string) <= 128, do: {:ok, {:atom_literal, string}}, else: {:error, "atom too long"}
    end
    {:ok, ast} = Code.string_to_quoted(source, static_atoms_encoder: encoder, existing_atoms_only: false)
    lit = fn lit, node ->
      case node do
        {:atom_literal, s} -> {:atom, s}
        s when is_binary(s) -> {:string, s}
        n when is_integer(n) -> {:int, n}
        b when is_boolean(b) -> {:bool, b}
        l when is_list(l) -> {:list, Enum.map(l, fn x -> lit.(lit, x) end)}
        {a, b} -> {:tuple, [lit.(lit, a), lit.(lit, b)]}
        {:{}, _m, elems} -> {:tuple, Enum.map(elems, fn x -> lit.(lit, x) end)}
        {:%{}, _m, pairs} -> {:map, Enum.map(pairs, fn {k, v} -> {lit.(lit, k), lit.(lit, v)} end)}
        nil -> {:atom, "nil"}
        other -> raise "mix.lock contains non-literal syntax: #{inspect(other)}"
      end
    end
    {:map, pairs} = lit.(lit, ast)
    hexre = ~r/\A[0-9a-f]{64}\z/
    namere = ~r/\A[a-z][a-z0-9_]{0,127}\z/
    entries = Enum.map(pairs, fn {k, v} ->
      app = case k do
        {:atom, a} -> a
        {:string, s} -> s
        _ -> raise "bad lock key"
      end
      unless app =~ namere, do: raise("unsafe app name #{inspect(app)}")
      case v do
        {:tuple, [{:atom, "hex"}, {:atom, pkg}, {:string, ver}, {:string, inner},
                  {:list, managers}, {:list, _deps}, {:string, "hexpm"}, {:string, outer}]} ->
          unless pkg =~ namere, do: raise("unsafe package name #{inspect(pkg)}")
          unless ver =~ ~r/\A[A-Za-z0-9._+-]+\z/, do: raise("unsafe version #{inspect(ver)}")
          unless inner =~ hexre and outer =~ hexre, do: raise("#{app}: checksums must be 64-hex (refresh the lock with current Hex)")
          mgrs = Enum.map(managers, fn {:atom, m} -> m; _ -> raise "bad manager" end)
          {:hex, %{"app" => app, "package" => pkg, "version" => ver,
                   "inner_sha256" => inner, "outer_sha256" => outer, "managers" => mgrs}}
        {:tuple, [{:atom, "hex"} | rest]} ->
          raise "#{app}: unsupported hex lock entry shape (#{length(rest) + 1} fields); refresh the lock with the pinned Hex"
        {:tuple, [{:atom, "git"}, {:string, url}, {:string, rev}, {:list, opts}]} ->
          unless url =~ ~r/\A[!#-\[\]-~]{1,2048}\z/, do: raise("#{app}: unsafe git URL #{inspect(url)}")
          unless rev =~ ~r/\A[0-9a-f]{40}\z/, do: raise("#{app}: the git revision must be a full commit")
          entry = Enum.reduce(opts, %{"app" => app, "url" => url, "rev" => rev}, fn opt, acc ->
            {key, value} = case opt do
              {:tuple, [{:atom, key}, {:string, value}]} when key in ["branch", "ref", "tag", "sparse", "subdir"] ->
                {key, value}
              {:tuple, [{:atom, "depth"}, {:int, n}]} when n > 0 ->
                {"depth", n}
              {:tuple, [{:atom, "submodules"}, {:bool, b}]} ->
                {"submodules", b}
              other ->
                raise "#{app}: unsupported git lock option #{inspect(other)}"
            end
            if Map.has_key?(acc, key), do: raise("#{app}: git lock option #{key} given twice")
            if key in ["sparse", "subdir"] and
                 (String.starts_with?(value, "/") or ".." in String.split(value, "/")),
               do: raise("#{app}: git #{key} must be a relative path inside the repository")
            Map.put(acc, key, value)
          end)
          {:git, entry}
        {:tuple, [{:atom, "git"} | _]} ->
          raise "#{app}: unsupported git lock entry shape; refresh the lock with mix deps.get"
        _ ->
          raise "#{app}: unsupported lock entry"
      end
    end)
    apps = Enum.map(entries, fn {_, entry} -> entry["app"] end)
    if length(apps) != length(Enum.uniq(apps)), do: raise("mix.lock names an app twice")
    hex = for {:hex, entry} <- entries, do: entry
    git = for {:git, entry} <- entries, do: entry
    IO.puts(JSON.encode!(%{"entries" => hex, "git" => git}))
  "hexmark" ->
    # .hex marker: exact shape Mix's Hex.SCM writes (decoded from a real
    # fetch): {{:hex, 2, 0}, %{name, version, managers, inner_checksum,
    # outer_checksum, repo}}. Mismatch => "lock mismatch" at compile.
    [dep_dir, name, version, inner, outer, managers_csv] = args
    allowed = %{"mix" => :mix, "rebar3" => :rebar3, "rebar" => :rebar, "make" => :make}
    managers = managers_csv |> String.split(",", trim: true)
               |> Enum.map(fn m -> Map.fetch!(allowed, m) end)
    term = {{:hex, 2, 0},
            %{name: name, version: version, managers: managers,
              inner_checksum: inner, outer_checksum: outer, repo: "hexpm"}}
    File.write!(Path.join(dep_dir, ".hex"), :erlang.term_to_binary(term))
    IO.puts("marked")
  other ->
    raise "unknown mode #{other}"
end
"##;
