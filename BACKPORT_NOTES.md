# Jinja2 2.11.3+security.1 — Backport Notes

Security patches applied to Jinja2 2.11.3 for Python 2.7 compatibility.
Upstream source is Jinja2 3.x; patches have been adapted to avoid f-strings,
walrus operators, and other Python 3-only constructs.

## CVE-2024-22195 — `xmlattr` filter: spaces in attribute keys

**Upstream fix:** Jinja 3.1.3, commit `716795349e6f40c7ef4c4e77a3d23f35a57fb7c0`
**Files changed:** `src/jinja2/filters.py`

The `do_xmlattr` filter now rejects attribute keys containing whitespace
characters. An attacker who could control attribute key names could inject
arbitrary HTML attributes (XSS).

**Deviation from upstream:** Upstream uses a list comprehension with walrus
operator and `re.search`. Backport uses an explicit loop with `_attr_key_re`
regex (shared with CVE-2024-34064 fix) and raises `FilterArgumentError`.

## CVE-2024-34064 — `xmlattr` filter: `/`, `>`, `=` in attribute keys

**Upstream fix:** Jinja 3.1.4, commit `0668239dc6b44d0e255ce99b86a4adfd22b4b8d8`
**Files changed:** `src/jinja2/filters.py`

Extended CVE-2024-22195 fix to also reject `/`, `>`, and `=` characters in
attribute keys, per the HTML specification attribute-name-state rule.

**Deviation from upstream:** Regex `_attr_key_re = re.compile(r"[\s/>=]")`
is defined at module level (not inline) and shared between both CVE fixes.
Error message says "Invalid character in attribute name".

## CVE-2024-56326 — Sandbox bypass via indirect `str.format` reference

**Upstream fix:** Jinja 3.1.5, commit `91a972f503fe009cad77ae699cad87def24b9f8`
**Files changed:** `src/jinja2/sandbox.py`

A custom Jinja filter could capture a reference to `str.format` or
`str.format_map` and invoke it outside the sandboxed `call()` path, bypassing
the `SandboxedFormatter` safety check.

**Fix approach:** `SandboxedEnvironment.wrap_str_format()` intercepts
`str.format`/`str.format_map` bound methods at attribute access time (in
`getattr` and `getitem`). It returns a sentinel wrapper function that raises
`SecurityError` when called directly. The sandboxed `call()` method detects
the sentinel via `_jinja2_sandboxed_format` and routes through `format_string`
(i.e., `SandboxedFormatter`) instead, preserving safe template-level usage.

**Deviation from upstream:** Upstream Jinja 3.1.5 uses a wrapper that calls
`format_string` directly (no sentinel). This backport uses a sentinel pattern
so that the wrapper raises `SecurityError` when invoked by a filter (which
bypasses `call()`), while `call()` intercepts the sentinel for the safe path.
The old `inspect_format_method` path in `call()` has been removed.

## CVE-2025-27516 — Sandbox bypass via `|attr` filter accessing `format`

**Upstream fix:** Jinja 3.1.6, commit (attr filter sandbox routing)
**Files changed:** `src/jinja2/filters.py`

The `|attr` filter used `getattr` directly without going through
`SandboxedEnvironment.getattr()`, allowing it to retrieve `str.format` as a
raw, unsandboxed callable. A template could then call the method with an
attacker-controlled format string, escaping the sandbox.

**Fix:** In sandboxed environments, `do_attr()` now:
1. Calls `environment.wrap_str_format(value)` — if non-None (i.e., the value
   is `str.format`/`str.format_map`), returns `unsafe_undefined` to block it.
2. Calls `environment.is_safe_attribute()` for the standard underscore/internal
   attribute checks.

**Deviation from upstream:** Upstream routes through `environment.getattr()`
directly. The backport inlines the attribute-only checks to avoid the
item-lookup fallback that `environment.getattr()` adds (preserving `|attr`
semantics: "always an attribute, items not looked up"). The `wrap_str_format`
check is invoked on the raw `getattr` result to detect format methods.

## Not applied: CVE-2024-56201 — Arbitrary code execution via malicious extension

This CVE affects code in the Jinja 3.x compiler (`compiler.py`) that is not
present in Jinja 2.11.3. No patch required.
