/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The Python static tool extractor, 1.17.
 *
 * Placeholder names: `add_tool(fn)` named the tool after whatever identifier it
 * was given — a loop variable, a parameter, a local holding a `Tool` object — and
 * the line matcher read `@mcp.tool() def my_tool(…)` out of docstrings. A name
 * now comes from a function the identifier is bound to (a `def` in the file, or
 * one imported from the package), a literal list a loop walks, or the callers
 * of a wrapper; a registration whose name only exists at run time is recorded,
 * never invented.
 *
 * The surface: a description or title constant imported from a sibling module
 * is read across files (one hop), a registered function's signature becomes the
 * input schema FastMCP sends, and its docstring the description when the
 * registration gives none.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { extractToolsFromSource } from '../src/acquire/toolExtract.js';
import { resolveTargets } from '../src/acquire/index.js';
import { scanSurface } from '../src/engine.js';
import { readRegistrationsWithStats } from '../src/analysis/toolRegistry.js';
import { PyPackage } from '../src/analysis/pyModules.js';
import { cleandoc } from '../src/analysis/pySignature.js';
import type { JsonSchema, SourceFile, ToolDef } from '../src/types.js';

const WORK = mkdtempSync(join(tmpdir(), 'mtc-py-117-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

const f = (path: string, content: string): SourceFile => ({ path, content });
const HEAD = 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("x")\n';
const names = (files: SourceFile[]): string[] => extractToolsFromSource(files).tools.map((t) => t.name).sort();
const tool = (files: SourceFile[], name: string): ToolDef | undefined => extractToolsFromSource(files).tools.find((t) => t.name === name);
const props = (t: ToolDef | undefined): Record<string, JsonSchema> => (t?.inputSchema?.properties ?? {}) as Record<string, JsonSchema>;

const SEARCH = `
async def search_web(query: str) -> str:
    """Search the web."""
    return query


async def fetch_page(url: str) -> str:
    """Fetch one page."""
    return url
`;

function timed(label: string, fn: () => void, budget = 1000): void {
  const t0 = performance.now();
  fn();
  const ms = performance.now() - t0;
  assert.ok(ms < budget, `${label}: ${ms.toFixed(0)} ms`);
}

// ── the placeholder spec, case by case ──────────────────────────────────────────

test('a loop over a literal table registers the functions in it, not the loop variable', () => {
  const src = HEAD + SEARCH + `
TOOLS = [(search_web, "Search"), (fetch_page, "Fetch")]
for fn, title in TOOLS:
    mcp.add_tool(fn, title=title)
`;
  const r = extractToolsFromSource([f('server.py', src)]);
  assert.deepEqual(r.tools.map((t) => t.name).sort(), ['fetch_page', 'search_web']);
  assert.equal(r.tools.find((t) => t.name === 'search_web')!.title, 'Search');
  assert.equal(r.origins['fetch_page']!.via, 'loop');
  assert.deepEqual(r.unnamed, []);
});

test('the same loop over a list built at run time invents no name and records the registration', async () => {
  const src = HEAD + `
from .registry import load_tools

TOOLS = load_tools()
for fn, title in TOOLS:
    mcp.add_tool(fn, title=title)
`;
  const r = extractToolsFromSource([f('pkg/server.py', src)]);
  assert.deepEqual(r.tools, []);
  assert.deepEqual(r.unnamed, [{ file: 'pkg/server.py', line: 9 }]);

  // Through acquisition and the engine: the surface says so, and the coverage caveat names it.
  const dir = join(WORK, 'loop-unknown');
  mkdirSync(join(dir, 'pkg'), { recursive: true });
  writeFileSync(join(dir, 'pkg', 'server.py'), src);
  writeFileSync(join(dir, 'pkg', 'registry.py'), 'def load_tools():\n    return []\n');
  const [target] = await resolveTargets(dir);
  assert.deepEqual(target!.surface.staticToolsUnnamed, [{ file: 'pkg/server.py', line: 9 }]);
  const report = await scanSurface(target!.surface, { surface: true });
  assert.ok(report.coverage.caveats.some((c) => /registrations with unknown names/.test(c) && c.includes('`pkg/server.py:9`')), report.coverage.caveats.join('\n'));
  assert.ok(report.surface!.truncated.some((t) => /pkg\/server\.py line 9: registers tools whose names cannot be read/.test(t)));
  assert.deepEqual(report.capabilities, []);
});

test('a wrapper `def register(tool): mcp.add_tool(tool)` yields what its callers pass — or a record, never `tool`', () => {
  const called = HEAD + SEARCH + `
def register(tool):
    mcp.add_tool(tool)


register(search_web)
register(tool=fetch_page)
`;
  const r = extractToolsFromSource([f('server.py', called)]);
  assert.deepEqual(r.tools.map((t) => t.name).sort(), ['fetch_page', 'search_web']);
  assert.equal(r.origins['search_web']!.via, 'helper');
  assert.deepEqual(r.origins['search_web']!.helpers, ['register']);
  assert.equal(r.origins['search_web']!.line, 18);

  // Used as a decorator.
  const decorated = HEAD + `
def register(fn):
    mcp.add_tool(fn)
    return fn


@register
def ping() -> str:
    """Ping."""
    return "pong"
`;
  assert.deepEqual(names([f('server.py', decorated)]), ['ping']);
  assert.equal(tool([f('server.py', decorated)], 'ping')!.description, 'Ping.');

  // Called nowhere in view (from another module, or not at all): recorded, not named.
  const uncalled = HEAD + '\ndef register(tool):\n    mcp.add_tool(tool)\n';
  const u = extractToolsFromSource([f('server.py', uncalled)]);
  assert.deepEqual(u.tools, []);
  assert.deepEqual(u.unnamed, [{ file: 'server.py', line: 6 }]);

  // A caller passing something unreadable is recorded at the call.
  const unread = HEAD + SEARCH + '\ndef register(tool):\n    mcp.add_tool(tool)\n\nregister(search_web)\nregister(make_tool())\n';
  const v = extractToolsFromSource([f('server.py', unread)]);
  assert.deepEqual(v.tools.map((t) => t.name), ['search_web']);
  assert.deepEqual(v.unnamed, [{ file: 'server.py', line: 18 }]);
});

test('`mcp.add_tool(search_web)` with `def search_web` in the file is search_web, as before', () => {
  assert.deepEqual(names([f('server.py', HEAD + SEARCH + '\nmcp.add_tool(search_web)\n')]), ['search_web']);
  // A positional or keyword name wins over the function's.
  assert.deepEqual(names([f('server.py', HEAD + SEARCH + '\nmcp.add_tool(search_web, "web")\nmcp.add_tool(fetch_page, name="fetch")\n')]), ['fetch', 'web']);
});

test('`mcp.add_tool(search_web)` with the function imported from the package is search_web', () => {
  const tools = f('pkg/tools.py', SEARCH);
  for (const imp of ['from .tools import search_web', 'from pkg.tools import search_web', 'from pkg.tools import (\n    fetch_page,  # unused\n    search_web,\n)']) {
    const r = extractToolsFromSource([f('pkg/server.py', HEAD + `${imp}\n\nmcp.add_tool(search_web)\n`), tools]);
    assert.deepEqual(r.tools.map((t) => t.name), ['search_web'], imp);
    assert.equal(r.tools[0]!.description, 'Search the web.', imp);
    assert.deepEqual(Object.keys(props(r.tools[0])), ['query'], imp);
  }
  // An alias registers the function's own name — what `fn.__name__` is.
  assert.deepEqual(names([f('pkg/server.py', HEAD + 'from .tools import search_web as web\nmcp.add_tool(web)\n'), tools]), ['search_web']);
  // Through a package `__init__` that re-exports it.
  const reexport = [
    f('pkg/server.py', HEAD + 'from pkg.tools import search_web\nmcp.add_tool(search_web)\n'),
    f('pkg/tools/__init__.py', 'from .web import search_web\n'),
    f('pkg/tools/web.py', SEARCH),
  ];
  assert.deepEqual(names(reexport), ['search_web']);
  // From outside the package (a dependency): not bound, recorded.
  const outside = extractToolsFromSource([f('pkg/server.py', HEAD + 'from other_dist.tools import search_web\nmcp.add_tool(search_web)\n')]);
  assert.deepEqual(outside.tools, []);
  assert.equal(outside.unnamed.length, 1);
});

test('a usage example in a docstring, a comment or a code template registers nothing', () => {
  const doc = `"""Coercion helpers.

Usage::

    @mcp.tool()
    def my_tool(names: StrList, color: IntList | None = None) -> str: ...
"""
` + HEAD + `
# @mcp.tool()
# def commented_out() -> str: ...

TEMPLATE = f'''
    @server.tool(name=spec.name, description=spec.description)
    async def handler({'{params}'}):
        """Generated handler."""
'''

CTOR = """types.Tool(name="in_a_string", description="x", inputSchema={})"""


@mcp.tool()
def real_tool(x: str) -> str:
    """The real one."""
    return x
`;
  const r = extractToolsFromSource([f('server.py', doc)]);
  assert.deepEqual(r.tools.map((t) => t.name), ['real_tool']);
  assert.deepEqual(r.unnamed, []);
  // The JavaScript matchers likewise: a JSDoc example, a comment, a template literal.
  const js = `/**
 * Usage:
 * \`\`\`ts
 * server.registerTool("my_tool", { description: "x" }, handler);
 * \`\`\`
 */
// server.tool('name', ...) or .setTool('name', ...)
const help = [\`  ctx.server.tool("my_tool", "My custom tool", {}, async () => {\`];
server.registerTool("real_js", { description: "Real." }, async () => ({}));
`;
  assert.deepEqual(names([f('dist/index.js', js)]), ['real_js']);
});

test('no stop-list: a real tool called my_tool, fn, tool or name is kept', () => {
  const src = HEAD + `
@mcp.tool()
def my_tool(x: str) -> str:
    """A tool honestly named my_tool."""
    return x


def fn(q: str) -> str:
    return q


mcp.add_tool(fn)
mcp.add_tool(fn, name="tool")
`;
  assert.deepEqual(names([f('server.py', src)]), ['fn', 'my_tool', 'tool']);
  assert.deepEqual(names([f('dist/index.js', 'server.registerTool("name", { description: "Name a colour." }, async () => ({}));')]), ['name']);
});

test('a list handler file: `name: "name" in w ? … : ""` is an operand, not a tool object (@mdedit/mcp-server 0.3.14)', () => {
  const js = `import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const groups = list.map((w) => ({
  workspaceId: w.workspaceId,
  name: "name" in w ? w.name : "",
}));
server.registerTool(
  "create_article",
  { description: "Create a durable Markdown Document.", inputSchema: { title: z.string() } },
  async () => ({}),
);
const TOOLS = [
  { name: "list_articles", description: "List the articles.", inputSchema: { type: "object" } },
  { name: 'read_article' /* by id */, description: "Read one article.", inputSchema: { type: "object" } },
];
`;
  assert.deepEqual(names([f('dist/index.js', js)]), ['create_article', 'list_articles', 'read_article']);
});

// ── more shapes, each bound or recorded ─────────────────────────────────────────

test('loops: a list, a tuple, a dict, `fn.__name__`; an element that is not a function is recorded', () => {
  const src = HEAD + SEARCH + `
def summarize(text: str) -> str:
    return text


for fn in [search_web, fetch_page]:
    mcp.add_tool(fn)

for f in (summarize,):
    mcp.add_tool(f, name=f.__name__ + "_v2" if False else f.__name__)

NAMED = {"web": search_web, "page": fetch_page}
for key, func in NAMED.items():
    mcp.add_tool(func, name=key)
`;
  const r = extractToolsFromSource([f('server.py', src)]);
  // The ternary in the third loop cannot be chosen: recorded, not guessed.
  assert.deepEqual(r.tools.map((t) => t.name).sort(), ['fetch_page', 'page', 'search_web', 'web']);
  assert.deepEqual(r.unnamed.map((u) => u.line), [22]);

  const named = HEAD + SEARCH + '\nALL = [search_web, fetch_page]\nfor tool_fn in ALL:\n    mcp.add_tool(tool_fn, name=tool_fn.__name__)\n';
  assert.deepEqual(names([f('server.py', named)]), ['fetch_page', 'search_web']);

  // A loop over something unreadable still registers a name that does not depend on it.
  const independent = HEAD + SEARCH + '\nfor opts in load_options():\n    mcp.add_tool(search_web, annotations=opts)\n';
  const ind = extractToolsFromSource([f('server.py', independent)]);
  assert.deepEqual(ind.tools.map((t) => t.name), ['search_web']);
  assert.equal(ind.origins['search_web']!.hintSource, 'unreadable');
  assert.deepEqual(ind.unnamed, []);

  const mixed = HEAD + SEARCH + '\nfrom other_dist import remote_tool\n\nALL = [search_web, remote_tool]\nfor t in ALL:\n    mcp.add_tool(t)\n';
  const m = extractToolsFromSource([f('server.py', mixed)]);
  assert.deepEqual(m.tools.map((t) => t.name), ['search_web']);
  assert.deepEqual(m.unnamed.map((u) => u.line), [18]);
});

test('a parameter, a local `Tool` object, a renamed function and an unreadable explicit name are not names', () => {
  const src = HEAD + SEARCH + `
from fastmcp.tools import Tool


class Mixin:
    def register_all(self, server, method):
        server.add_tool(method, name=self.prefix + method.__name__)


def build(spec):
    t = Tool.from_function(spec.fn, name=spec.name)
    mcp.add_tool(t)


def make(macro_name):
    async def tool_fn(**kwargs) -> str:
        return ""

    tool_fn.__name__ = macro_name
    mcp.add_tool(tool_fn)


def wrap(func):
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    mcp.add_tool(wrapper)


@mcp.tool(name=spec_name())
async def handler() -> str:
    return ""
`;
  const r = extractToolsFromSource([f('server.py', src)]);
  assert.deepEqual(r.tools, []);
  assert.equal(r.unnamed.length, 5);
});

test('a module-level def is shadowed by a parameter or a local of the same name, never by a class attribute', () => {
  const shadowed = HEAD + SEARCH + '\ndef setup(search_web):\n    mcp.add_tool(search_web)\n';
  const s = extractToolsFromSource([f('server.py', shadowed)]);
  assert.deepEqual(s.tools, []);
  assert.equal(s.unnamed.length, 1);
  const local = HEAD + SEARCH + '\ndef setup():\n    search_web = load()\n    mcp.add_tool(search_web)\n';
  assert.deepEqual(names([f('server.py', local)]), []);
  const attr = HEAD + SEARCH + '\nclass Out:\n    search_web: str = ""\n\nmcp.add_tool(search_web)\n';
  assert.deepEqual(names([f('server.py', attr)]), ['search_web']);
});

test('a decorator whose arguments open with a comment keeps its name and hints', () => {
  const src = HEAD + `
from mcp.types import ToolAnnotations


def register(mcp):
    @mcp.tool(  # type: ignore[untyped-decorator]
        annotations=ToolAnnotations(readOnlyHint=True)
    )
    async def read_memory(memory_reference: str) -> str:
        """Read memory."""
        return ""
`;
  const r = extractToolsFromSource([f('tools/memory.py', src)]);
  assert.deepEqual(r.tools.map((t) => t.name), ['read_memory']);
  assert.equal(r.origins['read_memory']!.hintSource, 'declared');
  assert.equal(r.tools[0]!.annotations?.readOnlyHint, true);
});

test('Python test modules are skipped only when they are tests; a framework `Tool(name=…)` without an inputSchema is not MCP', () => {
  const tests = f('pkg/models_test.py', 'import unittest\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP("t")\n\n@mcp.tool()\ndef test_only() -> str:\n    return ""\n');
  const module = f('pkg/tools/tool_test.py', HEAD + '\n@mcp.tool()\ndef invoke_tool(tool: str) -> str:\n    """Invoke a tool."""\n    return tool\n');
  assert.deepEqual(names([tests, module]), ['invoke_tool']);
  const framework = f('nerve/create.py', 'from mcp.server.fastmcp import FastMCP\nexample = Tool(name="get_weather", description="x", arguments=[], tool="curl x")\n');
  assert.deepEqual(names([framework]), []);
  const lowLevel = f('server.py', 'import mcp.types as types\nTOOLS = [types.Tool(name="ok", description="Fine.", inputSchema={"type": "object", "properties": {"q": {}}})]\n');
  assert.deepEqual(names([lowLevel]), ['ok']);
});

// ── constants from a sibling module ───────────────────────────────────────────────

const CONTRACT = `from typing import Final

from p.markets import MARKETS

TITLE: Final = "Web search"

DESCRIPTION: Final = """\\
Search the internet. \\
Returns ranked results.\\
"""

JOINED: Final = (
    "Search the web. "  # first line
    "Returns results."
)

PARTIAL: Final = f"Markets: {MARKET_LIST}. Pass one."
MAX_LEN: Final = 400
REEXPORTED = MARKETS
CHANGED = "before"
CHANGED = "after"
`;

test('a description or title constant imported from a sibling module is read across files, one hop', () => {
  const server = HEAD + `
from p.contract import CHANGED, DESCRIPTION, JOINED, PARTIAL, REEXPORTED, TITLE


def a(q: str) -> str:
    """Docstring a."""
    return q


def b(q: str) -> str:
    """Docstring b."""
    return q


def c(q: str) -> str:
    return q


def d(q: str) -> str:
    return q


def e(q: str) -> str:
    """Docstring e."""
    return q


mcp.add_tool(a, title=TITLE, description=DESCRIPTION)
mcp.add_tool(b, description=JOINED)
mcp.add_tool(c, description=PARTIAL)
mcp.add_tool(d, description=REEXPORTED)
mcp.add_tool(e, description=CHANGED)
`;
  const files = [f('src/p/server.py', server), f('src/p/contract.py', CONTRACT), f('src/p/markets.py', 'MARKETS = "en-gb, fr-fr"\n')];
  const tools = extractToolsFromSource(files).tools;
  const by = (n: string) => tools.find((t) => t.name === n)!;
  assert.equal(by('a').title, 'Web search');
  // The description as the server sends it: an explicit one is not cleaned like a docstring.
  assert.equal(by('a').description, 'Search the internet. Returns ranked results.');
  assert.equal(by('b').description, 'Search the web. Returns results.');
  // An f-string piece that cannot be read is left out; the rest is read.
  assert.equal(by('c').description, 'Markets: . Pass one.');
  // A constant that is itself imported is not followed a second hop; one assigned
  // twice is not a constant. Either way the docstring does not stand in for it.
  assert.equal(by('d').description, undefined);
  assert.equal(by('e').description, undefined);
});

test('a constant from a module outside the package, or a file that is not the package\'s, is not read', () => {
  const server = HEAD + 'from vendor_dist.contract import DESCRIPTION\n\ndef a(q: str) -> str:\n    """Doc."""\n    return q\n\nmcp.add_tool(a, description=DESCRIPTION)\n';
  const t = tool([f('src/p/server.py', server)], 'a');
  assert.ok(t);
  assert.equal(t!.description, undefined);
  // A file over the extractor's size limit is not part of the package it reads.
  const huge = f('src/p/contract.py', `DESCRIPTION = "x"\n${'#'.repeat(600 * 1024)}\n`);
  const h = tool([f('src/p/server.py', server.replace('vendor_dist', 'p')), huge], 'a');
  assert.equal(h!.description, undefined);
});

// ── the input schema FastMCP builds ───────────────────────────────────────────────

test('signature schemas: every annotation kind', () => {
  const src = HEAD + `
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from mcp.server.fastmcp import Context
from pydantic import Field

Mode = Annotated[Literal["fast", "slow"], Field(description="How hard to try.")]


class Item:
    pass


@mcp.tool()
def everything(
    self_like: str,
    count: int,
    ratio: float,
    flag: bool,
    tags: list[str],
    ids: List[int],
    weights: dict[str, float],
    meta: Dict[str, Any],
    note: Optional[str],
    maybe: str | None,
    either: Union[int, str],
    kind: Literal["a", "b"],
    one: Literal[1],
    query: Annotated[str, Field(min_length=1, max_length=40, description="The query.")],
    limit: int = Field(default=10, ge=1, le=100, description="Rows."),
    needed: str = Field(..., description="Required by Field(...)."),
    mode: Mode = "fast",
    item: Item | None = None,
    forward: "int" = 3,
    pair: tuple[str, ...] = (),
    *args: str,
    ctx: Context,
    **kwargs: Any,
) -> str:
    """All the kinds."""
    return ""
`;
  const t = tool([f('server.py', src)], 'everything')!;
  const p = props(t);
  assert.deepEqual(Object.keys(p), [
    'self_like', 'count', 'ratio', 'flag', 'tags', 'ids', 'weights', 'meta', 'note', 'maybe', 'either', 'kind', 'one',
    'query', 'limit', 'needed', 'mode', 'item', 'forward', 'pair',
  ]);
  assert.deepEqual(p.count, { type: 'integer' });
  assert.deepEqual(p.ratio, { type: 'number' });
  assert.deepEqual(p.flag, { type: 'boolean' });
  assert.deepEqual(p.tags, { type: 'array', items: { type: 'string' } });
  assert.deepEqual(p.ids, { type: 'array', items: { type: 'integer' } });
  assert.deepEqual(p.weights, { type: 'object', additionalProperties: { type: 'number' } });
  assert.deepEqual(p.meta, { type: 'object', additionalProperties: {} });
  assert.deepEqual(p.note, { anyOf: [{ type: 'string' }, { type: 'null' }] });
  assert.deepEqual(p.maybe, { anyOf: [{ type: 'string' }, { type: 'null' }] });
  assert.deepEqual(p.either, { anyOf: [{ type: 'integer' }, { type: 'string' }] });
  assert.deepEqual(p.kind, { enum: ['a', 'b'], type: 'string' });
  assert.deepEqual(p.one, { const: 1, type: 'integer' });
  assert.deepEqual(p.query, { type: 'string', minLength: 1, maxLength: 40, description: 'The query.' });
  assert.deepEqual(p.limit, { type: 'integer', default: 10, minimum: 1, maximum: 100, description: 'Rows.' });
  assert.deepEqual(p.needed, { type: 'string', description: 'Required by Field(...).' });
  assert.deepEqual(p.mode, { enum: ['fast', 'slow'], type: 'string', description: 'How hard to try.', default: 'fast' });
  // A class the scanner cannot see is an empty schema, never a guess (its default stays).
  assert.deepEqual(p.item, { default: null });
  assert.deepEqual(p.forward, { type: 'integer', default: 3 });
  assert.deepEqual(p.pair, { type: 'array', items: { type: 'string' } });
  assert.deepEqual(t.inputSchema!.required, ['self_like', 'count', 'ratio', 'flag', 'tags', 'ids', 'weights', 'meta', 'note', 'maybe', 'either', 'kind', 'one', 'query', 'needed']);
});

test('signature schemas: self, ctx and Context are not inputs; exclude_args hides a parameter', () => {
  const src = HEAD + `
from fastmcp import Context


class Server:
    @mcp.tool()
    def method_tool(self, q: str, context: Context[None, None] = None) -> str:
        return q


@mcp.tool(exclude_args=["secret"])
def hidden(q: str, ctx=None, secret: str = "x") -> str:
    return q
`;
  const r = extractToolsFromSource([f('server.py', src)]);
  assert.deepEqual(Object.keys(props(r.tools.find((t) => t.name === 'method_tool'))), ['q']);
  assert.deepEqual(Object.keys(props(r.tools.find((t) => t.name === 'hidden'))), ['q']);
});

test('signature schemas for add_tool(fn), in this file and in another', () => {
  const tools = f('pkg/tools.py', `from typing import Annotated
from pydantic import Field
from pkg.contract import QUERY_DOC, MAX_Q


def search(query: Annotated[str, Field(max_length=MAX_Q, description=QUERY_DOC)], page: int = 1) -> str:
    return query
`);
  const contract = f('pkg/contract.py', 'QUERY_DOC = "What to look for."\nMAX_Q = 200\n');
  const server = f('pkg/server.py', HEAD + 'from pkg.tools import search\nmcp.add_tool(search, description="Search.")\n');
  const t = tool([server, tools, contract], 'search')!;
  assert.deepEqual(t.inputSchema, {
    type: 'object',
    properties: { query: { type: 'string', maxLength: 200, description: 'What to look for.' }, page: { type: 'integer', default: 1 } },
    required: ['query'],
  });
});

// ── docstrings ──────────────────────────────────────────────────────────────────

test('the docstring is the description when the registration gives none, cleaned like inspect.cleandoc', () => {
  const src = HEAD + `
def long_signature(first_parameter: str, second_parameter: int = 0, third_parameter: bool = False) -> dict[str, str]:
    """Do the thing.

        Indented detail stays relative.
    Args:
        first_parameter: the first.
    """
    return {}


def described(q: str) -> str:
    """Docstring that is not sent."""
    return q


def unreadable(q: str) -> str:
    """Docstring that is not sent either."""
    return q


def fstring_doc(q: str) -> str:
    f"""Not a docstring: {q}"""
    return q


def expression_doc(q: str) -> str:
    """Not a docstring.""".strip()
    return q


def first_statement(q: str) -> str:
    sql = """SELECT * FROM t"""
    return sql


mcp.add_tool(long_signature)
mcp.add_tool(described, description="Explicit.")
mcp.add_tool(unreadable, description=build_description())
mcp.add_tool(fstring_doc)
mcp.add_tool(expression_doc)
mcp.add_tool(first_statement)
`;
  const r = extractToolsFromSource([f('server.py', src)]);
  const d = (n: string) => r.tools.find((t) => t.name === n)?.description;
  assert.equal(d('long_signature'), 'Do the thing.\n\n    Indented detail stays relative.\nArgs:\n    first_parameter: the first.');
  assert.equal(d('described'), 'Explicit.');
  assert.equal(d('unreadable'), undefined);
  assert.equal(d('fstring_doc'), undefined);
  assert.equal(d('expression_doc'), undefined);
  assert.equal(d('first_statement'), undefined);
  // A decorated tool: the same docstring from both readers, kept once.
  const dec = HEAD + '\n@mcp.tool()\ndef dec(x: str) -> str:\n    """\n    Line one.\n\n    Line two.\n    """\n    return x\n';
  assert.equal(tool([f('server.py', dec)], 'dec')!.description, 'Line one.\n\nLine two.');
  assert.equal(cleandoc('  First.\n\t\tTabbed.\n      Spaced.\n\n'), 'First.\n          Tabbed.\nSpaced.');
});

// ── Staan, offline ──────────────────────────────────────────────────────────────

test('a Staan-shaped package: both tools with title, description and input schema', async () => {
  const dir = join(WORK, 'staan-like');
  const write = (rel: string, content: string): void => {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  };
  write('pyproject.toml', '[project]\nname = "staan-like-mcp"\nversion = "1.0.1"\n');
  write('src/staan_like/__init__.py', '__version__ = "1.0.1"\n');
  write('src/staan_like/contract.py', `from typing import Final
WEB_SEARCH_TITLE: Final = "Web search"
WEB_SEARCH_DESCRIPTION: Final = """\\
Search the internet. \\
Returns ranked results.\\
"""
ANSWER_TITLE: Final = "Answer"
ANSWER_DESCRIPTION: Final = (
    "Answer a question with citations. "
    "Use it for a ready answer."
)
QUERY_PARAM: Final = "Search query in natural language."
MAX_QUERY: Final = 400
`);
  write('src/staan_like/server.py', `from __future__ import annotations

from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from pydantic import BaseModel, Field

from staan_like.contract import (
    ANSWER_DESCRIPTION,
    ANSWER_TITLE,
    MAX_QUERY,
    QUERY_PARAM,
    WEB_SEARCH_DESCRIPTION,
    WEB_SEARCH_TITLE,
)


class AnswerOutput(BaseModel):
    answer: Annotated[str, Field(description="The answer.")]


async def web_search(
    query: Annotated[str, Field(min_length=1, max_length=MAX_QUERY, description=QUERY_PARAM)],
    *,
    offset: Annotated[Literal[0, 10, 20], Field(description="Paging.")] = 0,
    ctx: Context,
) -> str:
    """Search the web; see the tool description registered in create_server."""
    return query


async def answer(query: str, *, mode: Literal["short", "long"] = "short", ctx: Context) -> str:
    """Ask for a grounded answer."""
    return query


def create_server() -> MCPServer:
    server = MCPServer("staan-like")
    server.add_tool(web_search, title=WEB_SEARCH_TITLE, description=WEB_SEARCH_DESCRIPTION)
    server.add_tool(answer, title=ANSWER_TITLE, description=ANSWER_DESCRIPTION)
    return server
`);
  const [target] = await resolveTargets(dir);
  const report = await scanSurface(target!.surface, { surface: true });
  const s = report.surface!;
  assert.deepEqual(s.tools.map((t) => t.name), ['answer', 'web_search']);
  const [ans, web] = s.tools;
  assert.equal(web!.title, 'Web search');
  assert.equal(web!.description, 'Search the internet. Returns ranked results.');
  assert.deepEqual(web!.inputSchema, {
    type: 'object',
    properties: {
      query: { type: 'string', minLength: 1, maxLength: 400, description: 'Search query in natural language.' },
      offset: { enum: [0, 10, 20], type: 'integer', description: 'Paging.', default: 0 },
    },
    required: ['query'],
  });
  assert.equal(ans!.title, 'Answer');
  assert.equal(ans!.description, 'Answer a question with citations. Use it for a ready answer.');
  assert.deepEqual(Object.keys(ans!.inputSchema!.properties as object), ['query', 'mode']);
  assert.deepEqual(s.truncated, []);
});

// ── hostile bounds ────────────────────────────────────────────────────────────────

test('hostile: 500 KB files, long import chains, cyclic imports — each read in under a second', () => {
  const big = 500 * 1024;
  const cases: [string, SourceFile[]][] = [];
  // A docstring of 500 KB under 200 registrations of one function.
  cases.push(['huge docstring', [f('server.py', HEAD + `def f(q: str) -> str:\n    """${'d'.repeat(big)}"""\n    return q\n` + 'mcp.add_tool(f)\n'.repeat(200))]]);
  // A name that occurs everywhere, and is the loop variable of a loop over an unreadable list.
  cases.push(['name everywhere', [f('server.py', HEAD + 'def fn(): pass\n' + 'fn fn fn fn fn fn fn fn fn fn fn fn fn fn fn fn\n'.repeat(Math.floor(big / 48)) + 'for fn in load():\n    mcp.add_tool(fn)\n')]]);
  // Thousands of add_tool calls deep in nested blocks.
  let nested = HEAD;
  for (let i = 0; i < 60; i++) nested += `${' '.repeat(i)}if x${i}:\n`;
  nested += `${' '.repeat(60)}mcp.add_tool(t)\n`.repeat(4000);
  cases.push(['add_tool flood', [f('server.py', nested.slice(0, big))]]);
  // Nested decorator argument lists and blank lines between decorator and def.
  cases.push(['decorator nest', [f('server.py', HEAD + '@a.tool('.repeat(20_000) + ')'.repeat(20_000) + '\n')]]);
  cases.push(['decorator blanks', [f('server.py', HEAD + '@mcp.tool()' + '\n'.repeat(big) + 'x = 1\n')]]);
  // A long parenthesized import list, and a 500 KB implicit concatenation.
  cases.push(['import list', [f('server.py', HEAD + 'from p.contract import (\n' + 'A,\n'.repeat(big / 3) + ')\nmcp.add_tool(A)\n')]]);
  cases.push(['concatenation', [f('server.py', HEAD + 'D = (\n' + '"x"\n'.repeat(big / 4) + ')\ndef g(): pass\nmcp.add_tool(g, description=D)\n')]]);
  // A re-export chain of 300 modules, and a cycle.
  const chain: SourceFile[] = [f('p/server.py', HEAD + 'from p.m0 import tool_fn\nmcp.add_tool(tool_fn)\n')];
  for (let i = 0; i < 300; i++) chain.push(f(`p/m${i}.py`, i === 299 ? 'def tool_fn(): pass\n' : `from p.m${i + 1} import tool_fn\n`));
  cases.push(['deep imports', chain]);
  const cycle = [
    f('p/server.py', HEAD + 'from p.a import tool_fn, DESC\nmcp.add_tool(tool_fn, description=DESC)\n'),
    f('p/a.py', 'from p.b import tool_fn, DESC\n'),
    f('p/b.py', 'from p.a import tool_fn, DESC\n'),
  ];
  cases.push(['cyclic imports', cycle]);
  // A signature of nested Annotated / Optional / list types.
  cases.push(['deep annotation', [f('server.py', HEAD + `@mcp.tool()\ndef deep(x: ${'Optional[list['.repeat(400)}str${']]'.repeat(400)}) -> str:\n    return ""\n`)]]);
  for (const [label, files] of cases) timed(label, () => extractToolsFromSource(files));

  // The deep chain and the cycle end in no name — never a loop variable, never a hang.
  assert.deepEqual(names(chain), []);
  assert.deepEqual(names(cycle), []);
  // A re-export chain within the hop limit is followed.
  const short = [f('p/server.py', HEAD + 'from p.m0 import tool_fn\nmcp.add_tool(tool_fn)\n'), f('p/m0.py', 'from p.m1 import tool_fn\n'), f('p/m1.py', 'def tool_fn(): pass\n')];
  assert.deepEqual(names(short), ['tool_fn']);
});

test('hostile: per-name work stays bounded — loops and wrapper callers over thousands of names', () => {
  const big = 500 * 1024;
  const loopsOver = (names: string[]): string => {
    let s = '';
    for (let i = 0; i < names.length; i += 200) s += `for f in [${names.slice(i, i + 200).join(', ')}]:\n    mcp.add_tool(f)\n`;
    return s;
  };
  // Every looked-up name repeated along one long line: finding each occurrence's
  // line start must not rescan the line (14 s on a 500 KB file).
  {
    const ids = Array.from({ length: 1000 }, (_, i) => `u${i}`);
    const loops = loopsOver(ids);
    let line = 'X = [';
    for (let k = 0; line.length < big - loops.length - 200; k++) line += `${ids[k % ids.length]}, `;
    const files = [f('server.py', HEAD + line + ']\n' + loops)];
    timed('long line', () => extractToolsFromSource(files));
    assert.deepEqual(names(files), []);
  }
  // Loops over 60,000 distinct unbound names: one identifier index per file,
  // not a scan of the file per name (44 s), and a cap on the elements read.
  {
    let s = HEAD;
    for (let j = 0; ; j++) {
      const loop = loopsOver(Array.from({ length: 200 }, (_, i) => `a${j * 200 + i}`));
      if (s.length + loop.length > big) break;
      s += loop;
    }
    const files = [f('server.py', s)];
    timed('distinct names', () => extractToolsFromSource(files));
    const x = extractToolsFromSource(files);
    assert.deepEqual(x.tools, []);
    assert.deepEqual(x.truncated, ['server.py'], 'the cap on elements read is said');
  }
  // Module constants and wrapper callers, each folded at the cost of a pass over
  // the file: at most a fixed number per file (240 s on a 500 KB file before).
  {
    let consts = '';
    let calls = '';
    let defs = '';
    for (let h = 0; h < 40; h++) defs += `def reg${h}(t):\n    mcp.add_tool(t)\n`;
    for (let k = 0; HEAD.length + defs.length + consts.length + calls.length < 120 * 1024; k++) {
      consts += `a${k} = b${k}\n`;
      calls += `reg${Math.floor(k / 200) % 40}(a${k})\n`;
    }
    const files = [f('server.py', HEAD + defs + consts + calls)];
    timed('wrapper callers', () => extractToolsFromSource(files), 2000);
    const x = extractToolsFromSource(files);
    assert.deepEqual(x.tools, []);
    assert.deepEqual(x.truncated, ['server.py']);
    let loops = '';
    for (let j = 0; j < 20; j++) loops += loopsOver(Array.from({ length: 200 }, (_, i) => `a${j * 200 + i}`));
    const constLoops = [f('server.py', HEAD + consts + loops)];
    timed('constant loops', () => extractToolsFromSource(constLoops), 2000);
  }
  // Thousands of functions renamed at the end of the file: one pass finds every
  // `fn.__name__ = …`, not one pass per function.
  {
    let defs = '';
    let ren = '';
    const ids = Array.from({ length: 4000 }, (_, i) => `r${i}`);
    for (const id of ids) {
      defs += `def ${id}(): pass\n`;
      ren += `${id}.__name__ = "z"\n`;
    }
    const files = [f('server.py', HEAD + defs + loopsOver(ids) + ren)];
    timed('renamed functions', () => extractToolsFromSource(files));
    assert.deepEqual(names(files), []);
  }
});

test('the reader alone: stats carry the unnamed lines, and no package means no cross-file reading', () => {
  const server = f('pkg/server.py', HEAD + 'from .tools import search_web\nmcp.add_tool(search_web)\n');
  const tools = f('pkg/tools.py', SEARCH);
  const alone = readRegistrationsWithStats(server);
  assert.deepEqual(alone.regs, []);
  assert.deepEqual(alone.unnamed, [5]);
  const withPkg = readRegistrationsWithStats(server, new PyPackage([server, tools]));
  assert.deepEqual(withPkg.regs.map((r) => r.name), ['search_web']);
  assert.deepEqual(withPkg.unnamed, []);
});
