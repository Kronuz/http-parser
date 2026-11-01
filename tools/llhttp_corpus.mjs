// Generates test/llhttp_corpus.inc from llhttp's markdown conformance tests.
//
//   node tools/llhttp_corpus.mjs LLHTTP_CHECKOUT > test/llhttp_corpus.inc
//   node tools/llhttp_corpus.mjs LLHTTP_CHECKOUT --check test/llhttp_corpus.inc
//
// LLHTTP_CHECKOUT is a clone of https://github.com/nodejs/llhttp at a release tag with
// `npm ci && npm run build` run in it (mdgator, the markdown reader llhttp's own runner
// uses, and build/llhttp.h, for llhttp's method numbers). The
// input transformations are those of llhttp's test/md-test.ts, so each case is the
// bytes llhttp's suite feeds its parser. The expected log is reduced to the events
// http_parser's API can report (test/conformance.cc, "Normalized events"): the method,
// protocol and version spans, the *_complete notifications, chunk extensions and
// on_reset have no http_parser callback and are dropped.
//
// llhttp is MIT-licensed (Copyright Fedor Indutny, 2018); the generated file carries
// its notice and the commit it was generated from.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const root = process.argv[2];
if (!root) {
	console.error("usage: node tools/llhttp_corpus.mjs LLHTTP_CHECKOUT [--check FILE]");
	process.exit(2);
}
const require = createRequire(path.join(path.resolve(root), "package.json"));
const { MDGator } = require("mdgator");

const files = [
	"request/sample", "request/lenient-headers", "request/lenient-header-value-relaxed",
	"request/lenient-version", "request/method", "request/uri", "request/connection",
	"request/content-length", "request/transfer-encoding", "request/invalid", "request/finish",
	"request/pausing", "request/pipelining",
	"response/sample", "response/connection", "response/content-length",
	"response/transfer-encoding", "response/invalid", "response/finish",
	"response/lenient-version", "response/pausing", "response/pipelining",
];

// llhttp's method numbers, read from the header its generator writes.
const header = fs.readFileSync(path.join(root, "build", "llhttp.h"), "utf8");
const methodMap = header.slice(header.indexOf("#define HTTP_ALL_METHOD_MAP"));
const methods = new Map();
for (const m of methodMap.matchAll(/XX\((\d+),\s*([A-Z_-]+),\s*([A-Z_-]+)\)/g)) {
	if (!methods.has(Number(m[1]))) methods.set(Number(m[1]), m[3]);
}

function transformInput(input) {
	// The same steps, in the same order, as llhttp's test/md-test.ts.
	input = input.replace(/\n$/, "");
	input = input.replace(/\\(\r\n|\r|\n)/g, "");
	input = input.replace(/\r\n|\r|\n/g, "\r\n");
	input = input.replace(/\\r/g, "\r");
	input = input.replace(/\\n/g, "\n");
	input = input.replace(/\\t/g, "\t");
	input = input.replace(/\\f/g, "\f");
	input = input.replace(/\\x([0-9a-fA-F]+)/g, (all, hex) => String.fromCharCode(parseInt(hex, 16)));
	input = input.replace(/\\([0-7]{1,3})/g, (_, digits) => String.fromCharCode(parseInt(digits, 8)));
	if (/\$\{(.+?)\}/.test(input)) throw new Error("inline JavaScript in a test input is not supported");
	return input;
}

function esc(s) {
	// Over UTF-8 bytes, as the parser sees them; test/conformance.h escapes alike.
	let out = "";
	for (const c of Buffer.from(s, "utf8")) {
		const ch = String.fromCharCode(c);
		if (ch === "\\") out += "\\\\";
		else if (c >= 0x20 && c < 0x7f) out += ch;
		else out += "\\x" + c.toString(16).padStart(2, "0");
	}
	return out;
}

// Reduces an expected log to normalized events (one per line) and an annotation.
function normalize(log, type) {
	const events = [];
	let field = null, value = null, body = null, url = null, status = null;
	const flushHeader = () => {
		if (field !== null) events.push(`header ${esc(field)}: ${esc(value ?? "")}`);
		field = value = null;
	};
	const flushBody = () => { if (body !== null) events.push(`body ${esc(body)}`); body = null; };
	const flushUrl = () => { if (url !== null) events.push(`url ${esc(url)}`); url = null; };
	const flushStatus = () => { if (status !== null) events.push(`status ${esc(status)}`); status = null; };
	const flushAll = () => { flushUrl(); flushStatus(); flushHeader(); flushBody(); };
	let note = "";
	for (const raw of log.split("\n")) {
		if (raw === "") continue;
		const line = raw.replace(/\\t/g, "\t").replace(/\\f/g, "\f");
		const m = line.match(/^off=(\d+|NULL) (.*)$/);
		if (!m) throw new Error(`unparsed log line: ${line}`);
		const rest = m[2];
		let s;
		if ((s = rest.match(/^len=(\d+) span\[([a-z_.]+)\]=(?:"(.*)"|(lf|cr))$/))) {
			const text = s[4] === "lf" ? "\n" : s[4] === "cr" ? "\r" : s[3];
			const kind = s[2];
			// method, protocol, version, chunk extensions: no http_parser callback
			if (!["url", "status", "header_field", "header_value", "body"].includes(kind)) continue;
			if (kind !== "url") flushUrl();
			if (kind !== "status") flushStatus();
			if (kind !== "body") flushBody();
			if (kind !== "header_field" && kind !== "header_value") flushHeader();
			switch (kind) {
				case "url": url = (url ?? "") + text; break;
				case "status": status = (status ?? "") + text; break;
				case "header_field":
					if (value !== null) flushHeader();
					field = (field ?? "") + text;
					break;
				case "header_value": value = (value ?? "") + text; break;
				case "body": body = (body ?? "") + text; break;
			}
			continue;
		}
		if (/^(method|url|protocol|version|status|header_field|header_value|chunk_extension_name|chunk_extension_value) complete$/.test(rest)) continue;
		if (rest === "reset" || rest === "skip body") continue;
		if (rest === "pause") {
			// A pause does not end a pending slice group (a header split by a pause in
			// on_header_field_complete is still one header): it is written where it
			// happens, before the group it interrupts.
			events.push("pause");
			continue;
		}
		flushAll();
		if (rest === "message begin") events.push("begin");
		else if ((s = rest.match(/^headers complete method=(\d+) v=(\d+)\/(\d+)/))) events.push(`headers v=${s[2]}/${s[3]} method=${methods.get(Number(s[1])) ?? "#" + s[1]}`);
		else if ((s = rest.match(/^headers complete status=(\d+) v=(\d+)\/(\d+)/))) events.push(`headers v=${s[2]}/${s[3]} status=${s[1]}`);
		else if ((s = rest.match(/^chunk header len=(\d+)$/))) events.push(`chunk ${s[1]}`);
		else if (rest === "chunk complete") events.push("chunk_done");
		else if (rest === "message complete") events.push("complete");
		else if ((s = rest.match(/^error code=(\d+) reason="(.*)"$/))) {
			const code = Number(s[1]);
			if (code === 22) events.push("upgrade");
			else if (code === 23) events.push("h2upgrade");
			else events.push("error");
			note = `off=${m[1]} code=${code} ${s[2]}`;
		} else if ((s = rest.match(/^finish=(\d+)$/))) events.push(`finish=${s[1]}`);
		else throw new Error(`unknown log event: ${line}`);
	}
	flushAll();
	return { events, note };
}

function cstr(s) {
	// UTF-8 bytes (as llhttp's runner hands the input to its parser), octal escapes for
	// every byte outside printable ASCII (no hex run-on); the length is passed alongside
	// so NUL bytes survive.
	let out = "\"";
	for (const c of Buffer.from(s, "utf8")) {
		const ch = String.fromCharCode(c);
		if (ch === "\"" || ch === "\\") out += "\\" + ch;
		else if (ch === "?") out += "\\?";
		else if (c >= 0x20 && c < 0x7f) out += ch;
		else out += "\\" + c.toString(8).padStart(3, "0");
	}
	return out + "\"";
}

const cases = [];
for (const name of files) {
	const raw = fs.readFileSync(path.join(root, "test", name + ".md"), "utf8");
	const groups = new MDGator().parse(raw);
	const walk = (group, trail) => {
		const here = [...trail, group.name];
		for (const child of group.children) walk(child, here);
		for (const test of group.tests) {
			if (!test.values.has("http")) continue;
			const meta = test.meta.get("http")[0];
			if (meta.skip === true) continue;
			const input = transformInput(test.values.get("http")[0]);
			const log = test.values.get("log")[0];
			const { events, note } = normalize(log, meta.type);
			cases.push({
				location: `${name}.md:${test.line + 1}`,
				title: [...here.slice(1), test.name].join(" > "),
				type: meta.type,
				pause: meta.pause ?? "",
				skipBody: meta.skipBody === true,
				input,
				expected: events.join("\n") + "\n",
				note,
			});
		}
	};
	for (const g of groups) walk(g, []);
}

let commit = "unknown";
try { commit = execFileSync("git", ["-C", root, "describe", "--tags", "--always"], { encoding: "utf8" }).trim() + " " + execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(); } catch { /* not a checkout */ }

let out = "";
out += "// Generated by tools/llhttp_corpus.mjs from llhttp " + commit + ".\n";
out += "// Do not edit: regenerate, and check with --check.\n";
out += "//\n";
out += "// The inputs and expected logs are llhttp's markdown conformance tests\n";
out += "// (test/request/*.md, test/response/*.md), under llhttp's license:\n";
out += "//\n";
// llhttp's LICENSE, verbatim: MIT asks for the notice in every copy.
for (const line of fs.readFileSync(path.join(root, "LICENSE"), "utf8").trimEnd().split("\n"))
	out += ("// " + line).trimEnd() + "\n";
out += `// ${cases.length} cases.\n\n`;
for (const c of cases) {
	out += `{ ${cstr(c.location)}, ${cstr(c.title)}, ${cstr(c.type)}, ${cstr(c.pause)}, ${c.skipBody ? 1 : 0},\n`;
	out += `  std::string_view(${cstr(c.input)}, ${Buffer.byteLength(c.input, "utf8")}),\n`;
	out += `  ${cstr(c.expected)},\n  ${cstr(c.note)} },\n`;
}

const check = process.argv.indexOf("--check");
if (check !== -1) {
	const current = fs.readFileSync(process.argv[check + 1], "utf8");
	if (current !== out) {
		console.error(`${process.argv[check + 1]} differs from what llhttp ${commit} generates`);
		process.exit(1);
	}
	console.error(`${process.argv[check + 1]} matches llhttp ${commit} (${cases.length} cases)`);
} else {
	process.stdout.write(out);
}
