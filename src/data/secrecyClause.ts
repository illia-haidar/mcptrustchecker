/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The clause after "tell the user" in MTC-INJ-SECRECY-1.
 *
 * A factual clause after "tell the user" turns a secrecy directive into an
 * HONESTY rule: "do not tell the user it can be sent", "never tell the user a
 * booking/order is done", "Do NOT tell the user it's impossible", "Do NOT tell
 * the user 'the payment did not go through' — funds moved". Those forbid a false
 * claim; they hide nothing. The subject has to be a third party (it, there, the
 * X, a X …, or a bare plural noun before a plural verb: "rules are stable")
 * followed within a few words by a finite verb. Two clauses stay concealment:
 *  - one about the assistant itself — "do not tell the user you are defaulting",
 *    "you cannot grant it";
 *  - one that reports an event or a data movement — "the data was sent", "their
 *    messages are logged", "this is happening". That is hiding what happened,
 *    not refusing to make a false claim. The verb group may be future ("will be
 *    uploaded", "this tool will also send"), progressive ("it's being logged"),
 *    "gets copied", or carry an adverb ("was quietly sent", "has also been
 *    forwarded"). A modal of possibility ("it can be sent") is a claim about
 *    what is possible, not an event, and stays an honesty rule. A secret or a
 *    piece of the user's data that is the subject or the object of an event
 *    needs no auxiliary: "their key leaked", "their files leaked", "the server
 *    received their messages", "the server collected your contacts", "their
 *    secrets ended up in the logs". A data movement that is under way is an
 *    event too: "the upload is in progress".
 * The user's data in someone else's hands is concealment too, with or without
 * an event verb: "the server has a copy of their SSH key", "the vendor can see
 * their messages", "their history is visible to us", "their password was in
 * the request", "the tool has access to their files", "the tool phoned home".
 * An event clause stays an honesty rule when the sentence makes the claim depend
 * on a verification BY THE SYSTEM: "the file was saved unless the call
 * succeeded", "the message was sent until the API confirms delivery", "… if the
 * response has an error" (see `verifiedAt`).
 *
 * Until round 5 of 1.16.1 all of this was a lookahead written out four times in
 * the rule's regex — 22,900 characters that V8 compiled in 100–275 ms on first
 * use, once per string width. It is now read in code over a bounded window: the
 * words after the phrase are split into tokens once, the word classes are sets,
 * and the few shapes left are small regexes compiled once. The reading is the
 * regex's, step for step: every way the lookahead could match is tried.
 */

const words = (list: string): ReadonlySet<string> => new Set(list.split('|'));

// --- Word classes ---------------------------------------------------------------
// A word is matched whole: in the middle of a clause it is a token of its own
// followed by whitespace; at the end of one, its head (letters, digits, `_`,
// `-`) may be followed by punctuation, but not by `'s` / `’t` (see `boundary`).

const AUX = words('was|were|is|are|am|get|gets|got|gotten|being|been');
const EVENT_ADV = words('also|quietly|silently|secretly|covertly|automatically|then|now|already|just|actually|still|always|immediately|later|periodically|being|been|be');
/** `logged` and `used` with their exceptions (see `LOGGED_IN`, `USED_UP`), and `backed up`. */
const EVENT_PARTICIPLE = words(
  'sent|uploaded|shared|forwarded|collected|stored|logged|recorded|tracked|transmitted|exported|copied|accessed|saved|exfiltrated|read|' +
    'included|attached|appended|posted|emailed|mailed|opened|kept|retained|used|monitored|captured|synced|synchronized|disconnected|leaked|' +
    'published|sold|scanned|harvested|transferred|relayed|submitted|downloaded|cached|indexed|inspected|viewed|stolen',
);
const EVENT_VERB = words(
  'send|upload|share|forward|collect|store|log|record|track|transmit|export|copy|access|save|exfiltrate|read|include|attach|append|post|' +
    'email|open|keep|retain|monitor|capture|sync|leak|publish|sell|scan|harvest|transfer|relay|submit|download|cache|index|inspect',
);
const EVENT_NOW = words('sends|uploads|forwards|transmits|leaks|exfiltrates|happening|happened|occurred');
/** A secret, or the user's own data: what a concealed event moves. */
const DATA_NOUN = words(
  'password|passwords|passphrase|passphrases|key|keys|token|tokens|secret|secrets|credential|credentials|seed|seeds|cookie|cookies|' +
    'session|sessions|mnemonic|mnemonics|file|files|message|messages|history|histories|keystroke|keystrokes|contact|contacts|' +
    'conversation|conversations|chat|chats|email|emails|data|document|documents|photo|photos|clipboard|location|locations|whereabouts',
);
/**
 * What happens to it, with or without an auxiliary: the event participles that
 * move or keep data, read as a simple past too ("their mnemonic leaked", "the
 * server collected their tokens"), and `backed up` / `ended up`. A state is not
 * an event: "the token used", "their session disconnected".
 */
const DATA_EVENT = words(
  'sent|uploaded|shared|forwarded|collected|stored|logged|recorded|tracked|transmitted|exported|copied|accessed|saved|exfiltrated|read|' +
    'included|attached|appended|posted|emailed|mailed|opened|kept|retained|monitored|captured|synced|leaked|published|sold|scanned|' +
    'harvested|transferred|relayed|submitted|downloaded|cached|indexed|inspected|viewed|stolen|received|exposed|stole|scraped|grabbed|' +
    'dumped|reported',
);
/** A data movement under way: "the upload is in progress". */
const DATA_MOVEMENT = words(
  'upload|uploads|download|downloads|export|exports|transfer|transfers|sync|syncs|backup|backups|exfiltration|collection|recording|' +
    'tracking|logging|monitoring|capture|scraping|harvesting',
);
const UNDER_WAY = words('underway|ongoing|happening|running');
const PHONES = words('phoned|phones|phoning|called|calls|calling');
const HAS = words('has|have|had|get|gets|got|gain|gains|gained');
/** Someone or somewhere other than the user: "our server", "us", "the vendor", "a third party", "the request", "the logs". */
const PARTY = words('our|us|we|vendor|vendors|server|servers|backend|broker|brokers|request|requests|log|logs|analytics|someone|others|anyone');
const BE_STATE = words('is|are|was|were');
const STILL = words('still|now|already');

/** "it's", "the file's": an auxiliary `'s`. */
const APOSTROPHE_S = /^[\w-]{0,24}['’]s$/;
/** "will", "would", "it'll". */
const FUTURE = /^(?:will|would|[\w-]{0,24}['’]ll)$/;
/** A bare `be` is an auxiliary unless a modal of possibility, `to` or a negation stands right before it. */
const BARE_BE = /(?<!\b(?:can|could|may|might|must|should|shall|to|not|never)\s)be/iy;
/** "logged in / out / on / off" and "used up" are states, not events. */
const LOGGED_IN = /\s+(?:in|out|on|off)\b/iy;
const USED_UP = /\s+up\b/iy;
const USERS = /^user['’]s$/;
/** "third party" / "third-parties": one separator character between the two words. */
const THIRD_PARTY = /third[\s-]part(?:y|ies)\b/iy;
const UP = words('up');
const ACCESS = words('access');
const TO = words('to');

// --- Tokens ---------------------------------------------------------------------

interface Token {
  /** Start; end of the `[\w'’/-]` run; end of its `[\w-]` head; end of its `\w` head. */
  s: number;
  e: number;
  core: number;
  w: number;
  /** Start of the next token when whitespace follows the run, else -1. */
  next: number;
  /** Length of that whitespace. */
  gap: number;
  /** The run, its `[\w-]` head and its `\w` head, lower-cased ("\u0000" when longer than any word read here). */
  word: string;
  head: string;
  wd: string;
}

const LONGEST = 40;
const isWord = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isHead = (c: number): boolean => isWord(c) || c === 45;
const isRun = (c: number): boolean => isHead(c) || c === 39 || c === 0x2019 || c === 47;
const SPACE = /\s/;
const lower = (text: string, s: number, e: number): string => (e - s <= LONGEST ? text.slice(s, e).toLowerCase() : '\u0000');

/**
 * Up to `max` tokens from `at`: runs of `[\w'’/-]` separated by whitespace. A
 * run not followed by whitespace ends the list — no clause reads across
 * punctuation.
 */
function tokensAt(text: string, at: number, max: number): Token[] {
  const out: Token[] = [];
  let s = at;
  while (out.length < max) {
    let e = s;
    while (e < text.length && isRun(text.charCodeAt(e))) e++;
    if (e === s) break;
    let core = s;
    while (core < e && isHead(text.charCodeAt(core))) core++;
    let w = s;
    while (w < core && isWord(text.charCodeAt(w))) w++;
    let n = e;
    while (n < text.length && SPACE.test(text[n]!)) n++;
    out.push({ s, e, core, w, next: n > e ? n : -1, gap: n - e, word: lower(text, s, e), head: lower(text, s, core), wd: lower(text, s, w) });
    if (n === e) break;
    s = n;
  }
  return out;
}

const at = (re: RegExp, text: string, i: number): boolean => {
  re.lastIndex = i;
  return re.test(text);
};
/** A word in the middle of a clause: the whole token, whitespace after it. */
const whole = (t: Token | undefined, set: ReadonlySet<string>): t is Token => t !== undefined && t.next >= 0 && set.has(t.word);
/** After a clause's last word, `'s` / `’t` would continue it. */
const boundary = (text: string, i: number): boolean => {
  const c = text.charCodeAt(i);
  return !((c === 39 || c === 0x2019) && /[A-Za-z]/.test(text[i + 1] ?? ''));
};
/** The last word of a clause: the token's head, not continued. */
const last = (text: string, t: Token | undefined, set: ReadonlySet<string>): t is Token => t !== undefined && set.has(t.head) && boundary(text, t.core);
const lastIs = (text: string, t: Token | undefined, word: string): t is Token => t !== undefined && t.head === word && boundary(text, t.core);

// --- An event or a data movement -------------------------------------------------

/** The token indices after a future auxiliary at `i` and up to two adverbs: "will", "will also", "it'll quietly". */
function futureEnds(t: Token[], i: number): number[] {
  const f = t[i];
  if (!f || f.next < 0 || !FUTURE.test(f.word)) return [];
  const out = [i + 1];
  if (whole(t[i + 1], EVENT_ADV)) {
    out.push(i + 2);
    if (whole(t[i + 2], EVENT_ADV)) out.push(i + 3);
  }
  return out;
}

/** The token indices after an auxiliary at `i`: "was", "gets", "it's", "will be", "would also get", a bare "be". */
function auxEnds(text: string, t: Token[], i: number): number[] {
  const a = t[i];
  if (!a || a.next < 0) return [];
  const out: number[] = [];
  if (AUX.has(a.word) || APOSTROPHE_S.test(a.word) || (a.word === 'be' && at(BARE_BE, text, a.s))) out.push(i + 1);
  for (const n of futureEnds(t, i)) {
    const b = t[n];
    if (b && b.next >= 0 && (b.word === 'be' || b.word === 'get')) out.push(n + 1);
  }
  return out;
}

/** `n`, and past one or two adverbs: "was sent", "was also sent", "was then quietly sent". */
function advEnds(t: Token[], n: number): number[] {
  const out = [n];
  if (whole(t[n], EVENT_ADV)) {
    out.push(n + 1);
    if (whole(t[n + 1], EVENT_ADV)) out.push(n + 2);
  }
  return out;
}

type Open = (end: number) => boolean;

/** What has been read of one field, by position: each claim end and each marker is read once. */
interface Memo {
  /** Claim end → does a verification by the system follow it (see `verifiedAt`)? */
  verified: Map<number, boolean>;
  /** Marker position → does it open one (see `markerVerifies`)? */
  markers: Map<number, boolean>;
}

/** A participle ending the clause at `j`. */
function participle(text: string, t: Token[], j: number, open: Open): boolean {
  const p = t[j];
  if (!p) return false;
  if (last(text, p, EVENT_PARTICIPLE) && !(p.head === 'logged' && at(LOGGED_IN, text, p.core)) && !(p.head === 'used' && at(USED_UP, text, p.core)) && open(p.core)) return true;
  return p.word === 'backed' && p.next >= 0 && lastIs(text, t[j + 1], 'up') && open(t[j + 1]!.core);
}

/** A data event ending the clause at `j`: "leaked", "ended up". */
function dataEvent(text: string, t: Token[], j: number, open: Open): boolean {
  const p = t[j];
  if (!p) return false;
  if (last(text, p, DATA_EVENT) && !(p.head === 'logged' && at(LOGGED_IN, text, p.core)) && open(p.core)) return true;
  return (p.word === 'backed' || p.word === 'ended') && p.next >= 0 && lastIs(text, t[j + 1], 'up') && open(t[j + 1]!.core);
}

/** The token index after a data event (or "got") at `i` in the middle of a clause: "collected", "got", "backed up". */
function dataEventLead(text: string, t: Token[], i: number): number[] {
  const a = t[i];
  if (!a || a.next < 0) return [];
  if ((DATA_EVENT.has(a.word) || a.word === 'got') && !(a.word === 'logged' && at(LOGGED_IN, text, a.e))) return [i + 1];
  if ((a.word === 'backed' || a.word === 'ended') && whole(t[i + 1], UP)) return [i + 2];
  return [];
}

/**
 * The user's own data from `i`: "their SSH key", "your messages", "the user's
 * files" — up to two plain words before the noun. Returns [end, token index] of
 * each noun that ends the clause.
 */
function userData(text: string, t: Token[], i: number): [number, number][] {
  const a = t[i];
  if (!a || a.next < 0) return [];
  let n = -1;
  if (a.word === 'their' || a.word === 'your') n = i + 1;
  else if (a.word === 'the' && t[i + 1] && t[i + 1]!.next >= 0 && USERS.test(t[i + 1]!.word)) n = i + 2;
  if (n < 0) return [];
  const out: [number, number][] = [];
  for (let j = 0; j <= 2; j++) {
    const k = n + j;
    if (last(text, t[k], DATA_NOUN)) out.push([t[k]!.core, k]);
    // A word skipped before the noun is plain: no apostrophe, no slash.
    const skip = t[k];
    if (!skip || skip.next < 0 || skip.core !== skip.e) break;
  }
  return out;
}

/** The token index after a party at `i`: "our", "vendors", "third-party", "third party". */
function partyLead(t: Token[], i: number): number[] {
  const a = t[i];
  if (!a || a.next < 0) return [];
  if (PARTY.has(a.word)) return [i + 1];
  if (a.word === 'third-party' || a.word === 'third-parties') return [i + 1];
  if (a.word === 'third' && a.gap === 1 && t[i + 1] && t[i + 1]!.next >= 0 && (t[i + 1]!.word === 'party' || t[i + 1]!.word === 'parties')) return [i + 2];
  return [];
}

/** Is a party named within six words after the noun at token `k`: "their history is visible to us"? */
function partyFollows(text: string, t: Token[], k: number): boolean {
  const noun = t[k]!;
  if (noun.core !== noun.e || noun.next < 0) return false;
  for (let j = k + 1; j <= k + 7 && j < t.length; j++) {
    const p = t[j]!;
    if (PARTY.has(p.wd) || at(THIRD_PARTY, text, p.s)) return true;
  }
  return false;
}

/** Does an event or a data movement start at token `i` and end where `open` says the claim waits for nothing? */
function eventAt(text: string, t: Token[], i: number, open: Open): boolean {
  // "was (also) sent", "will be uploaded", "it's being logged", "gets copied"
  for (const n of auxEnds(text, t, i)) for (const m of advEnds(t, n)) if (participle(text, t, m, open)) return true;
  // "will send", "it'll quietly upload"
  for (const n of futureEnds(t, i)) if (last(text, t[n], EVENT_VERB) && open(t[n]!.core)) return true;
  // "sends", "this is happening"
  if (last(text, t[i], EVENT_NOW) && open(t[i]!.core)) return true;
  // "their key leaked", "the token got sent"
  if (whole(t[i], DATA_NOUN)) for (let j = 0; j <= 2; j++) if (dataEvent(text, t, i + 1 + j, open)) return true;
  // "the server received their messages", "got their token"
  for (const n of dataEventLead(text, t, i)) for (let j = 0; j <= 3; j++) if (last(text, t[n + j], DATA_NOUN) && open(t[n + j]!.core)) return true;
  // "the upload is (still) in progress"
  if (whole(t[i], DATA_MOVEMENT) && whole(t[i + 1], BE_STATE)) {
    for (const n of whole(t[i + 2], STILL) ? [i + 2, i + 3] : [i + 2]) {
      const a = t[n];
      if (last(text, a, UNDER_WAY) && open(a.core)) return true;
      if (a && a.next >= 0 && (a.word === 'in' || a.word === 'taking') && lastIs(text, t[n + 1], a.word === 'in' ? 'progress' : 'place') && open(t[n + 1]!.core)) return true;
    }
  }
  // "the tool phoned home"
  if (whole(t[i], PHONES) && lastIs(text, t[i + 1], 'home') && open(t[i + 1]!.core)) return true;
  // "the tool has access to their files"
  if (whole(t[i], HAS) && whole(t[i + 1], ACCESS) && whole(t[i + 2], TO)) {
    for (const [end] of userData(text, t, i + 3)) if (open(end)) return true;
  }
  // "the server has a copy of their SSH key", "a third party now has their data"
  for (const n of partyLead(t, i)) {
    for (let j = 0; j <= 4 && n + j < t.length; j++) for (const [end] of userData(text, t, n + j)) if (open(end)) return true;
  }
  // "their history is visible to us"
  for (const [end, k] of userData(text, t, i)) if (partyFollows(text, t, k) && open(end)) return true;
  return false;
}

/**
 * Does the clause at `q` report an event or a data movement — within its first
 * six words — that no verification by the system qualifies? The claim ends it
 * asks about are token ends of the 24 tokens read, so a candidate asks
 * `verifiedAt` about at most 24 positions per clause start, each read once per
 * field (see `Memo`).
 */
function concealedAt(text: string, q: number, memo: Memo): boolean {
  const t = tokensAt(text, q, 24);
  const open: Open = (end) => !verifiedAt(text, end, memo);
  for (let k = 0; k <= 5 && k < t.length; k++) if (eventAt(text, t, k, open)) return true;
  return false;
}

// --- A claim that waits for a verification ----------------------------------------
// "unless the call succeeded", "unless verify_key returned ok", "unless it
// actually did", "until the API confirms delivery", "if the response has an
// error", "when save_file failed". The condition's subject has to be the
// SYSTEM, from a closed list: "it" (the operation), a tool named in identifier
// form (`verify_key`, `uploadStatus`), or the call, the request, the operation,
// the upload / export / download / sync / job / task / write, the API, the
// server, the response — after "the", "its", "this" or "that", with at most one
// modifier ("the server's response", "the API call") — and its verb follows it
// directly. Any other subject waits for nothing: a person ("unless they ask if
// it was", "until the user confirms"), a role or an organisation ("unless the
// client says it was", "until the team says so"), no subject at all ("unless
// questioned whether it was", "unless prompted about it"), a passive ("unless
// it is asked about"). The event stays hidden until somebody finds out. Any
// other suffix leaves the event hidden as well: "…, even if they ask whether it
// did", "… when it returns", "…, even if the call fails", "… if the upload
// succeeded".

const MARKER = /(?:\b(unless|until)|(?<!\beven\s)\b(if|when|whenever))\s+/iy;
const SYSTEM_NOUN = words(
  'call|calls|request|requests|operation|operations|upload|uploads|export|exports|download|downloads|sync|syncs|job|jobs|task|tasks|' +
    'write|writes|api|apis|server|servers|response|responses',
);
const SYSTEM_DET = words('the|its|this|that');
/** A tool named in identifier form: `verify_key`, `upload_status`, `uploadStatus`. */
const TOOL_NAME = /^[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+$|^[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*$/;
const BE_FORM = words('is|are|was|were');
/** "asked", "questioned", "shown": after a form of "be", a passive with no agent. */
const PARTICIPLE = /^[a-z]{2,}(?:ed|en|wn)$/;
const UNLESS_VERB = words('did|does|was|were|is|are|has|had|succeed|succeeds|succeeded|returned|returns|confirm|confirms|confirmed|verifies|verified');
const UNTIL_VERB = words('confirm|confirms|confirmed|returns|returned|reports|succeeds|finishes|completes');
const UNTIL_STATE = words('done|confirmed|complete|verified');
const IF_VERB = words('fail|fails|failed|error|errors|errored');
const IF_REPORTS = words('returns|returned|has|had|contains');
const ERROR = words('error|errors');
const SAYS = words('says|said');
const REALLY = words('actually|really');
const AN = words('a|an');

/** Is there a verb of `marker` at token `j`: "succeeded", "says so", "is done", "returns an error"? */
function verbAt(t: Token[], j: number, marker: string): boolean {
  const v = t[j];
  if (!v) return false;
  const so = whole(v, SAYS) && t[j + 1]?.wd === 'so';
  if (marker === 'unless') return UNLESS_VERB.has(v.wd) || so || (whole(v, REALLY) && (UNLESS_VERB.has(t[j + 1]?.wd ?? '') || (whole(t[j + 1], SAYS) && t[j + 2]?.wd === 'so')));
  if (marker === 'until') return UNTIL_VERB.has(v.wd) || (so && v.word === 'says') || (v.word === 'is' && v.next >= 0 && UNTIL_STATE.has(t[j + 1]?.wd ?? ''));
  if (IF_VERB.has(v.wd)) return true;
  if (!whole(v, IF_REPORTS)) return false;
  return ERROR.has(t[j + 1]?.wd ?? '') || (whole(t[j + 1], AN) && ERROR.has(t[j + 2]?.wd ?? ''));
}

/** The token index after a system subject at the start of `t` (see above), or -1. */
function systemSubject(text: string, t: Token[]): number {
  const a = t[0];
  if (!a || a.next < 0) return -1;
  if (a.word === 'it' || (a.core === a.e && a.e - a.s <= 64 && TOOL_NAME.test(text.slice(a.s, a.e)))) return 1;
  let k = SYSTEM_DET.has(a.word) ? 1 : 0;
  // One modifier: "the server's response", "the API call", "the upload job".
  const mod = t[k];
  if (mod && mod.next >= 0 && SYSTEM_NOUN.has(mod.head) && (mod.word === mod.head || APOSTROPHE_S.test(mod.word)) && whole(t[k + 1], SYSTEM_NOUN)) k++;
  return whole(t[k], SYSTEM_NOUN) ? k + 1 : -1;
}

/** Does the marker at `i` open a verification by the system: "unless the call succeeded"? */
function markerVerifies(text: string, i: number): boolean {
  MARKER.lastIndex = i;
  const m = MARKER.exec(text);
  if (!m) return false;
  const marker = (m[1] ?? m[2])!.toLowerCase();
  const t = tokensAt(text, i + m[0].length, 8);
  const v = systemSubject(text, t);
  if (v < 0) return false;
  // "unless it is asked about": a passive names no one who verifies.
  const p = t[v + 1];
  if (BE_FORM.has(t[v]?.word ?? '') && p && PARTICIPLE.test(p.wd) && !UNTIL_STATE.has(p.wd)) return false;
  return verbAt(t, v, marker);
}

/**
 * Does the claim ending at `end` wait for a verification by the system — a
 * marker within 80 characters of its own sentence, then a system subject and
 * its verb? Each claim end and each marker is read once per field.
 */
function verifiedAt(text: string, end: number, memo: Memo): boolean {
  const hit = memo.verified.get(end);
  if (hit !== undefined) return hit;
  let v = false;
  for (let i = end; i <= end + 80 && i < text.length; i++) {
    const c = text[i]!;
    if (c === 'u' || c === 'i' || c === 'w' || c === 'U' || c === 'I' || c === 'W') {
      let ok = memo.markers.get(i);
      if (ok === undefined) memo.markers.set(i, (ok = markerVerifies(text, i)));
      if (ok) {
        v = true;
        break;
      }
    }
    if (c === '.' || c === ';' || c === '!' || c === '?' || c === '\n') break;
  }
  memo.verified.set(end, v);
  return v;
}

// --- The honest clause, and the rule's regex ---------------------------------------

/**
 * The shape of a factual claim: a third-party subject ("it", "the payment", "a
 * booking", "there") and a finite verb within six words, or a bare plural noun
 * before a plural verb ("rules are stable"). A subject about the assistant —
 * you, I, we — is no third party.
 */
const HONEST_SHAPE = new RegExp(
  String.raw`it['’]s\b|(?:it|this|there|they|he|she|the|a|an|any|no|some|its|their|his|her)\s+(?:(?!(?:you|your|i|we|my|our)\b)[\w'’/-]+\s+){0,5}?` +
    String.raw`(?:is|are|was|were|isn['’]?t|wasn['’]?t|aren['’]?t|weren['’]?t|can|cannot|can['’]?t|could|couldn['’]?t|did|didn['’]?t|does|doesn['’]?t|will|won['’]?t|` +
    String.raw`would|wouldn['’]?t|has|hasn['’]?t|have|haven['’]?t|had|hadn['’]?t|should|must|may|might|\w{2,}ed)\b` +
    String.raw`|[a-z][\w'’-]*s\s+(?:are|were|have|aren['’]?t|weren['’]?t|haven['’]?t)\b`,
  'iy',
);
/** Where the clause starts: after ", that " or a space, and an opening quote ("tell the user 'the payment …'"). */
const CLAUSE_STARTS = [/,?\s+that\s+["'“‘]?/iy, /\s+["'“‘]?/y];

/**
 * Is the text at `end` — right after "tell the user" — an honesty rule: a
 * factual claim about a third party that reports no hidden event?
 */
export function honestClauseAt(text: string, end: number, memo: Memo = { verified: new Map(), markers: new Map() }): boolean {
  for (const start of CLAUSE_STARTS) {
    start.lastIndex = end;
    const m = start.exec(text);
    if (m && at(HONEST_SHAPE, text, end + m[0].length) && !concealedAt(text, end + m[0].length, memo)) return true;
  }
  return false;
}

/**
 * How many "tell the user" sites of one field have their clause read. A field
 * with more is padding, not prose: from the next site on, a gated match counts
 * as 1.16.0 counted every one of them — as concealment. Which sites those are
 * depends on the text alone (the first CANDIDATES in it), not on how the field
 * is searched.
 */
const CANDIDATES = 256;

/** One field's reading (see `Memo`), with its verdicts per site. */
interface Reading extends Memo {
  text: string;
  /** The start of the last site whose clause is read; found on first use. */
  limit?: number;
  /** Clause start → `honestClauseAt`. */
  honest: Map<number, boolean>;
}

/**
 * The rule's regex: `gated|plain`, where a match of `gated` ("do not tell the
 * user", "without telling the user", "never mention the user") counts only
 * when no honest clause follows it. At the leftmost position where any branch
 * matches, a gated match followed by an honest clause gives way to a plain
 * branch at that position ("do not mention this" in "do not mention this to the
 * user <honest clause>"), and failing that the search resumes one character
 * later — what a negative lookahead after each gated branch did. A subclass of
 * RegExp, so that `test`, `match`, `matchAll` and `exec` all apply the check:
 * each of them goes through `exec`, and `matchAll` copies the class.
 */
export function secrecyPattern(gated: string, plain: string): RegExp {
  interface Parts {
    scan: RegExp;
    gated: RegExp;
    plain: RegExp;
    /** Every gated site, to find the field's CANDIDATES-th. */
    sites: RegExp;
    /** The field read last: the same field is searched many times in a row. */
    reading?: Reading;
  }
  const compiled = new Map<boolean, Parts>();
  const parts = (ignoreCase: boolean): Parts => {
    let p = compiled.get(ignoreCase);
    if (!p) {
      const f = ignoreCase ? 'i' : '';
      p = {
        scan: new RegExp(`${gated}|${plain}`, `g${f}`),
        gated: new RegExp(gated, `y${f}`),
        plain: new RegExp(plain, `y${f}`),
        sites: new RegExp(gated, `g${f}`),
      };
      compiled.set(ignoreCase, p);
    }
    return p;
  };
  /** Is the clause after the site at `site`, ending its phrase at `end`, an honesty rule? Read once per field and position. */
  const honestAt = (p: Parts, text: string, site: number, end: number): boolean => {
    let r = p.reading;
    if (r?.text !== text) p.reading = r = { text, honest: new Map(), verified: new Map(), markers: new Map() };
    if (r.limit === undefined) {
      r.limit = Infinity;
      let n = 0;
      for (const m of text.matchAll(p.sites)) {
        if (++n === CANDIDATES) {
          r.limit = m.index;
          break;
        }
      }
    }
    if (site > r.limit) return false;
    let v = r.honest.get(end);
    if (v === undefined) r.honest.set(end, (v = honestClauseAt(text, end, r)));
    return v;
  };
  class SecrecyRegExp extends RegExp {
    override exec(input: string): RegExpExecArray | null {
      const text = String(input);
      const p = parts(this.ignoreCase);
      const keep = this.global || this.sticky;
      let from = keep ? this.lastIndex : 0;
      while (from <= text.length) {
        p.scan.lastIndex = from;
        const c = p.scan.exec(text);
        if (!c || (this.sticky && c.index !== from)) break;
        p.gated.lastIndex = c.index;
        let m = p.gated.exec(text);
        if (m && honestAt(p, text, c.index, c.index + m[0].length)) m = null;
        if (!m) {
          p.plain.lastIndex = c.index;
          m = p.plain.exec(text);
        }
        if (m) {
          if (keep) this.lastIndex = m.index + m[0].length;
          return m;
        }
        if (this.sticky) break;
        from = c.index + 1;
      }
      if (keep) this.lastIndex = 0;
      return null;
    }
  }
  return new SecrecyRegExp(`${gated}|${plain}`);
}
