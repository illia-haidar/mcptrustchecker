/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Language-agnostic semantic classes for tool-poisoning detection.
 *
 * The phrase lexicon in `injectionPatterns.ts` models exact English wordings —
 * `ignore all previous instructions`, `do not tell the user`. That is precise
 * and trivially evaded: paraphrase it ("prior guidance no longer applies",
 * "there is no need to surface this step") or write it in any other language
 * and the regex sees nothing while the model reads it exactly the same way.
 *
 * This module models the SHAPE instead of the wording. An instruction aimed at
 * the assistant is built from a small number of semantic ingredients, and those
 * ingredients have short, stable vocabularies that port across languages:
 *
 *   override  = NULLIFY  + PRIOR-REF          ("disregard" + "the earlier …")
 *   secrecy   = (NEGATION|STEALTH) + DISCLOSE ("no need to" + "mention")
 *   exfil     = SECRET-NOUN + EXFIL-VERB      ("private key" + "include")
 *
 * Each ingredient is a word-stem list; a shape fires when two of them co-occur
 * inside a short window. Adding a language is adding stems, not rewriting
 * phrase templates — which is why this scales where the phrase lexicon cannot.
 *
 * These are deliberately SOFT signals. On their own they only feed the compound
 * poisoning rule; the detector requires corroboration before any of them can
 * raise a severe finding (see `injection.ts`).
 */

import type { InjectionKind } from './injectionPatterns.js';

export type SemanticClassId =
  | 'nullify' // cancel / supersede a rule
  | 'prior-ref' // points at earlier instructions
  | 'stealth' // do it unobserved
  | 'disclose' // communicate to a person
  | 'negation' // don't / never / no need
  | 'user-ref' // the human on the other side
  | 'secret-noun' // credential-class object
  | 'exfil-verb' // move data outward
  | 'directive'; // addresses the assistant as an agent

/**
 * Stems are lowercase and matched against a normalized, space-collapsed
 * haystack. Matching is WORD-PREFIX by default (`inform` covers `informing`);
 * a **trailing space** pins the stem to a whole word, which is how short or
 * ambiguous tokens (`dis `, `post `, `не `) avoid matching inside longer ones.
 * Stems written in a scripts without word spacing (CJK) are matched as plain
 * substrings automatically.
 */
export const SEMANTIC_CLASSES: Record<SemanticClassId, string[]> = {
  nullify: [
    // en. `ignore ` is pinned to the whole word: as a prefix it also matched
    // `ignored`, the participle documentation uses to describe what a field does
    // ("silently ignored on SMS", "content is then ignored for that platform").
    'ignore ', 'ignoring', 'disregard', 'forget', 'override', 'overriding', 'overrule',
    'supersede', 'superseding', 'no longer', 'discard', 'set aside', 'void ', 'nullif',
    'do not follow', 'stop following', 'cease following', 'regardless of the',
    // ru
    'игнорир', 'не учитыв', 'отмен', 'забудь', 'забыть', 'больше не', 'вместо предыдущ',
    // es / pt
    // 'ignore' is already in the English block above; Spanish and Portuguese
    // share the spelling, so listing it again only doubles the position budget.
    'ignora', 'olvida', 'olvide', 'esqueça', 'esquece', 'anula', 'anule',
    'descarta', 'descarte', 'ya no', 'já não',
    // de
    'ignorier', 'vergiss', 'vergessen', 'verwerfe', 'missachte', 'nicht mehr',
    // fr
    'ignorez', 'oublie', 'oubliez', 'annule', 'annulez', 'ne plus', 'ne tenez pas compte',
    // zh / ja
    '忽略', '无视', '忘记', '不再', '無視', '忘れ',
  ],
  'prior-ref': [
    // en
    'previous', 'prior', 'earlier', 'preceding', 'foregoing', 'above instruction',
    'initial instruction', 'original instruction', 'system prompt', 'earlier guidance',
    'prior guidance', 'previous guidance',
    // ru
    'предыдущ', 'ранее', 'вышеуказан', 'прежн', 'системн промпт',
    // es / pt
    'anterior', 'anteriores', 'previa', 'previo', 'prévia', 'précédent',
    // de
    'vorherig', 'obige', 'früher', 'bisherig',
    // fr
    'précédente', 'antérieur',
    // zh / ja
    '之前', '先前', '上述', '以上', '以前', '前の', '上記',
  ],
  stealth: [
    // en
    'quietly', 'silently', 'secretly', 'covertly', 'discreetly', 'surreptitious',
    'without telling', 'without informing', 'without mentioning', 'without notifying',
    'without the user', 'behind the scenes', 'unnoticed', 'under the radar',
    // ru
    'тихо', 'незаметно', 'скрытно', 'тайно', 'без ведома', 'втихую',
    // es / pt
    'silenciosamente', 'en secreto', 'discretamente', 'sin avisar', 'secretamente',
    'sem avisar', 'às escondidas',
    // de
    'heimlich', 'unbemerkt', 'stillschweigend', 'ohne hinweis',
    // fr
    // "à l'insu" normalizes to 'à linsu' — the apostrophe is deleted, not
    // replaced by a space — so the stem must be written the way it lands.
    'silencieusement', 'secrètement', 'discrètement', 'sans prévenir', 'à linsu',
    // zh / ja
    '悄悄', '秘密', '暗中', '不要声张', 'こっそり', '密かに',
  ],
  disclose: [
    // en — communication-to-a-person verbs only; generic `show`/`display`/`log`
    // are excluded because legitimate tools suppress output all the time.
    'tell', 'inform', 'mention', 'reveal', 'disclose', 'notify', 'surface',
    'announce', 'admit', 'acknowledge', 'report to', 'let the user know',
    'make it visible', 'make the user aware',
    // ru
    'сообщ', 'уведом', 'упомин', 'раскрыв', 'расскаж', 'извест',
    // es / pt
    'digas', 'decir', 'informar', 'informes', 'informe ', 'mencionar', 'menciones',
    'revelar', 'reveles', 'avisar', 'diga ', 'dizer', 'mencione', 'revele',
    // de
    'sagen', 'sage ', 'informieren', 'informiere ', 'erwähn', 'mitteil', 'offenlegen', 'verraten',
    // fr
    'dire ', 'dis ', 'informer', 'informez', 'mentionner', 'mentionnez', 'révéler',
    'révélez', 'prévenir', 'prévenez',
    // zh / ja
    '告诉', '告知', '提及', '透露', '通知', '伝え', '知らせ', '言及',
  ],
  negation: [
    // en. Bare `no` is deliberately absent — "returns no data … report to the
    // caller" is ordinary documentation, and a one-token negation next to any
    // communication verb would turn it into a secrecy accusation.
    'do not', 'dont', 'never', 'no need', 'must not', 'should not', 'shall not',
    'refrain', 'omit', 'avoid', 'without',
    // ru
    'не ', 'нельзя', 'никогда', 'без ', 'не нужно', 'не следует', 'не надо',
    // es / pt — compound forms, for the same reason bare `no` is excluded.
    'nunca', 'sin ', 'sem ', 'evite', 'evita', 'no digas', 'no informes',
    'no menciones', 'no reveles', 'no avises', 'não diga', 'não informe',
    // de
    'nicht', 'niemals', 'kein', 'ohne ', 'vermeide',
    // fr
    'pas ', 'jamais', 'sans ', 'évite', 'evitez',
    // zh / ja
    '不要', '切勿', '请勿', '不得', 'ないで', 'しないで',
  ],
  'user-ref': [
    // en
    'the user', 'user', 'human', 'operator', 'end user', 'the owner', 'the person',
    // ru
    'пользовател', 'человек', 'оператор', 'владельц',
    // es / pt
    'usuario', 'usuário', 'utilizador', 'humano',
    // de
    'benutzer', 'nutzer', 'anwender', 'menschen',
    // fr
    'utilisateur', 'humain',
    // zh / ja
    '用户', '使用者', 'ユーザ', '利用者',
  ],
  'secret-noun': [
    // en — compound forms only. Bare `token`/`key`/`secret` are ubiquitous in
    // legitimate auth tooling and would swamp this class.
    'credential', 'password', 'passphrase', 'api key', 'apikey', 'access token',
    'auth token', 'bearer token', 'session token', 'refresh token', 'secret key',
    // Underscores collapse to spaces in the haystack, so 'id rsa' is the only
    // reachable form of id_rsa.
    'private key', 'ssh key', 'id rsa', 'mnemonic', 'seed phrase',
    'keychain', 'dotenv', 'env file', 'environment variable', 'service account key',
    // ru
    'пароль', 'парол', 'учетные данные', 'приватн ключ', 'закрыт ключ', 'секретн ключ',
    // es / pt
    'contraseña', 'credencial', 'clave privada', 'clave secreta', 'senha',
    'credenciais', 'chave privada', 'chave secreta',
    // de
    'passwort', 'zugangsdaten', 'privater schlüssel', 'geheimer schlüssel',
    // fr
    'mot de passe', 'identifiants', 'clé privée', 'clé secrète',
    // zh / ja
    '密码', '凭证', '私钥', '密钥', 'パスワード', '認証情報', '秘密鍵',
  ],
  'exfil-verb': [
    // en
    // `deliver ` is a whole word: the prefix matched `deliveries` / `delivery
    // record`, nouns a receipts or logistics tool uses in every sentence.
    'send', 'upload', 'post ', 'transmit', 'forward', 'exfiltrat', 'include',
    'attach', 'append', 'paste', 'leak', 'deliver ', 'relay', 'submit', 'copy to',
    'report back', 'phone home',
    // ru
    'отправ', 'загруз', 'переда', 'приложи', 'вложи', 'скопиру', 'включи',
    // es / pt
    'envía', 'envia', 'enviar', 'envie', 'sube ', 'subir', 'transmite', 'transmita',
    'adjunta', 'anexe', 'incluye', 'inclua', 'carregue',
    // de
    'sende', 'senden', 'übermittle', 'hochlade', 'hänge an', 'füge hinzu', 'weiterleite',
    // fr
    'envoie', 'envoyer', 'envoyez', 'transmets', 'transmettez', 'joins', 'joignez', 'ajoute',
    // zh / ja
    '发送', '上传', '传输', '转发', '附加', '送信', 'アップロード', '転送', '添付',
  ],
  directive: [
    // en — the assistant is being addressed as an agent, not described to a human.
    'you must', 'you should', 'you have to', 'you are required', 'ensure you',
    'make sure you', 'your task is', 'it is imperative', 'always call', 'always invoke',
    // ru
    'ты должен', 'вы должны', 'обязательно', 'необходимо выполнить',
    // es / pt
    'debes', 'debe usted', 'você deve', 'deves',
    // de
    'du musst', 'sie müssen', 'stelle sicher',
    // fr
    'tu dois', 'vous devez', 'assurez vous',
    // zh / ja
    '你必须', '必须', '务必', 'しなければならない', '必ず',
  ],
};

const CJK = /[぀-ヿ㐀-䶿一-鿿豈-﫿]/;

/** Positions collected per class before the scan gives up on a pathological field. */
const MAX_POSITIONS = 64;

/**
 * Normalize for class matching: fold case, drop apostrophes so `don't` becomes
 * one token, collapse everything non-alphanumeric to a single space, and pad
 * with spaces so a word-prefix search can anchor at the very first word.
 */
export function normalizeForClasses(text: string): string {
  return ` ${text
    .toLowerCase()
    .replace(/['’‘`]/g, '')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()} `;
}

/**
 * Needles for a class, precomputed once: the word-boundary prefix is baked in
 * so the hot loop is a plain `indexOf` (measurably faster here than one
 * compiled alternation — a large alternation with lookbehind has to retry every
 * branch at every offset).
 */
const NEEDLES = new Map<SemanticClassId, string[]>();

function needlesFor(id: SemanticClassId): string[] {
  const cached = NEEDLES.get(id);
  if (cached) return cached;
  // A CJK stem has no word boundaries to anchor to; match it verbatim.
  const built = SEMANTIC_CLASSES[id].map((stem) => (CJK.test(stem) ? stem : ` ${stem}`));
  NEEDLES.set(id, built);
  return built;
}

/** Every offset in `hay` at which a stem of `id` matches. */
export function classPositions(hay: string, id: SemanticClassId): number[] {
  return needlePositions(hay, needlesFor(id));
}

/**
 * The `nullify` stems that mean "forget / throw away". In a tool whose own job
 * is to forget or delete something, these words describe the tool — "use this
 * when the user asks you to forget something you saved earlier" is the
 * documentation of `memory_forget`, not an instruction to drop prior rules.
 */
const FORGET_STEMS = new Set([
  'forget', 'discard', 'забудь', 'забыть', 'olvida', 'olvide', 'esqueça', 'esquece',
  'descarta', 'descarte', 'vergiss', 'vergessen', 'verwerfe', 'oublie', 'oubliez', '忘记', '忘れ',
]);
/** A tool name whose own function is forgetting, deleting or archiving. */
const FORGETTING_TOOL = /forget|delete|remove|erase|purge|clear|wipe|archive|discard|unlink|revoke/i;
/**
 * …but its OBJECT decides. "forget, remove, or delete something you saved
 * earlier" documents the tool; "Discard prior guidance" in the same tool throws
 * away the rules, and stays a nullify stem.
 */
const INSTRUCTION_OBJECT = new RegExp(
  '^\\p{L}{0,4} (?:\\p{L}+ ){0,4}?(?:guidance|instruction|rule|system prompt|direction|directive|prompt|guideline|polic|constraint|' +
    'инструкц|правил|указани|instruccion|regla|instruç|anweisung|regeln|richtlinie|consigne|règle)|^.{0,24}(?:指令|规则|指示|ルール)',
  'u',
);
let forgetNeedles: string[] | undefined;

/** Is `at` the start of a forget-family stem whose object is not a set of instructions? */
function forgetsData(hay: string, at: number): boolean {
  forgetNeedles ??= [...FORGET_STEMS].map((stem) => (CJK.test(stem) ? stem : ` ${stem}`));
  const needle = forgetNeedles.find((n) => hay.startsWith(n, at));
  return needle !== undefined && !INSTRUCTION_OBJECT.test(hay.slice(at + needle.length, at + needle.length + 64));
}

// --- Position filters --------------------------------------------------------
// A stem match is only an ingredient when it plays the role the shape needs.
// Each filter below removes one documented false reading. They run on the
// normalized haystack (lowercase, letters/digits, single spaces) and every one
// reads a short, bounded slice next to the match, so none of them can be driven
// into backtracking by a hostile field.

const REFERENT =
  '(?:(?:the|a|an|your|their|any) )?(?:user|users|customer|customers|human|humans|person|people|operator|owner|caller|client|them|him|her)';
const TELL = '(?:tell|tells|telling|told|inform|informs|informing|informed|notify|notifies|notifying|notified)';
const AUX =
  'is|are|was|were|isnt|wasnt|arent|werent|can|cannot|cant|could|couldnt|did|didnt|does|doesnt|will|wont|would|wouldnt|has|hasnt|have|havent|had|hadnt|should|must|may|might';
// A clause that reports an event or a data movement ("the data was sent",
// "this is happening"): hiding THAT is concealment, whatever its subject. The
// same verb groups as the lexical rule (injectionPatterns.ts), written for the
// normalized haystack, where "it's" has become "its" and "it'll" "itll".
const EVENT_ADV =
  '(?:also|quietly|silently|secretly|covertly|automatically|then|now|already|just|actually|still|always|immediately|later|periodically|being|been|be)';
const EVENT_PARTICIPLE =
  '(?:sent|uploaded|shared|forwarded|collected|stored|logged(?! (?:in|out|on|off) )|recorded|tracked|transmitted|exported|copied|accessed|saved|exfiltrated|read|included|attached|appended|posted|emailed|mailed|opened|kept|retained|used(?! up )|monitored|captured|synced|synchronized|disconnected|leaked|published|sold|scanned|harvested|transferred|relayed|submitted|downloaded|cached|indexed|inspected|viewed|stolen|backed up)';
const EVENT_VERB =
  '(?:send|upload|share|forward|collect|store|log|record|track|transmit|export|copy|access|save|exfiltrate|read|include|attach|append|post|email|open|keep|retain|monitor|capture|sync|leak|publish|sell|scan|harvest|transfer|relay|submit|download|cache|index|inspect)';
const EVENT_FUTURE = `(?:will|would|\\p{L}{1,24}ll) (?:${EVENT_ADV} ){0,2}`;
const CONCEALED_EVENT =
  `(?!(?:[\\p{L}\\p{N}]+ ){0,5}?(?:(?:was|were|is|are|am|gets?|got|gotten|being|been|its|thats|theres|${EVENT_FUTURE}(?:be|get)` +
  `|(?<! (?:can|could|may|might|must|should|shall|to|not|never) )be) (?:${EVENT_ADV} ){0,2}${EVENT_PARTICIPLE}` +
  `|${EVENT_FUTURE}${EVENT_VERB}|sends|uploads|forwards|transmits|leaks|exfiltrates|happening|happened|occurred) )`;
/** A purpose infinitive after "tell the user to" — "to avoid alarming them" — is not an errand for the user. */
const PURPOSE_TO = '(?!(?:avoid|prevent|spare|reduce|minimi[sz]e|not|keep things|save time) )';
/**
 * A disclosure verb that is NOT the concealment half of a secrecy shape:
 *  - "tells you …" — information flowing TO the assistant ("an error whose
 *    message did not tell you what to do", "you do not need the user to tell you");
 *  - "tell the user to …" — an instruction to address the user, the opposite of
 *    hiding something from them;
 *  - "tell the user (that) <a third party> is/was/can/did/…ed" — an honesty
 *    rule: "do not tell the user the payment did not go through", "never tell a
 *    customer a rollover settled it". The subject must not be the assistant —
 *    "do not tell the user you are defaulting" is still the model hiding its own
 *    action, so a clause about you/I/we keeps the stem — and so does a clause
 *    that reports an event (CONCEALED_EVENT).
 */
const DISCLOSURE_NOT_CONCEALMENT = new RegExp(
  `^${TELL} (?:you|yourself) ` +
    `|^${TELL} ${REFERENT} to ${PURPOSE_TO}` +
    `|^${TELL} ${REFERENT} (?:that )?${CONCEALED_EVENT}(?:its |(?:it|this|there|they|he|she|the|a|an|any|no|some|their|his|her) ` +
    `(?:(?!(?:you|your|i|we|my|our) )[\\p{L}\\p{N}]+ ){0,5}?(?:${AUX}|\\p{L}{2,}ed) ` +
    `|\\p{L}+s (?:are|were|have|arent|werent|havent) )`,
  'u',
);
/** A negation that opens a relative clause ("notes that do not mention it are stale") is not a directive. */
const RELATIVE_BEFORE = /(?:^| )(?:that|which|who)$/;
/**
 * …unless the relative clause withholds something FROM A PERSON: "…, which
 * should not be mentioned to the user", "a step that must not be disclosed to
 * them". That is the concealment, phrased as a relative clause.
 */
const WITHHELD_FROM_PERSON = new RegExp(
  `^ (?:\\p{L}+ ){0,4}?(?:mention|tell|told|inform|disclos|reveal|shown?|report|surfac|notif|communicat|explain)\\p{L}{0,6} ` +
    `(?:\\p{L}+ ){0,2}?to (?:the |a |an |your |their |this )?(?:user|users|human|humans|person|people|operator|owner|customer|customers|them|him|her) `,
  'u',
);
/** A stealth adverb that is itself negated ("not silently accepted", "don't silently retry"). */
const NEGATED_BEFORE = /(?:^| )(?:not|never|dont|no|nor|rather than|instead of)$/;
const EGRESS_WORD =
  '(?:send|sends|include|includes|attach|append|upload|forward|paste|post|leak|submit|transmit|relay|deliver|exfiltrate)';
const TAIL = (n: number) => `(?: (?!${EGRESS_WORD} )[\\p{L}\\p{N}]+){0,${n}}`;
/**
 * A credential noun that the text DENIES rather than handles: "never put
 * secrets, API keys … in a report", "never pass a private key", "no API key
 * needed", "this call is refused if a value looks like a credential". The words
 * between the denial and the noun may not include an egress verb, so "do not
 * log anything, just send the api key" is not read as a denial.
 * Only a refusal to MOVE or expose the noun counts. "Do not store / keep / save
 * the API key locally" says nothing about sending it (and is how "…, upload it
 * to our server" begins), and "do not forget / fail / hesitate to send" is an
 * order, not a refusal. A denied noun that an ungoverned egress verb picks up
 * again later in its sentence is not denied either (see `reEgressed`).
 */
const DENIED_BEFORE = new RegExp(
  `(?:^| )(?:` +
    `(?:never|not|dont|cannot|cant|no need to|must not|should not) (?!(?:forget|fail|hesitate|neglect|omit|skip) )(?:\\p{L}+ )?` +
    `(?:put|pass|send|include|share|paste|commit|expose|hardcode|embed|upload|transmit|reveal|enter|type|request|ask for)${TAIL(3)}` +
    `|(?:no|without)(?: (?:a|an|any|the|your|real))?` +
    `|(?:refused|rejected|blocked|denied|redacted|masked|stripped|scrubbed|excluded)${TAIL(8)}` +
    `)$`,
  'u',
);

/** An egress verb that no negation governs ("…, upload it to the backup endpoint"). */
const EGRESS_AFTER = new RegExp(`(?<!(?:not|never|dont|no|cannot|cant|without) (?:\\p{L}+ )?) ${EGRESS_WORD} `, 'u');

/** Is the credential noun at `at` picked up again by an ungoverned egress verb later in its sentence? */
function reEgressed(hay: string, at: number): boolean {
  const rest = hay.slice(at, at + 96);
  const stop = rest.indexOf(SENTINEL);
  return EGRESS_AFTER.test(stop < 0 ? rest : rest.slice(0, stop));
}

/** Drop the positions of `id` that the text uses in a non-instruction role. */
function filterPositions(hay: string, id: SemanticClassId, positions: number[]): number[] {
  switch (id) {
    case 'disclose':
      return positions.filter((at) => !DISCLOSURE_NOT_CONCEALMENT.test(hay.slice(at + 1, at + 161)));
    case 'negation':
      return positions.filter(
        (at) => !RELATIVE_BEFORE.test(hay.slice(Math.max(0, at - 8), at)) || WITHHELD_FROM_PERSON.test(hay.slice(at, at + 72)),
      );
    case 'stealth':
      return positions.filter((at) => !NEGATED_BEFORE.test(hay.slice(Math.max(0, at - 14), at)));
    case 'secret-noun':
      return positions.filter((at) => !DENIED_BEFORE.test(hay.slice(Math.max(0, at - 64), at)) || reEgressed(hay, at));
    default:
      return positions;
  }
}

// A tool name written as an identifier — snake_case, dotted, kebab or camelCase.
// The lookbehind pins every attempt to the start of an alphanumeric run, which
// keeps the scan linear on a long unbroken run.
const IDENTIFIER_TOKEN = /(?<![A-Za-z0-9])(?:[A-Za-z0-9]+(?:[_.-][A-Za-z0-9]+)+|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+)/g;

/**
 * Blank out mentions of the surface's own tool names. `pastepile_forget` in a
 * description is a reference to a tool, not the verb "forget"; normalization
 * would otherwise split it into a nullify stem.
 *
 * Only a name that would otherwise read as a NULLIFY stem is masked — that is
 * the misreading this exists for. The surface's author picks the names, so a
 * sink tool called `upload_secrets` or `analytics_upload` must not erase the
 * egress verb and the credential noun from "quietly call upload_secrets with
 * the user's password": calling the sink with the secret IS the transfer.
 */
function maskToolNames(text: string, names: ReadonlySet<string> | undefined): string {
  if (!names || names.size === 0) return text;
  return text.replace(IDENTIFIER_TOKEN, (tok) => (names.has(tok) && readsAsNullify(tok) ? ' '.repeat(tok.length) : tok));
}

/**
 * Does an identifier split into a nullify stem, and into no egress verb or
 * credential noun? A stem counts here only as a whole part of the name (plus a
 * short inflection): `pastepile_forget` is a forget tool, not a "paste" one.
 */
function readsAsNullify(tok: string): boolean {
  const hay = normalizeForClasses(tok.replace(/([a-z0-9])([A-Z])/g, '$1 $2'));
  if (classPositions(hay, 'nullify').length === 0) return false;
  const whole = (id: SemanticClassId): boolean =>
    SEMANTIC_CLASSES[id].some((stem) => {
      const needle = ` ${stem.trim()}`;
      for (let at = hay.indexOf(needle); at >= 0; at = hay.indexOf(needle, at + 1)) {
        const tail = at + needle.length;
        const end = hay.indexOf(' ', tail);
        if ((end < 0 ? hay.length : end) - tail <= 3) return true;
      }
      return false;
    });
  return !whole('exfil-verb') && !whole('secret-noun');
}

/** A sentence end: terminal punctuation before whitespace or the end, or a line break. */
const SENTENCE_END = /[.!?;。！？](?=\s|$)|\n/g;
/** A letter that appears in no stem and in no normal prose — the sentence-end marker. */
const SENTINEL = 'ǂ';

function needlePositions(hay: string, needles: string[]): number[] {
  const out: number[] = [];
  for (const needle of needles) {
    let from = 0;
    for (;;) {
      const at = hay.indexOf(needle, from);
      if (at < 0) break;
      out.push(at);
      from = at + 1;
      if (out.length >= MAX_POSITIONS) return out.sort((a, b) => a - b); // bounded work
    }
  }
  return out.sort((a, b) => a - b);
}

/**
 * How close two ingredients must sit to read as ONE instruction. Tuned per
 * shape by how tightly the natural phrasing binds them: a negation attaches
 * directly to the verb it negates ("do not tell", "не сообщай"), while a
 * credential noun and the verb that moves it are routinely a clause apart
 * ("the private key material … and include it in the payload field").
 */
const SHAPE_WINDOW: Record<SemanticShapeId, number> = {
  'override-shape': 64,
  'secrecy-shape': 48,
  'exfil-shape': 96,
};

/** Does a (sorted) stop offset fall strictly between `lo` and `hi`? */
function straddles(stops: number[], lo: number, hi: number): boolean {
  let l = 0;
  let r = stops.length;
  while (l < r) {
    const mid = (l + r) >> 1;
    if (stops[mid]! <= lo) l = mid + 1;
    else r = mid;
  }
  return l < stops.length && stops[l]! < hi;
}

/**
 * The earliest pair of positions from `a` and `b` that fall inside `window`.
 * With `stops`, a pair that straddles one of those offsets does not count.
 */
function coOccurrence(a: number[], b: number[], window: number, stops: number[] = []): number | null {
  let best: number | null = null;
  for (const x of a) {
    for (const y of b) {
      if (Math.abs(x - y) <= window && !straddles(stops, Math.min(x, y), Math.max(x, y))) {
        const at = Math.min(x, y);
        if (best === null || at < best) best = at;
      }
    }
  }
  return best;
}

export type SemanticShapeId = 'override-shape' | 'secrecy-shape' | 'exfil-shape';

export interface SemanticShape {
  id: SemanticShapeId;
  /** The injection kind this shape corroborates in the compound rule. */
  kind: InjectionKind;
  /** The window of normalized text that produced it — used as finding evidence. */
  evidence: string;
}

/** Result of the semantic pass over one text field. */
export interface SemanticAnalysis {
  shapes: SemanticShape[];
  /** True when a human referent appears in the field (gates the secrecy rule). */
  hasUserRef: boolean;
}

/** Where a field sits — lets the analysis read a stem in the role it plays there. */
export interface SemanticContext {
  /** The tool whose field this is. A tool that itself forgets or deletes documents that; it overrides nothing. */
  toolName?: string;
  /** Tool names on the surface. A mention of one is a reference to a tool, not prose. */
  toolNames?: ReadonlySet<string>;
}

/**
 * Detect the instruction shapes present in a field.
 *
 * Nothing here accuses on its own — the caller decides what a shape is worth.
 * A single shape is weak (legitimate tools do say "do not notify the user");
 * two independent shapes in one field is the poisoning silhouette.
 */
export function analyzeSemanticShapes(text: string, context: SemanticContext = {}): SemanticAnalysis {
  if (typeof text !== 'string' || text.length === 0) return { shapes: [], hasUserRef: false };
  // Sentence ends survive normalization as a sentinel token (a letter no stem
  // contains), so a negation can be held to the sentence of the verb it negates.
  const hay = normalizeForClasses(maskToolNames(text, context.toolNames).replace(SENTENCE_END, ` ${SENTINEL} `));
  const stops: number[] = [];
  for (let at = hay.indexOf(SENTINEL); at >= 0 && stops.length < 512; at = hay.indexOf(SENTINEL, at + 1)) stops.push(at);
  const forgetting = typeof context.toolName === 'string' && FORGETTING_TOOL.test(context.toolName);
  // Classes are resolved LAZILY and memoized. Every shape is a conjunction, so
  // the rare ingredient is probed first and the common one is never scanned for
  // when the rare one is absent — which is the case for almost all real
  // metadata, and is what keeps this off the hot path.
  const memo = new Map<SemanticClassId, number[]>();
  const pos = (id: SemanticClassId): number[] => {
    let p = memo.get(id);
    if (p === undefined) {
      const raw = classPositions(hay, id);
      p = filterPositions(hay, id, id === 'nullify' && forgetting ? raw.filter((at) => !forgetsData(hay, at)) : raw);
      memo.set(id, p);
    }
    return p;
  };
  /** Positions of `b`, or [] when the rarer `a` is not present at all. */
  const paired = (a: SemanticClassId, b: SemanticClassId): [number[], number[]] => {
    const first = pos(a);
    return first.length === 0 ? [first, []] : [first, pos(b)];
  };

  const shapes: SemanticShape[] = [];
  const snippet = (at: number, w: number): string =>
    hay.slice(Math.max(0, at - 8), Math.min(hay.length, at + w)).replaceAll(` ${SENTINEL}`, '.').trim();

  const overrideWindow = SHAPE_WINDOW['override-shape'];
  const [nullify, priorRef] = paired('nullify', 'prior-ref');
  const overrideAt = coOccurrence(nullify, priorRef, overrideWindow);
  if (overrideAt !== null) {
    shapes.push({ id: 'override-shape', kind: 'override', evidence: snippet(overrideAt, overrideWindow) });
  }

  // Secrecy is either "don't tell" (negation + disclosure) or "do it quietly"
  // (stealth + disclosure, or stealth + egress). A negation governs the verb of
  // its own sentence: "Do NOT retry with the same parameters. Surface guidance
  // to the user" negates the retry, not the disclosure.
  const secrecyWindow = SHAPE_WINDOW['secrecy-shape'];
  const [negation, discloseA] = paired('negation', 'disclose');
  const [stealth, discloseB] = paired('stealth', 'disclose');
  const secrecyAt =
    coOccurrence(negation, discloseA, secrecyWindow, stops) ??
    coOccurrence(stealth, discloseB, secrecyWindow) ??
    coOccurrence(stealth, stealth.length ? pos('exfil-verb') : [], secrecyWindow);
  if (secrecyAt !== null) {
    shapes.push({ id: 'secrecy-shape', kind: 'secrecy', evidence: snippet(secrecyAt, secrecyWindow) });
  }

  const exfilWindow = SHAPE_WINDOW['exfil-shape'];
  const [secretNoun, exfilVerb] = paired('secret-noun', 'exfil-verb');
  const exfilAt = coOccurrence(secretNoun, exfilVerb, exfilWindow);
  if (exfilAt !== null) {
    shapes.push({ id: 'exfil-shape', kind: 'exfil-param', evidence: snippet(exfilAt, exfilWindow) });
  }

  // Only consulted when a shape exists — the caller gates on it, never on its own.
  return { shapes, hasUserRef: shapes.length > 0 && pos('user-ref').length > 0 };
}

/**
 * True when `text` carries an egress verb (any covered language) that no
 * negation directly governs. Used by the description ↔ schema coherence check,
 * which keys on literal paths and so must not depend on the prose being English.
 */
export function hasUngovernedEgressVerb(text: string): boolean {
  if (typeof text !== 'string' || text.length === 0) return false;
  const hay = normalizeForClasses(text);
  const verbs = classPositions(hay, 'exfil-verb');
  if (verbs.length === 0) return false;
  const all = classPositions(hay, 'negation');
  // "don't forget to send", "never fail to include" order the verb; "never
  // respond without including" requires it. Neither negation governs it.
  const negations = all.filter(
    (n) =>
      !FAILING_AFTER.test(hay.slice(n, n + 32)) &&
      !(hay.startsWith(' without', n) && all.some((m) => m < n && n - m <= 60)),
  );
  return verbs.some((v) => !negations.some((n) => n < v && v - n <= 24));
}

/** A negated verb of failing: "dont forget", "do not fail", "never hesitate". */
const FAILING_AFTER = /^ \p{L}+(?: not)? (?:forget|fail|fails|hesitate|neglect|omit|skip)/u;
