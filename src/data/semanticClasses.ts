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
    // en
    'ignore', 'ignoring', 'disregard', 'forget', 'override', 'overriding', 'overrule',
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
    'send', 'upload', 'post ', 'transmit', 'forward', 'exfiltrat', 'include',
    'attach', 'append', 'paste', 'leak', 'deliver', 'relay', 'submit', 'copy to',
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
  const out: number[] = [];
  for (const needle of needlesFor(id)) {
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

/** The earliest pair of positions from `a` and `b` that fall inside `window`. */
function coOccurrence(a: number[], b: number[], window: number): number | null {
  let best: number | null = null;
  for (const x of a) {
    for (const y of b) {
      if (Math.abs(x - y) <= window) {
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

/**
 * Detect the instruction shapes present in a field.
 *
 * Nothing here accuses on its own — the caller decides what a shape is worth.
 * A single shape is weak (legitimate tools do say "do not notify the user");
 * two independent shapes in one field is the poisoning silhouette.
 */
export function analyzeSemanticShapes(text: string): SemanticAnalysis {
  if (typeof text !== 'string' || text.length === 0) return { shapes: [], hasUserRef: false };
  const hay = normalizeForClasses(text);
  // Classes are resolved LAZILY and memoized. Every shape is a conjunction, so
  // the rare ingredient is probed first and the common one is never scanned for
  // when the rare one is absent — which is the case for almost all real
  // metadata, and is what keeps this off the hot path.
  const memo = new Map<SemanticClassId, number[]>();
  const pos = (id: SemanticClassId): number[] => {
    let p = memo.get(id);
    if (p === undefined) {
      p = classPositions(hay, id);
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
    hay.slice(Math.max(0, at - 8), Math.min(hay.length, at + w)).trim();

  const overrideWindow = SHAPE_WINDOW['override-shape'];
  const [nullify, priorRef] = paired('nullify', 'prior-ref');
  const overrideAt = coOccurrence(nullify, priorRef, overrideWindow);
  if (overrideAt !== null) {
    shapes.push({ id: 'override-shape', kind: 'override', evidence: snippet(overrideAt, overrideWindow) });
  }

  // Secrecy is either "don't tell" (negation + disclosure) or "do it quietly"
  // (stealth + disclosure, or stealth + egress).
  const secrecyWindow = SHAPE_WINDOW['secrecy-shape'];
  const [negation, discloseA] = paired('negation', 'disclose');
  const [stealth, discloseB] = paired('stealth', 'disclose');
  const secrecyAt =
    coOccurrence(negation, discloseA, secrecyWindow) ??
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
