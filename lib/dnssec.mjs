/**
 * DNSSEC validation status for a DoH answer.
 *
 * VENDORED. The original is `research/gtld/dnssec.mjs` in the author's
 * published measurement repository `algo13-study`, where AD_STATUS and
 * adStatus were written for the gTLD census scripts. Only those two exports
 * are copied here. The census also needs MNEMONIC, toNum and keytag, which
 * this tool does not use.
 *
 * The copy is deliberate. A cross-repo dependency on a published corpus
 * would make this tool fail if that corpus moves, and the corpus must stay
 * frozen because it produced published figures.
 *
 * Behaviour is unchanged from the original.
 */

/** The three states an answer can be in, as far as validation goes. */
export const AD_STATUS = {
  VALIDATED:   'validated',    // the resolver set AD, so it checked the chain
  UNVALIDATED: 'unvalidated',  // records arrived, AD clear
  NO_ANSWER:   'no-answer',    // nothing to classify
};

/**
 * Classify a DoH JSON answer: validated, unvalidated, or no-answer.
 *
 * no-answer covers both an absent response (the query failed after its
 * retries) and a response that carries no records of the type asked for. An
 * unsigned zone reaches the second case legitimately, so the two are one
 * class here; the response Status is recorded separately and tells them apart.
 *
 * @param {object|null} j    parsed DoH JSON, or null if the query failed
 * @param {number} [type]    RR type to require, e.g. 16 for TXT. Omit to
 *                           accept any record in the answer section.
 */
export const adStatus = (j, type) => {
  if (!j || !Array.isArray(j.Answer)) return AD_STATUS.NO_ANSWER;
  const rr = type === undefined ? j.Answer : j.Answer.filter(a => a.type === type);
  if (!rr.length) return AD_STATUS.NO_ANSWER;
  return j.AD ? AD_STATUS.VALIDATED : AD_STATUS.UNVALIDATED;
};

/** TXT record type, for adStatus and answer filters. */
export const TYPE_TXT = 16;
