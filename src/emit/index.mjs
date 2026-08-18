import * as oscalAssessmentResults from './oscal/assessment-results.mjs';
import * as ocr from './fedramp-20x/ocr.mjs';
import * as scn from './fedramp-20x/scn.mjs';
import * as sdr from './fedramp-20x/sdr.mjs';

/**
 * The emitter interface, and the whole of the format-pluggability argument.
 *
 * Every emitter is `emit(state, options) -> document`. They share one input — the control state
 * built in ../evidence/state.mjs — and none of them can see the evidence locker, the collectors
 * or the ruleset directly. Adding a format means adding a projection, not another traversal.
 *
 * That constraint is what makes the format question a cheap one to be wrong about. FedRAMP 20x
 * consumes FedRAMP's own JSON schemas today; Rev5 will take OSCAL until 2027; a customer
 * questionnaire wants prose. All three are the same state seen from different angles, and none
 * of them is a thing anyone should be authoring by hand.
 */

export const EMITTERS = Object.freeze({
  sdr: { ...sdr, label: 'FedRAMP 20x Security Decision Record (KSI section)', validated: true },
  ocr: { ...ocr, label: 'FedRAMP 20x Ongoing Certification Report', validated: true },
  // The only emitter that takes an input besides the state, because a significant change is a
  // decision rather than an observation. See the header of fedramp-20x/scn.mjs.
  scn: { ...scn, label: 'FedRAMP 20x Significant Change Notification', validated: true, needsChange: true },
  'oscal-ar': {
    ...oscalAssessmentResults,
    label: 'OSCAL Assessment Results',
    validated: false,
  },
});

export function emitterFor(name) {
  const emitter = EMITTERS[name];
  if (!emitter) {
    throw new Error(`Unknown emitter "${name}". Available: ${Object.keys(EMITTERS).join(', ')}`);
  }
  return emitter;
}
