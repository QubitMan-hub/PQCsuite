import { ml_dsa44 } from './ml-dsa.js';
import { dsa as DSA } from 'classical-library';
const cases = [[ml_dsa44, 80]] as const;
cases.push([DSA, 1]);
for (const [dsa, count] of cases) {
  dsa.sign(message);
}
DSA.sign(message);
