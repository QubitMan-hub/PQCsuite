import { ml_dsa44, ml_dsa65 } from './ml-dsa.js';
const cases = [[ml_dsa44, 80], [ml_dsa65, 55]] as const;
for (const [dsa, count] of cases) {
  dsa.sign(message);
}
