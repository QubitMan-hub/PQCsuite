import { createHash } from 'crypto';
import { DIGEST, GREETING as hi } from './settings';

export function checksum(data) {
  console.log(hi);
  return createHash(DIGEST).update(data).digest('hex');
}
