/**
 * Cryptographic Binary Security Key Generator
 * Produces official DETOX binary security key tokens: SEC-BIN-<32-bit-binary>-<timestamp-base36>
 * Example: SEC-BIN-11010010101110000010011111010100-M1X8PQ9
 */

/**
 * Generates an official DETOX binary security key token.
 * Combines 4 randomized 8-bit octets (32 binary bits) and a high-resolution base36 timestamp.
 */
export function generateBinarySecurityToken(): string {
  const octets: string[] = [];
  for (let i = 0; i < 4; i++) {
    // 8-bit binary octet (00000000 to 11111111)
    const randomByte = Math.floor(Math.random() * 256);
    octets.push(randomByte.toString(2).padStart(8, '0'));
  }
  const binary32 = octets.join('');
  const timestampBase36 = Date.now().toString(36).toUpperCase();
  return `SEC-BIN-${binary32}-${timestampBase36}`;
}

/**
 * Validates whether a given string is a syntactically correct DETOX binary token.
 */
export function isValidBinarySecurityToken(token: string): boolean {
  if (typeof token !== 'string') return false;
  // Match SEC-BIN-[01]{32}-[0-9A-Z]+
  const regex = /^SEC-BIN-[01]{32}-[0-9A-Z]+$/;
  return regex.test(token);
}
