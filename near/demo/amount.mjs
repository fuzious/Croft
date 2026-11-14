// Keep the amount checked by the oracle identical to the user's decimal input.
export function decimalToYocto(value) {
  const match = typeof value === 'string' && /^(\d+)(?:\.(\d{1,24}))?$/.exec(value.trim());
  if (!match) throw new Error('Enter a non-negative NEAR amount with at most 24 decimal places.');
  const amount = BigInt(match[1]) * 10n ** 24n + BigInt((match[2] || '').padEnd(24, '0'));
  if (amount > 2n ** 128n - 1n) throw new Error('Amount exceeds the NEAR payment limit (u128).');
  return amount.toString();
}
