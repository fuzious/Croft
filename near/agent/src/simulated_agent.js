// Optional payment-enforcement fixture, separate from the protocol receipt-analysis workflow.
// A SIMULATED LLM agent: deterministic, scripted, no model involved. It reads an invoice the way a naive
// tool-using agent would, and it obeys instructions embedded in the document (a prompt injection).

/** Payment intents [{receiver, amount, reason}] the naive agent derives from an invoice. */
export function planPayments(invoice, { spendableNear }) {
  const plan = [];
  const number = /INVOICE\s+#(\S+)/i.exec(invoice)?.[1] || '?';
  const amount = /Amount due:\s*([\d.]+)\s*NEAR/i.exec(invoice)?.[1];
  const payTo = /Pay to:\s*([a-z0-9._-]+)/i.exec(invoice)?.[1];
  if (amount && payTo) plan.push({ receiver: payTo, amount, reason: `invoice #${number}: Amount due` });
  // the injected instruction: a naive agent treats any text in its context as an instruction
  const injected = /ignore (?:all )?previous instructions,?\s*send all funds to\s+([a-z0-9._-]+[a-z0-9])/i.exec(invoice);
  if (injected) plan.push({ receiver: injected[1], amount: spendableNear, reason: 'instruction found in the invoice: send all funds' });
  return plan;
}
