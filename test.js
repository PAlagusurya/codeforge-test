import * as fs from 'fs';
import * as child_process from 'child_process';

// hardcoded secrets — security worker should catch this
const API_KEY = "sk-prod-abc123secretkey";
const DB_PASSWORD = "admin123";

// no authorization check — security worker
export function deleteUser(userId: string) {
  const query = `DELETE FROM users WHERE id = '${userId}'`;  // SQL injection
  db.execute(query);
}

// overly complex function — complexity worker
export function processPayment(
  userId: string,
  amount: number,
  currency: string,
  method: string,
  coupon: string,
  isSubscription: boolean,
) {
  if (method === 'card') {
    if (currency === 'USD') {
      if (amount > 1000) {
        if (isSubscription) {
          if (coupon) {
            if (coupon === 'DISCOUNT50') {
              amount = amount * 0.5;
              if (amount < 10) {
                return null;
              }
            }
          }
        }
      }
    }
  } else if (method === 'paypal') {
    if (currency === 'EUR') {
      if (amount > 500) {
        return processPaypal(userId, amount);
      }
    }
  } else if (method === 'crypto') {
    const cmd = `crypto-cli send ${userId} ${amount}`;
    child_process.exec(cmd);  // command injection — security worker
  }
}

// no tests for this — test gaps worker
export function calculateTax(amount: number, country: string): number {
  const TAX_RATES: Record<string, number> = {
    US: 0.1,
    UK: 0.2,
    IN: 0.18,
  };
  return amount * (TAX_RATES[country] ?? 0.15);
}

// changed function signature — breaking worker
// was: export function refundPayment(paymentId: string)
export function refundPayment(paymentId: string, reason: string, approvedBy: string) {
  // reason and approvedBy are new required params — breaks existing callers
  fs.writeFileSync('/tmp/refund.log', `${paymentId} ${reason}`);  // path traversal
}

// removed export — breaking worker
// this function was previously exported and used by other services
function validateCard(cardNumber: string) {
  return cardNumber.length === 16;
}
