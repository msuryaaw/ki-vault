import type { PasswordStrength } from '../types/vault';

/**
 * Evaluates the strength of a master password on the client side.
 * Used exclusively for instant UX feedback without storing or exposing the value.
 */
export function evaluatePasswordStrength(password: string): PasswordStrength {
  if (!password) {
    return {
      level: 'weak',
      score: 0,
      feedback: 'Enter a master password.',
    };
  }

  let score = 0;

  if (password.length >= 10) score += 1;
  if (password.length >= 14) score += 1;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;

  if (password.length < 8) {
    return {
      level: 'weak',
      score: 1,
      feedback: 'Too short (minimum 8 characters recommended).',
    };
  }

  if (score <= 1) {
    return {
      level: 'weak',
      score: 1,
      feedback: 'Weak — combine uppercase, numbers, and symbols.',
    };
  }

  if (score === 2) {
    return {
      level: 'fair',
      score: 2,
      feedback: 'Fair — consider adding length and varied symbols.',
    };
  }

  if (score === 3) {
    return {
      level: 'good',
      score: 3,
      feedback: 'Good — strong enough for daily use.',
    };
  }

  return {
    level: 'strong',
    score: 4,
    feedback: 'Excellent — high-entropy master password.',
  };
}
