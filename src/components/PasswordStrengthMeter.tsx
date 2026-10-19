import React from 'react';
import { cn } from '../lib/utils';
import { evaluatePasswordStrength } from '../lib/password';

export interface PasswordStrengthMeterProps {
  password: string;
  className?: string;
}

export const PasswordStrengthMeter: React.FC<PasswordStrengthMeterProps> = ({
  password,
  className,
}) => {
  const strength = evaluatePasswordStrength(password);

  const getBarColor = (index: number) => {
    if (index >= strength.score) return 'bg-muted';
    switch (strength.level) {
      case 'weak':
        return 'bg-destructive';
      case 'fair':
        return 'bg-amber-500';
      case 'good':
        return 'bg-blue-500';
      case 'strong':
        return 'bg-emerald-500';
      default:
        return 'bg-muted';
    }
  };

  const getLabelColor = () => {
    switch (strength.level) {
      case 'weak':
        return 'text-destructive';
      case 'fair':
        return 'text-amber-500';
      case 'good':
        return 'text-blue-500';
      case 'strong':
        return 'text-emerald-500';
    }
  };

  if (!password) return null;

  return (
    <div className={cn('space-y-1.5', className)}>
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground font-medium">Strength:</span>
        <span className={cn('font-semibold capitalize', getLabelColor())}>
          {strength.level}
        </span>
      </div>
      <div className="grid grid-cols-4 gap-1.5 h-1.5">
        {[0, 1, 2, 3].map((idx) => (
          <div
            key={idx}
            className={cn('rounded-full transition-all duration-300', getBarColor(idx))}
          />
        ))}
      </div>
      <p className="text-[11px] text-muted-foreground/80">{strength.feedback}</p>
    </div>
  );
};
