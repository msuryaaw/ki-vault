import React from 'react';
import { cn } from '../lib/utils';
import { AlertCircle, CheckCircle2, X } from 'lucide-react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  exampleText?: string;
  prefixIcon?: React.ReactNode;
  suffixIcon?: React.ReactNode;
  isValid?: boolean;
  onClear?: () => void;
  showCharCount?: boolean;
  maxLength?: number;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      label,
      error,
      helperText,
      exampleText,
      prefixIcon,
      suffixIcon,
      isValid = false,
      onClear,
      showCharCount = false,
      maxLength,
      type = 'text',
      id,
      value,
      ...props
    },
    ref
  ) => {
    const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);
    const currentLength = typeof value === 'string' ? value.length : 0;
    const hasValue = typeof value === 'string' && value.length > 0;

    return (
      <div className="w-full space-y-1.5 text-left">
        <div className="flex items-center justify-between">
          {label && (
            <label
              htmlFor={inputId}
              className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider"
            >
              {label}
            </label>
          )}
          {showCharCount && maxLength && (
            <span
              className={cn(
                'text-[10px] font-mono',
                currentLength >= maxLength
                  ? 'text-destructive font-bold'
                  : 'text-muted-foreground/70'
              )}
            >
              {currentLength} / {maxLength}
            </span>
          )}
        </div>

        <div className="relative flex items-center">
          {prefixIcon && (
            <div className="absolute left-3 flex items-center pointer-events-none text-muted-foreground">
              {prefixIcon}
            </div>
          )}

          <input
            id={inputId}
            type={type}
            ref={ref}
            value={value}
            maxLength={maxLength}
            className={cn(
              'flex h-10 w-full rounded-lg border border-border bg-input/40 px-3 py-2 text-sm text-foreground shadow-sm placeholder:text-muted-foreground/60 transition-colors focus:border-primary/50 focus:bg-input/60 focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
              prefixIcon && 'pl-9',
              (suffixIcon || onClear || isValid || error) && 'pr-9',
              error && 'border-destructive/80 bg-destructive/5 text-destructive focus:ring-destructive focus:border-destructive',
              !error && isValid && 'border-emerald-500/80 bg-emerald-500/5 focus:ring-emerald-500 focus:border-emerald-500',
              className
            )}
            {...props}
          />

          {/* Suffix / Action icon */}
          <div className="absolute right-2.5 flex items-center gap-1">
            {onClear && hasValue && !props.disabled && (
              <button
                type="button"
                onClick={onClear}
                className="p-1 text-muted-foreground hover:text-foreground rounded transition-colors"
                aria-label="Clear input"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
            {error ? (
              <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
            ) : isValid ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
            ) : suffixIcon ? (
              <div className="text-muted-foreground">{suffixIcon}</div>
            ) : null}
          </div>
        </div>

        {error ? (
          <div className="space-y-0.5">
            <p className="text-xs text-destructive font-medium flex items-center gap-1">
              <span>{error}</span>
            </p>
            {exampleText && (
              <p className="text-[11px] text-muted-foreground">{exampleText}</p>
            )}
          </div>
        ) : (
          <div className="space-y-0.5">
            {helperText && <p className="text-xs text-muted-foreground">{helperText}</p>}
            {exampleText && (
              <p className="text-[11px] text-muted-foreground/80">{exampleText}</p>
            )}
          </div>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

