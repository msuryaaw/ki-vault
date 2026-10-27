import React, { useState, useRef, useEffect, useId } from 'react';
import { ChevronDown, Check } from 'lucide-react';
import { cn } from '../lib/utils';

export interface DropdownOption<T extends string | number = string> {
  value: T;
  label: string;
  disabled?: boolean;
}

export interface DropdownProps<T extends string | number = string> {
  options: DropdownOption<T>[];
  value?: T;
  onChange?: (value: T) => void;
  placeholder?: string;
  prefixIcon?: React.ReactNode;
  disabled?: boolean;
  className?: string;
  ariaLabel?: string;
  id?: string;
}

export function Dropdown<T extends string | number = string>({
  options,
  value,
  onChange,
  placeholder = 'Select an option...',
  prefixIcon,
  disabled = false,
  className,
  ariaLabel,
  id,
}: DropdownProps<T>) {
  const [isOpen, setIsOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState<number>(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const listboxRef = useRef<HTMLUListElement>(null);
  const generatedId = useId();
  const dropdownId = id || generatedId;

  const selectedIndex = options.findIndex((opt) => opt.value === value);
  const selectedOption = selectedIndex >= 0 ? options[selectedIndex] : null;

  // Sync highlightedIndex whenever menu opens or selection changes
  useEffect(() => {
    if (isOpen) {
      setHighlightedIndex(selectedIndex >= 0 ? selectedIndex : 0);
    }
  }, [isOpen, selectedIndex]);

  // Click outside listener to close popup
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (e: MouseEvent | TouchEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
    };
  }, [isOpen]);

  // Scroll active option into view
  useEffect(() => {
    if (isOpen && listboxRef.current && highlightedIndex >= 0) {
      const activeElement = listboxRef.current.children[highlightedIndex] as HTMLElement | undefined;
      activeElement?.scrollIntoView({ block: 'nearest' });
    }
  }, [isOpen, highlightedIndex]);

  const handleSelect = (option: DropdownOption<T>) => {
    if (option.disabled || disabled) return;
    onChange?.(option.value);
    setIsOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (disabled) return;

    if (!isOpen) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setIsOpen(true);
      }
      return;
    }

    switch (e.key) {
      case 'Escape':
        e.preventDefault();
        setIsOpen(false);
        break;

      case 'Enter':
      case ' ':
        e.preventDefault();
        if (highlightedIndex >= 0 && highlightedIndex < options.length) {
          handleSelect(options[highlightedIndex]);
        }
        break;

      case 'ArrowDown': {
        e.preventDefault();
        let nextIndex = highlightedIndex + 1;
        while (nextIndex < options.length && options[nextIndex].disabled) {
          nextIndex++;
        }
        if (nextIndex < options.length) {
          setHighlightedIndex(nextIndex);
        }
        break;
      }

      case 'ArrowUp': {
        e.preventDefault();
        let prevIndex = highlightedIndex - 1;
        while (prevIndex >= 0 && options[prevIndex].disabled) {
          prevIndex--;
        }
        if (prevIndex >= 0) {
          setHighlightedIndex(prevIndex);
        }
        break;
      }

      case 'Tab':
        setIsOpen(false);
        break;

      case 'Home':
        e.preventDefault();
        setHighlightedIndex(0);
        break;

      case 'End':
        e.preventDefault();
        setHighlightedIndex(options.length - 1);
        break;
    }
  };

  return (
    <div
      ref={containerRef}
      className={cn('relative w-full text-left select-none', className)}
    >
      {/* Trigger Button */}
      <button
        type="button"
        id={`${dropdownId}-button`}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-labelledby={ariaLabel ? undefined : `${dropdownId}-button`}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => !disabled && setIsOpen((prev) => !prev)}
        onKeyDown={handleKeyDown}
        className={cn(
          'flex h-9 w-full items-center justify-between rounded-lg border border-input bg-background px-2.5 py-1.5 text-xs text-foreground shadow-2xs transition-colors',
          'hover:border-primary/50 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary',
          disabled && 'cursor-not-allowed opacity-50',
          isOpen && 'border-primary ring-1 ring-primary'
        )}
      >
        <div className="flex items-center gap-2 truncate min-w-0 pr-1">
          {prefixIcon && (
            <span className="shrink-0 text-muted-foreground pointer-events-none">
              {prefixIcon}
            </span>
          )}
          <span
            className={cn(
              'truncate font-normal',
              !selectedOption && 'text-muted-foreground'
            )}
          >
            {selectedOption ? selectedOption.label : placeholder}
          </span>
        </div>

        <ChevronDown
          className={cn(
            'h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150',
            isOpen && 'rotate-180 text-primary'
          )}
        />
      </button>

      {/* Dropdown Menu Popup */}
      {isOpen && (
        <ul
          ref={listboxRef}
          role="listbox"
          id={`${dropdownId}-listbox`}
          aria-labelledby={`${dropdownId}-button`}
          tabIndex={-1}
          className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-xl border border-border bg-popover/95 backdrop-blur-md p-1 shadow-lg text-xs text-popover-foreground focus:outline-none animate-in fade-in-50 zoom-in-95 duration-100"
        >
          {options.map((option, idx) => {
            const isSelected = option.value === value;
            const isHighlighted = idx === highlightedIndex;

            return (
              <li
                key={String(option.value)}
                role="option"
                id={`${dropdownId}-option-${idx}`}
                aria-selected={isSelected}
                aria-disabled={option.disabled}
                onClick={() => handleSelect(option)}
                onMouseEnter={() => !option.disabled && setHighlightedIndex(idx)}
                className={cn(
                  'relative flex items-center justify-between rounded-lg px-2.5 py-1.5 text-xs font-normal cursor-pointer transition-colors',
                  option.disabled && 'cursor-not-allowed opacity-50',
                  isSelected && 'bg-primary/10 text-primary font-medium',
                  !isSelected && isHighlighted && 'bg-muted text-foreground',
                  !isSelected && !isHighlighted && 'text-foreground hover:bg-muted/60'
                )}
              >
                <span className="truncate pr-2">{option.label}</span>
                {isSelected && (
                  <Check className="h-3.5 w-3.5 shrink-0 text-primary" />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
