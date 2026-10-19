import React, { useState, useEffect } from 'react';
import type { PlatformSummary, CreatePlatformInput, UpdatePlatformInput } from '../types/domain';
import { Button } from './Button';
import { Input } from './Input';
import { Globe, X } from 'lucide-react';

interface PlatformFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreatePlatformInput | UpdatePlatformInput) => Promise<void>;
  initialData?: PlatformSummary | null;
  loading?: boolean;
}

export const PlatformFormModal: React.FC<PlatformFormModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  initialData,
  loading = false,
}) => {
  const [name, setName] = useState('');
  const [category, setCategory] = useState('');
  const [website, setWebsite] = useState('');
  const [clientError, setClientError] = useState<string | null>(null);

  useEffect(() => {
    if (initialData) {
      setName(initialData.name || '');
      setCategory(initialData.category || '');
      setWebsite(initialData.website || '');
    } else {
      setName('');
      setCategory('');
      setWebsite('');
    }
    setClientError(null);
  }, [initialData, isOpen]);

  if (!isOpen) return null;

  const isEditing = Boolean(initialData);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);

    const trimmedName = name.trim();
    if (!trimmedName) {
      setClientError('Platform name is required.');
      return;
    }

    try {
      await onSubmit({
        name: trimmedName,
        category: category.trim() || null,
        website: website.trim() || null,
      });
      onClose();
    } catch (err: unknown) {
      const maybeErr = err as { message?: string };
      setClientError(maybeErr.message || 'Operation failed.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-2xl space-y-5 text-left">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2 font-bold text-base text-foreground">
            <Globe className="h-5 w-5 text-primary" />
            <span>{isEditing ? 'Edit Platform' : 'Add New Platform'}</span>
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground p-1 rounded-md transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Platform Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Google, GitHub, Proton"
            disabled={loading}
            autoFocus
            required
          />

          <Input
            label="Category (Optional)"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            placeholder="e.g. Email, Development, Finance"
            disabled={loading}
          />

          <Input
            label="Website URL (Optional)"
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            placeholder="e.g. https://github.com"
            disabled={loading}
          />

          {clientError && (
            <p className="text-xs text-destructive">{clientError}</p>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onClose}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              loading={loading}
            >
              {isEditing ? 'Save Changes' : 'Create Platform'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
