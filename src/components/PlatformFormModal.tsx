import React, { useState, useEffect } from 'react';
import type { PlatformSummary, CreatePlatformInput, UpdatePlatformInput } from '../types/domain';
import { Button } from './Button';
import { Input } from './Input';
import { LogoManagerModal } from './LogoManagerModal';
import { Globe, X, Image as ImageIcon } from 'lucide-react';

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
  const [logoId, setLogoId] = useState<string | null>(null);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);

  useEffect(() => {
    if (initialData) {
      setName(initialData.name || '');
      setCategory(initialData.category || '');
      setWebsite(initialData.website || '');
      setLogoId(initialData.logo_id || null);
    } else {
      setName('');
      setCategory('');
      setWebsite('');
      setLogoId(null);
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
        logo_id: logoId,
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
            onClear={() => setName('')}
            placeholder="Google, GitHub, Proton"
            helperText="Nama layanan atau platform penyedia akun."
            exampleText="Contoh: Google, GitHub, AWS, atau Proton."
            maxLength={256}
            showCharCount
            isValid={name.trim().length >= 2}
            error={name.length > 0 && name.trim().length < 2 ? 'Nama platform minimal 2 karakter.' : undefined}
            disabled={loading}
            autoFocus
            required
          />

          <Input
            label="Category (Optional)"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            onClear={() => setCategory('')}
            placeholder="Email, Development, Finance"
            helperText="Kategori pengelompokan platform."
            exampleText="Contoh: Email, Development, Social, Banking."
            maxLength={100}
            showCharCount
            disabled={loading}
          />

          <Input
            label="Website URL (Optional)"
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            onClear={() => setWebsite('')}
            placeholder="https://github.com"
            helperText="Alamat website resmi platform."
            exampleText="Contoh: https://google.com atau https://github.com."
            maxLength={2048}
            showCharCount
            isValid={website.length > 0 && /^https?:\/\/.+/i.test(website.trim())}
            error={website.length > 0 && !/^https?:\/\/.+/i.test(website.trim()) ? 'Gunakan URL lengkap dengan http:// atau https://' : undefined}
            disabled={loading}
          />

          {/* Logo Selection Section */}
          <div className="space-y-1.5 pt-1">
            <label className="text-xs font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <ImageIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Platform Logo (Optional)
              </span>
              <button
                type="button"
                onClick={() => setIsLogoModalOpen(true)}
                className="text-[11px] text-primary hover:underline cursor-pointer font-medium"
              >
                {logoId ? 'Change Logo' : 'Choose Logo...'}
              </button>
            </label>
            <div className="flex items-center justify-between p-2.5 rounded-lg border border-input bg-background/50">
              <span className="text-xs text-muted-foreground">
                {logoId ? 'Custom logo attached' : 'Default platform icon'}
              </span>
              {logoId ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setLogoId(null)}
                  className="h-6 px-2 text-[10px]"
                >
                  Remove
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setIsLogoModalOpen(true)}
                  className="h-6 px-2 text-[10px]"
                >
                  Browse...
                </Button>
              )}
            </div>
          </div>

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

      {/* Logo Manager Modal */}
      <LogoManagerModal
        isOpen={isLogoModalOpen}
        onClose={() => setIsLogoModalOpen(false)}
        selectedLogoId={logoId}
        onSelectLogo={(newLogoId) => {
          setLogoId(newLogoId);
          setIsLogoModalOpen(false);
        }}
      />
    </div>
  );
};
