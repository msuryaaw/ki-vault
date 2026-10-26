import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { LogoSummary } from '../types/domain';
import type { CommandError } from '../types/vault';
import {
  listLogos,
  importLogo,
  renameLogo,
  deleteLogo,
  getLogo,
} from '../services/domain';
import { Button } from './Button';
import { Input } from './Input';
import {
  Image,
  Upload,
  Trash2,
  Edit2,
  X,
  Check,
  AlertCircle,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';

const MAX_LOGO_SIZE_BYTES = 2 * 1024 * 1024; // 2 MiB
const ALLOWED_MIME_TYPES = [
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/svg+xml',
];

interface LogoManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedLogoId?: string | null;
  onSelectLogo?: (logoId: string | null) => void;
  onLogosUpdated?: () => void;
}

export const LogoManagerModal: React.FC<LogoManagerModalProps> = ({
  isOpen,
  onClose,
  selectedLogoId,
  onSelectLogo,
  onLogosUpdated,
}) => {
  const [logos, setLogos] = useState<LogoSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Cache for loaded logo previews (blob URLs)
  const [logoUrls, setLogoUrls] = useState<Record<string, string>>({});
  const blobUrlsRef = useRef<Record<string, string>>({});

  // Import State
  const [isImporting, setIsImporting] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [importName, setImportName] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importPreviewUrl, setImportPreviewUrl] = useState<string | null>(null);

  // Edit / Rename State
  const [editingLogoId, setEditingLogoId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState<string>('');
  const [isRenaming, setIsRenaming] = useState<boolean>(false);

  // Deletion Confirmation State
  const [deletingLogoId, setDeletingLogoId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  // Clean up blob URLs when component unmounts or modal closes
  const cleanupBlobUrls = useCallback(() => {
    Object.values(blobUrlsRef.current).forEach((url) => {
      URL.revokeObjectURL(url);
    });
    blobUrlsRef.current = {};
    setLogoUrls({});
  }, []);

  const fetchLogos = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listLogos();
      setLogos(data);
    } catch (err) {
      const maybeErr = err as CommandError;
      setError(maybeErr.message || 'Failed to load logos.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchLogos();
      setImportName('');
      setSelectedFile(null);
      if (importPreviewUrl) {
        URL.revokeObjectURL(importPreviewUrl);
        setImportPreviewUrl(null);
      }
      setEditingLogoId(null);
      setDeletingLogoId(null);
    } else {
      cleanupBlobUrls();
    }
  }, [isOpen, fetchLogos, cleanupBlobUrls, importPreviewUrl]);

  // Load thumbnail on demand for visible logo summary
  const loadLogoPreview = useCallback(async (logoId: string) => {
    if (blobUrlsRef.current[logoId]) return;

    try {
      const fullLogo = await getLogo(logoId);
      const uint8 = new Uint8Array(fullLogo.image_data);
      const blob = new Blob([uint8], { type: fullLogo.mime_type });
      const objectUrl = URL.createObjectURL(blob);
      blobUrlsRef.current[logoId] = objectUrl;
      setLogoUrls((prev) => ({ ...prev, [logoId]: objectUrl }));
    } catch {
      // Failed to load preview; will show fallback icon
    }
  }, []);

  // Lazy-load previews for all returned logos
  useEffect(() => {
    logos.forEach((logo) => {
      loadLogoPreview(logo.id);
    });
  }, [logos, loadLogoPreview]);

  if (!isOpen) return null;

  const inferMimeType = (file: File): string => {
    if (file.type && ALLOWED_MIME_TYPES.includes(file.type)) {
      return file.type;
    }
    const ext = file.name.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'png':
        return 'image/png';
      case 'jpg':
      case 'jpeg':
        return 'image/jpeg';
      case 'webp':
        return 'image/webp';
      case 'svg':
        return 'image/svg+xml';
      default:
        return file.type || '';
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    // Check size limit: 2 MiB
    if (file.size > MAX_LOGO_SIZE_BYTES) {
      setError(`File terlalu besar (${(file.size / (1024 * 1024)).toFixed(2)} MB). Maksimal ukuran file adalah 2 MB.`);
      return;
    }

    // Check MIME type with extension inference
    const mime = inferMimeType(file);
    if (!ALLOWED_MIME_TYPES.includes(mime)) {
      setError(`Format file tidak didukung (${file.type || mime || 'unknown'}). Format yang diizinkan: PNG, JPG/JPEG, WebP, SVG.`);
      return;
    }

    setSelectedFile(file);
    if (!importName.trim()) {
      // Strip extension for clean default name
      const nameWithoutExt = file.name.replace(/\.[^/.]+$/, '');
      setImportName(nameWithoutExt);
    }

    if (importPreviewUrl) {
      URL.revokeObjectURL(importPreviewUrl);
    }
    const preview = URL.createObjectURL(file);
    setImportPreviewUrl(preview);
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please choose an image file.');
      return;
    }
    const trimmedName = importName.trim();
    if (!trimmedName) {
      setError('Logo name cannot be empty.');
      return;
    }

    setIsImporting(true);
    setError(null);
    try {
      const arrayBuffer = await selectedFile.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);
      const numberArray = Array.from(uint8Array);

      const mimeType = inferMimeType(selectedFile);
      const imported = await importLogo(
        trimmedName,
        mimeType,
        numberArray
      );

      // Reset import form
      setSelectedFile(null);
      setImportName('');
      if (importPreviewUrl) {
        URL.revokeObjectURL(importPreviewUrl);
        setImportPreviewUrl(null);
      }
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      await fetchLogos();
      onLogosUpdated?.();

      // If in picker mode, automatically select newly imported logo
      if (onSelectLogo) {
        onSelectLogo(imported.id);
      }
    } catch (err) {
      const maybeErr = err as CommandError;
      setError(maybeErr.message || 'Failed to import logo.');
    } finally {
      setIsImporting(false);
    }
  };

  const handleStartRename = (logo: LogoSummary) => {
    setEditingLogoId(logo.id);
    setEditingName(logo.name);
    setDeletingLogoId(null);
  };

  const handleSaveRename = async (logoId: string) => {
    const trimmed = editingName.trim();
    if (!trimmed) return;

    setIsRenaming(true);
    setError(null);
    try {
      await renameLogo(logoId, trimmed);
      setEditingLogoId(null);
      setEditingName('');
      await fetchLogos();
      onLogosUpdated?.();
    } catch (err) {
      const maybeErr = err as CommandError;
      setError(maybeErr.message || 'Failed to rename logo.');
    } finally {
      setIsRenaming(false);
    }
  };

  const handleDelete = async (logoId: string) => {
    setIsDeleting(true);
    setError(null);
    try {
      await deleteLogo(logoId);
      setDeletingLogoId(null);

      // Clean up cached blob URL if deleted
      if (blobUrlsRef.current[logoId]) {
        URL.revokeObjectURL(blobUrlsRef.current[logoId]);
        delete blobUrlsRef.current[logoId];
      }

      // If currently selected logo is deleted, unselect it
      if (selectedLogoId === logoId && onSelectLogo) {
        onSelectLogo(null);
      }

      await fetchLogos();
      onLogosUpdated?.();
    } catch (err) {
      const maybeErr = err as CommandError;
      setError(maybeErr.message || 'Failed to delete logo.');
    } finally {
      setIsDeleting(false);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-xs">
      <div
        className="relative w-full max-w-2xl rounded-2xl border border-border bg-card p-6 shadow-xl animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[90vh]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="logo-manager-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border/60 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Image className="h-5 w-5 text-primary" />
            <div>
              <h2 id="logo-manager-title" className="text-base font-semibold text-foreground">
                Logo Manager
              </h2>
              <p className="text-[11px] text-muted-foreground">
                Import and organize brand icons stored in your encrypted vault.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground p-1 rounded-md transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Global Error Banner */}
        {error && (
          <div className="mb-4 rounded-lg bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span className="flex-1">{error}</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setError(null)}
              className="text-[10px] h-6 px-1.5"
            >
              Dismiss
            </Button>
          </div>
        )}

        {/* Import New Logo / Upload Logo Section */}
        <form
          onSubmit={handleImportSubmit}
          className="rounded-2xl border border-border/80 bg-background/60 p-4 mb-4 space-y-4"
        >
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Upload className="h-4 w-4 text-primary" />
              Upload Logo
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              UI yang lebih jelas dan informatif untuk menambahkan logo platform ke dalam vault terenkripsi.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* Drag & Drop / File Select Box */}
            <div className="md:col-span-7 space-y-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".png,.jpg,.jpeg,.webp,.svg,image/png,image/jpeg,image/webp,image/svg+xml"
                onChange={handleFileSelect}
                className="hidden"
                id="logo-file-input"
              />
              <label
                htmlFor="logo-file-input"
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  const file = e.dataTransfer.files?.[0];
                  if (file) {
                    const synthEvent = {
                      target: { files: [file] },
                    } as unknown as React.ChangeEvent<HTMLInputElement>;
                    handleFileSelect(synthEvent);
                  }
                }}
                className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-border/90 hover:border-primary/60 rounded-xl bg-card/40 hover:bg-card/70 transition-all cursor-pointer text-center group min-h-[140px]"
              >
                {importPreviewUrl ? (
                  <div className="flex flex-col items-center gap-2">
                    <div className="h-14 w-14 rounded-xl border border-border bg-background p-1.5 flex items-center justify-center shadow-sm">
                      <img
                        src={importPreviewUrl}
                        alt="Preview"
                        className="max-h-full max-w-full object-contain rounded"
                      />
                    </div>
                    <span className="text-xs font-medium text-foreground truncate max-w-[200px]">
                      {selectedFile?.name}
                    </span>
                    <span className="text-[11px] text-primary group-hover:underline">
                      Klik atau seret gambar lain untuk mengganti
                    </span>
                  </div>
                ) : (
                  <>
                    <div className="p-2.5 rounded-xl bg-muted/50 text-muted-foreground group-hover:text-primary mb-2 transition-colors">
                      <Image className="h-6 w-6" />
                    </div>
                    <span className="text-xs font-semibold text-foreground">
                      Pilih file logo
                    </span>
                    <span className="text-[11px] text-muted-foreground mt-0.5">
                      Drag & drop atau klik untuk memilih
                    </span>
                    <span className="text-[10px] text-muted-foreground/80 font-mono mt-1">
                      PNG, JPG, WebP, atau SVG (maks. 2 MB)
                    </span>
                  </>
                )}
              </label>

              {/* Logo Name & Save */}
              <div className="flex items-center gap-2 pt-1">
                <Input
                  placeholder="Nama logo (contoh: Google, GitHub)..."
                  value={importName}
                  onChange={(e) => setImportName(e.target.value)}
                  onClear={() => setImportName('')}
                  disabled={isImporting}
                  maxLength={64}
                  showCharCount
                  className="h-9 text-xs"
                />
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  loading={isImporting}
                  disabled={!selectedFile || !importName.trim()}
                  className="h-9 px-4 text-xs shrink-0 gap-1.5"
                >
                  <Check className="h-3.5 w-3.5" />
                  <span>Simpan</span>
                </Button>
              </div>
            </div>

            {/* Requirements Checklist Card */}
            <div className="md:col-span-5 rounded-xl border border-border/60 bg-muted/20 p-3.5 flex flex-col justify-between text-xs space-y-2">
              <span className="font-semibold text-foreground text-xs">
                Persyaratan logo:
              </span>
              <ul className="space-y-1.5 text-[11px] text-muted-foreground">
                <li className="flex items-start gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                  <span>Format: PNG, JPG, WebP, atau SVG</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                  <span>Ukuran maksimal: 2 MB</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                  <span>Resolusi disarankan: 256 × 256 px (persegi)</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                  <span>Rasio 1:1 (akan dipotong otomatis jika tidak persegi)</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                  <span>Gambar sebaiknya logo resmi atau ikon sederhana</span>
                </li>
              </ul>
            </div>
          </div>
        </form>

        {/* Gallery Grid */}
        <div className="flex-1 overflow-y-auto pr-1 min-h-[220px]">
          {loading ? (
            <div className="py-16 flex flex-col items-center justify-center gap-2 text-muted-foreground text-xs">
              <RefreshCw className="h-5 w-5 animate-spin text-primary" />
              <span>Loading logos from encrypted vault...</span>
            </div>
          ) : logos.length === 0 ? (
            <div className="py-16 text-center border border-dashed border-border rounded-xl flex flex-col items-center justify-center text-xs text-muted-foreground gap-2">
              <Image className="h-8 w-8 text-muted-foreground/50" />
              <p>No logos imported yet. Use the form above to add platform brand logos.</p>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
              {logos.map((logo) => {
                const isSelected = selectedLogoId === logo.id;
                const previewUrl = logoUrls[logo.id];
                const isEditingThis = editingLogoId === logo.id;
                const isDeletingThis = deletingLogoId === logo.id;

                if (isDeletingThis) {
                  return (
                    <div
                      key={logo.id}
                      className="rounded-xl border border-destructive/30 bg-destructive/10 p-2.5 flex flex-col justify-between text-xs space-y-2 animate-in fade-in"
                    >
                      <p className="text-[11px] text-destructive font-medium truncate">
                        Delete &quot;{logo.name}&quot;?
                      </p>
                      <div className="flex items-center gap-1.5 justify-end">
                        <Button
                          type="button"
                          variant="destructive"
                          size="sm"
                          loading={isDeleting}
                          onClick={() => handleDelete(logo.id)}
                          className="h-6 px-2 text-[10px]"
                        >
                          Delete
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setDeletingLogoId(null)}
                          className="h-6 px-2 text-[10px]"
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  );
                }

                return (
                  <div
                    key={logo.id}
                    onClick={() => onSelectLogo && onSelectLogo(isSelected ? null : logo.id)}
                    className={`group relative rounded-xl border p-2.5 flex flex-col justify-between transition-all cursor-pointer ${
                      isSelected
                        ? 'border-primary bg-primary/5 shadow-xs ring-1 ring-primary'
                        : 'border-border/80 hover:border-primary/40 bg-card hover:bg-muted/30'
                    }`}
                  >
                    {/* Selected Badge */}
                    {isSelected && (
                      <div className="absolute top-2 right-2 text-primary" title="Currently selected">
                        <CheckCircle2 className="h-4 w-4 fill-primary text-primary-foreground" />
                      </div>
                    )}

                    {/* Image Thumbnail Container */}
                    <div className="h-16 w-full flex items-center justify-center p-1.5 rounded-lg bg-background/80 border border-border/40 mb-2">
                      {previewUrl ? (
                        <img
                          src={previewUrl}
                          alt={logo.name}
                          className="max-h-full max-w-full object-contain"
                          loading="lazy"
                        />
                      ) : (
                        <Image className="h-6 w-6 text-muted-foreground/40 animate-pulse" />
                      )}
                    </div>

                    {/* Name / Rename Input */}
                    {isEditingThis ? (
                      <div
                        className="flex items-center gap-1 pt-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="text"
                          value={editingName}
                          onChange={(e) => setEditingName(e.target.value)}
                          autoFocus
                          className="w-full bg-background border border-input rounded px-1.5 py-0.5 text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                        />
                        <button
                          type="button"
                          disabled={isRenaming || !editingName.trim()}
                          onClick={() => handleSaveRename(logo.id)}
                          className="p-1 rounded text-primary hover:bg-primary/10"
                        >
                          <Check className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setEditingLogoId(null);
                            setEditingName('');
                          }}
                          className="p-1 rounded text-muted-foreground hover:bg-muted"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ) : (
                      <div>
                        <div className="flex items-center justify-between gap-1">
                          <p
                            className="text-xs font-semibold text-foreground truncate"
                            title={logo.name}
                          >
                            {logo.name}
                          </p>
                          <div
                            className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <button
                              type="button"
                              onClick={() => handleStartRename(logo)}
                              className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-muted cursor-pointer"
                              title="Rename logo"
                            >
                              <Edit2 className="h-3 w-3" />
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setDeletingLogoId(logo.id);
                                setEditingLogoId(null);
                              }}
                              className="p-1 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 cursor-pointer"
                              title="Delete logo"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        </div>
                        <p className="text-[10px] text-muted-foreground font-mono mt-0.5">
                          {formatFileSize(logo.size_bytes)}
                        </p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="mt-4 pt-3 border-t border-border/60 flex items-center justify-between">
          <span className="text-[11px] text-muted-foreground">
            {selectedLogoId && onSelectLogo
              ? 'Click the selected logo to unassign, or select another.'
              : `${logos.length} logo${logos.length === 1 ? '' : 's'} stored`}
          </span>
          <div className="flex items-center gap-2">
            {selectedLogoId && onSelectLogo && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onSelectLogo(null)}
                className="text-xs h-8"
              >
                Clear Logo
              </Button>
            )}
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={onClose}
              className="text-xs h-8"
            >
              Done
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
