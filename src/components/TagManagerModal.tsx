import React, { useState, useEffect, useCallback } from 'react';
import type { Tag } from '../types/domain';
import type { CommandError } from '../types/vault';
import { listTags, createTag, renameTag, deleteTag } from '../services/domain';
import { Button } from './Button';
import { Input } from './Input';
import {
  Tag as TagIcon,
  Plus,
  Trash2,
  Edit2,
  X,
  Check,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

interface TagManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTagsUpdated?: () => void;
}

export const TagManagerModal: React.FC<TagManagerModalProps> = ({
  isOpen,
  onClose,
  onTagsUpdated,
}) => {
  const [tags, setTags] = useState<Tag[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  // Creation State
  const [newTagName, setNewTagName] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Edit / Rename State
  const [editingTagId, setEditingTagId] = useState<string | null>(null);
  const [editingTagName, setEditingTagName] = useState<string>('');
  const [isRenaming, setIsRenaming] = useState<boolean>(false);

  // Deletion Confirmation State
  const [deletingTagId, setDeletingTagId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  const fetchTags = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listTags();
      setTags(data);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchTags();
      setNewTagName('');
      setEditingTagId(null);
      setDeletingTagId(null);
    }
  }, [isOpen, fetchTags]);

  if (!isOpen) return null;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newTagName.trim();
    if (!trimmed) return;

    setIsSubmitting(true);
    setError(null);
    try {
      await createTag(trimmed);
      setNewTagName('');
      await fetchTags();
      onTagsUpdated?.();
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStartRename = (tag: Tag) => {
    setEditingTagId(tag.id);
    setEditingTagName(tag.name);
    setDeletingTagId(null);
  };

  const handleSaveRename = async (tagId: string) => {
    const trimmed = editingTagName.trim();
    if (!trimmed) return;

    setIsRenaming(true);
    setError(null);
    try {
      await renameTag(tagId, trimmed);
      setEditingTagId(null);
      setEditingTagName('');
      await fetchTags();
      onTagsUpdated?.();
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setIsRenaming(false);
    }
  };

  const handleDelete = async (tagId: string) => {
    setIsDeleting(true);
    setError(null);
    try {
      await deleteTag(tagId);
      setDeletingTagId(null);
      await fetchTags();
      onTagsUpdated?.();
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-xs">
      <div
        className="relative w-full max-w-md rounded-2xl border border-border bg-card p-6 shadow-xl animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[85vh]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="tag-manager-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border/60 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <TagIcon className="h-5 w-5 text-primary" />
            <h2 id="tag-manager-title" className="text-base font-semibold text-foreground">
              Manage Tags
            </h2>
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
            <span className="flex-1">{error.message}</span>
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

        {/* Create Tag Form */}
        <form onSubmit={handleCreate} className="flex gap-2 mb-4 items-start">
          <Input
            placeholder="Tag baru (misal: Work, Personal, Finance)..."
            value={newTagName}
            onChange={(e) => setNewTagName(e.target.value)}
            onClear={() => setNewTagName('')}
            exampleText="Maks. 100 karakter. Contoh: Work, Personal, Finance."
            maxLength={100}
            showCharCount
            disabled={isSubmitting}
            className="flex-1 h-9 text-xs"
          />
          <Button
            type="submit"
            variant="primary"
            size="sm"
            loading={isSubmitting}
            disabled={!newTagName.trim()}
            className="h-9 px-3 text-xs flex items-center gap-1.5"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Add</span>
          </Button>
        </form>

        {/* Tag List */}
        <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[140px]">
          {loading ? (
            <div className="py-8 flex flex-col items-center justify-center gap-2 text-muted-foreground text-xs">
              <RefreshCw className="h-4 w-4 animate-spin text-primary" />
              <span>Loading tags...</span>
            </div>
          ) : tags.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No tags yet. Create one above to organize your accounts.
            </div>
          ) : (
            tags.map((tag) => {
              const isEditingThis = editingTagId === tag.id;
              const isDeletingThis = deletingTagId === tag.id;

              if (isEditingThis) {
                return (
                  <div
                    key={tag.id}
                    className="flex items-center gap-1.5 p-2 rounded-xl bg-primary/5 border border-primary/20"
                  >
                    <input
                      type="text"
                      value={editingTagName}
                      onChange={(e) => setEditingTagName(e.target.value)}
                      autoFocus
                      className="flex-1 bg-background border border-input rounded px-2.5 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                    <Button
                      type="button"
                      variant="primary"
                      size="sm"
                      loading={isRenaming}
                      onClick={() => handleSaveRename(tag.id)}
                      disabled={!editingTagName.trim()}
                      className="h-7 px-2 text-xs"
                    >
                      <Check className="h-3 w-3" />
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setEditingTagId(null);
                        setEditingTagName('');
                      }}
                      className="h-7 px-2 text-xs"
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                );
              }

              if (isDeletingThis) {
                return (
                  <div
                    key={tag.id}
                    className="flex items-center justify-between gap-2 p-2 rounded-xl bg-destructive/10 border border-destructive/20 text-xs animate-in fade-in duration-100"
                  >
                    <span className="text-destructive font-medium truncate">
                      Delete #{tag.name}?
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Button
                        type="button"
                        variant="destructive"
                        size="sm"
                        loading={isDeleting}
                        onClick={() => handleDelete(tag.id)}
                        className="h-6 px-2 text-[11px]"
                      >
                        Delete
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setDeletingTagId(null)}
                        className="h-6 px-2 text-[11px]"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                );
              }

              return (
                <div
                  key={tag.id}
                  className="flex items-center justify-between p-2.5 rounded-xl border border-border/70 hover:border-border hover:bg-muted/30 transition-colors group"
                >
                  <span className="font-medium text-xs text-foreground flex items-center gap-1">
                    <span className="text-primary font-bold">#</span>
                    <span>{tag.name}</span>
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => handleStartRename(tag)}
                      className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
                      title="Rename tag"
                    >
                      <Edit2 className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDeletingTagId(tag.id);
                        setEditingTagId(null);
                      }}
                      className="p-1 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors cursor-pointer"
                      title="Delete tag"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="mt-4 pt-3 border-t border-border/60 flex justify-end">
          <Button type="button" variant="outline" size="sm" onClick={onClose} className="text-xs">
            Done
          </Button>
        </div>
      </div>
    </div>
  );
};
