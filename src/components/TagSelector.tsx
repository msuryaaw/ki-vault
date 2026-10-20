import React, { useState } from 'react';
import type { Tag } from '../types/domain';
import { Button } from './Button';
import { Tag as TagIcon, Plus, X, Check } from 'lucide-react';

interface TagSelectorProps {
  availableTags: Tag[];
  selectedTagIds: string[];
  onChange: (tagIds: string[]) => void;
  onCreateTag?: (name: string) => Promise<Tag | null>;
  disabled?: boolean;
}

export const TagSelector: React.FC<TagSelectorProps> = ({
  availableTags,
  selectedTagIds,
  onChange,
  onCreateTag,
  disabled = false,
}) => {
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [newTagName, setNewTagName] = useState<string>('');
  const [creationLoading, setCreationLoading] = useState<boolean>(false);
  const [inlineError, setInlineError] = useState<string | null>(null);

  const handleToggleTag = (tagId: string) => {
    if (disabled) return;
    if (selectedTagIds.includes(tagId)) {
      onChange(selectedTagIds.filter((id) => id !== tagId));
    } else {
      onChange([...selectedTagIds, tagId]);
    }
  };

  const handleQuickCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setInlineError(null);
    const trimmed = newTagName.trim();
    if (!trimmed) {
      setInlineError('Tag name cannot be empty.');
      return;
    }

    if (availableTags.some((t) => t.name.toLowerCase() === trimmed.toLowerCase())) {
      setInlineError('A tag with this name already exists.');
      return;
    }

    if (!onCreateTag) return;

    setCreationLoading(true);
    try {
      const created = await onCreateTag(trimmed);
      if (created) {
        onChange([...selectedTagIds, created.id]);
        setNewTagName('');
        setIsCreating(false);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create tag.';
      setInlineError(msg);
    } finally {
      setCreationLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
          <TagIcon className="h-3.5 w-3.5 text-muted-foreground" />
          Tags
        </label>
        {onCreateTag && !isCreating && !disabled && (
          <button
            type="button"
            onClick={() => {
              setIsCreating(true);
              setInlineError(null);
            }}
            className="text-[11px] text-primary hover:underline flex items-center gap-1 cursor-pointer font-medium"
          >
            <Plus className="h-3 w-3" />
            New Tag
          </button>
        )}
      </div>

      {/* Quick Tag Creator Inline */}
      {isCreating && (
        <form onSubmit={handleQuickCreate} className="flex flex-col gap-1.5 p-2 rounded-lg bg-primary/5 border border-primary/20">
          <div className="flex items-center gap-1.5">
            <input
              type="text"
              placeholder="Tag name (e.g. Work, Finance)..."
              value={newTagName}
              onChange={(e) => setNewTagName(e.target.value)}
              autoFocus
              className="flex-1 bg-background border border-input rounded px-2.5 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <Button
              type="submit"
              variant="primary"
              size="sm"
              loading={creationLoading}
              className="h-7 px-2 text-xs"
            >
              <Check className="h-3.5 w-3.5" />
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                setIsCreating(false);
                setNewTagName('');
                setInlineError(null);
              }}
              className="h-7 px-2 text-xs"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
          {inlineError && <p className="text-[10px] text-destructive">{inlineError}</p>}
        </form>
      )}

      {/* Tag Chips */}
      {availableTags.length === 0 ? (
        <p className="text-[11px] text-muted-foreground italic">No tags created yet.</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {availableTags.map((tag) => {
            const isSelected = selectedTagIds.includes(tag.id);
            return (
              <button
                key={tag.id}
                type="button"
                onClick={() => handleToggleTag(tag.id)}
                disabled={disabled}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors cursor-pointer ${
                  isSelected
                    ? 'bg-primary text-primary-foreground shadow-xs'
                    : 'bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground border border-border/60'
                } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <span>#{tag.name}</span>
                {isSelected && <X className="h-3 w-3 hover:text-primary-foreground/80" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};
