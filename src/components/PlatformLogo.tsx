import React, { useEffect, useState, useRef } from 'react';
import { getLogo } from '../services/domain';
import { Globe } from 'lucide-react';

interface PlatformLogoProps {
  logoId?: string | null;
  platformName?: string;
  className?: string;
  fallbackClassName?: string;
  size?: 'sm' | 'md' | 'lg';
}

// Global in-memory cache of object URLs by logo ID to avoid duplicate IPC calls and memory bloat
const logoCache = new Map<string, string>();
const pendingFetches = new Map<string, Promise<string | null>>();

export async function fetchLogoBlobUrl(logoId: string): Promise<string | null> {
  if (logoCache.has(logoId)) {
    return logoCache.get(logoId)!;
  }

  if (pendingFetches.has(logoId)) {
    return pendingFetches.get(logoId)!;
  }

  const fetchPromise = (async () => {
    try {
      const fullLogo = await getLogo(logoId);
      const uint8 = new Uint8Array(fullLogo.image_data);
      const blob = new Blob([uint8], { type: fullLogo.mime_type });
      const objectUrl = URL.createObjectURL(blob);
      logoCache.set(logoId, objectUrl);
      return objectUrl;
    } catch {
      return null;
    } finally {
      pendingFetches.delete(logoId);
    }
  })();

  pendingFetches.set(logoId, fetchPromise);
  return fetchPromise;
}

export const PlatformLogo: React.FC<PlatformLogoProps> = ({
  logoId,
  platformName = 'Platform',
  className = '',
  fallbackClassName = '',
  size = 'md',
}) => {
  const [blobUrl, setBlobUrl] = useState<string | null>(() => {
    return logoId ? logoCache.get(logoId) || null : null;
  });
  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    if (!logoId) {
      setBlobUrl(null);
      return;
    }

    if (logoCache.has(logoId)) {
      setBlobUrl(logoCache.get(logoId)!);
      return;
    }

    fetchLogoBlobUrl(logoId).then((url) => {
      if (isMounted.current) {
        setBlobUrl(url);
      }
    });

    return () => {
      isMounted.current = false;
    };
  }, [logoId]);

  const sizeDimensions = {
    sm: 'h-6 w-6',
    md: 'h-8 w-8',
    lg: 'h-10 w-10',
  }[size];

  const iconDimensions = {
    sm: 'h-3.5 w-3.5',
    md: 'h-4 w-4',
    lg: 'h-5 w-5',
  }[size];

  if (blobUrl) {
    return (
      <div
        className={`${sizeDimensions} rounded-lg bg-white border border-border/60 flex items-center justify-center p-1 overflow-hidden shrink-0 shadow-2xs ${className}`}
      >
        <img
          src={blobUrl}
          alt={platformName}
          className="max-h-full max-w-full object-contain"
          loading="lazy"
        />
      </div>
    );
  }

  return (
    <div
      className={`${sizeDimensions} rounded-lg bg-accent text-primary flex items-center justify-center shrink-0 ${fallbackClassName || className}`}
    >
      <Globe className={iconDimensions} />
    </div>
  );
};
