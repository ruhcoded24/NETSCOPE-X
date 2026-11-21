import React from 'react';

interface GlassPanelProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export const GlassPanel: React.FC<GlassPanelProps> = ({
  children,
  className = '',
  title,
  subtitle,
  action,
}) => {
  return (
    <section
      className={`bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-5 ${className}`}
    >
      {(title || action) && (
        <div className="flex items-start justify-between gap-4 pb-4 mb-4 border-b border-[#C9A4FF]/12">
          <div className="min-w-0">
            {title && (
              <h2 className="text-base font-semibold text-white font-display tracking-tight truncate">
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="text-xs text-[#C9A4FF]/70 mt-0.5 truncate">{subtitle}</p>
            )}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      )}
      {children}
    </section>
  );
};
