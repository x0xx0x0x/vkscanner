import React, { useState, useEffect } from 'react';

/**
 * App layout with header, language toggle, and content area.
 */
export default function Layout({ children, lang, onLangChange }) {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('vk_theme') || 'dark';
  });

  useEffect(() => {
    if (theme === 'light') {
      document.body.classList.add('theme-light');
    } else {
      document.body.classList.remove('theme-light');
    }
    localStorage.setItem('vk_theme', theme);
  }, [theme]);

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="app-header__brand">
          <div className="app-header__logo">vk</div>
          <div>
            <div className="app-header__title">vkscanner</div>
            <div className="app-header__subtitle">voight-kampff phishing detector</div>
          </div>
        </div>
        <div className="app-header__controls" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="lang-toggle">
            <button
              className={`lang-toggle__btn ${lang === 'en' ? 'lang-toggle__btn--active' : ''}`}
              onClick={() => onLangChange('en')}
            >
              EN
            </button>
            <button
              className={`lang-toggle__btn ${lang === 'es' ? 'lang-toggle__btn--active' : ''}`}
              onClick={() => onLangChange('es')}
            >
              ES
            </button>
          </div>
          
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="lang-toggle__btn"
            style={{ 
              background: 'var(--bg-secondary)', 
              border: '1px solid var(--border-primary)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              padding: '8px 14px',
              height: '34px',
              fontSize: '12px',
              fontWeight: 700
            }}
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </div>
      </header>
      <main>{children}</main>
      <footer style={{
        textAlign: 'center',
        padding: '32px 0',
        marginTop: '48px',
        borderTop: '1px solid var(--border-subtle)',
        color: 'var(--text-muted)',
        fontSize: '12px',
      }}>
        vkscanner v1.0.0 — voight-kampff phishing detection engine
      </footer>
    </div>
  );
}
