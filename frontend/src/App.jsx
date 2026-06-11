import React, { useState } from 'react';
import Layout from './components/Layout';
import ScanForm from './components/ScanForm';
import ResultsPanel from './components/ResultsPanel';
import YaraRulesPanel from './components/YaraRulesPanel';
import HistoryPanel from './components/HistoryPanel';
import { useScan } from './hooks/useScan';
import translations from './utils/i18n';

export default function App() {
  const [lang, setLang] = useState('en');
  const t = translations[lang];
  const {
    loading, result, setResult, error,
    performUrlScan, performEmailScan, performEmailFileScan, performDocumentScan,
  } = useScan();

  const handleSelectScan = (scanData) => {
    setResult(scanData);
  };

  const handleScanReset = (deletedScanId) => {
    if (!deletedScanId || (result && result.scan_id === deletedScanId)) {
      setResult(null);
    }
  };

  return (
    <Layout lang={lang} onLangChange={setLang}>
      <div className="app-main-grid">
        <div className="app-left-col">
          <ScanForm
            onUrlScan={performUrlScan}
            onEmailScan={performEmailScan}
            onEmailFileScan={performEmailFileScan}
            onDocScan={performDocumentScan}
            loading={loading}
            t={t}
          />
          <HistoryPanel
            onSelectScan={handleSelectScan}
            onScanReset={handleScanReset}
            activeScanId={result ? result.scan_id : null}
            t={t}
          />
        </div>

        <div className="app-right-col">
          {error && (
            <div style={{
              padding: '14px 20px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--risk-high)',
              fontSize: '14px',
            }}>
              ❌ {t?.error_prefix || 'Error'}: {error}
            </div>
          )}

          {result ? (
            <ResultsPanel result={result} t={t} />
          ) : (
            <div className="card welcome-card" style={{ 
              textAlign: 'center', 
              padding: '48px 32px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: '400px',
              borderStyle: 'dashed',
              borderColor: 'rgba(96, 165, 250, 0.25)',
              background: 'rgba(17, 20, 28, 0.1)'
            }}>
              <div style={{ fontSize: '48px', marginBottom: '20px' }}>🛡️</div>
              <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '12px', color: 'var(--cyan)' }}>
                {lang === 'es' ? 'vkscanner — suite de inteligencia' : 'vkscanner — threat intelligence'}
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13px', maxWidth: '380px', lineHeight: '1.6', margin: '0 auto' }}>
                {lang === 'es' 
                  ? 'Sube un archivo o ingresa una URL en el panel izquierdo para iniciar el análisis heurístico y forense local.' 
                  : 'Upload a file or enter a URL on the left panel to begin static, heuristic, and YARA signature analysis.'}
              </p>
            </div>
          )}

          <YaraRulesPanel t={t} />
        </div>
      </div>
    </Layout>
  );
}
