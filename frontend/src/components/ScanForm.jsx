import React, { useState, useRef } from 'react';
import FileUpload from './FileUpload';

/**
 * Tabbed scan input form (URL / Email / Document).
 * Email tab supports both file upload (.eml/.msg) and manual input.
 * Document tab supports wordlist file upload (.txt).
 */
export default function ScanForm({ onUrlScan, onEmailScan, onEmailFileScan, onDocScan, loading, t }) {
  const [tab, setTab] = useState('url');

  // URL state
  const [url, setUrl] = useState('');

  // Email state
  const [emailFiles, setEmailFiles] = useState([]);

  // Document state
  const [files, setFiles] = useState([]);
  const [docPassword, setDocPassword] = useState('');
  const [customPasswords, setCustomPasswords] = useState('');
  const [wordlistFile, setWordlistFile] = useState(null);
  const wordlistRef = useRef(null);

  const [runThirdParty, setRunThirdParty] = useState(
    localStorage.getItem('vk_run_third_party') === 'true'
  );
  const [vtKey, setVtKey] = useState(localStorage.getItem('vk_virustotal_key') || '');
  const [urlscanKey, setUrlscanKey] = useState(localStorage.getItem('vk_urlscan_key') || '');
  const [abuseKey, setAbuseKey] = useState(localStorage.getItem('vk_abuseipdb_key') || '');

  const [showVt, setShowVt] = useState(false);
  const [showUrlscan, setShowUrlscan] = useState(false);
  const [showAbuse, setShowAbuse] = useState(false);

  const [isOpen, setIsOpen] = useState(false);

  const handleToggleThirdParty = (val) => {
    setRunThirdParty(val);
    localStorage.setItem('vk_run_third_party', val ? 'true' : 'false');
  };

  const handleVtChange = (val) => {
    setVtKey(val);
    localStorage.setItem('vk_virustotal_key', val);
  };

  const handleUrlscanChange = (val) => {
    setUrlscanKey(val);
    localStorage.setItem('vk_urlscan_key', val);
  };

  const handleAbuseChange = (val) => {
    setAbuseKey(val);
    localStorage.setItem('vk_abuseipdb_key', val);
  };

  const handleUrlSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) onUrlScan(url.trim());
  };

  const handleEmailSubmit = (e) => {
    e.preventDefault();
    if (emailFiles && emailFiles.length > 0) {
      onEmailFileScan(emailFiles);
    }
  };

  const handleDocSubmit = (e) => {
    e.preventDefault();
    if (files && files.length > 0) onDocScan(files, docPassword || null, customPasswords || null, wordlistFile);
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  return (
    <div>
      {/* Tabs */}
      <div className="tabs" id="scan-tabs">
        <button
          className={`tabs__btn ${tab === 'url' ? 'tabs__btn--active' : ''}`}
          onClick={() => setTab('url')}
          id="tab-url"
        >
          {t?.tab_url || '🔗 URL Scan'}
        </button>
        <button
          className={`tabs__btn ${tab === 'email' ? 'tabs__btn--active' : ''}`}
          onClick={() => setTab('email')}
          id="tab-email"
        >
          {t?.tab_email || '📧 Email Scan'}
        </button>
        <button
          className={`tabs__btn ${tab === 'document' ? 'tabs__btn--active' : ''}`}
          onClick={() => setTab('document')}
          id="tab-document"
        >
          {t?.tab_document || '📄 Document Scan'}
        </button>
      </div>

      {/* Collapsible API keys and OPSEC configuration */}
      <div className="card" style={{ marginBottom: '24px', padding: '16px 24px' }}>
        <div 
          onClick={() => setIsOpen(!isOpen)} 
          style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            cursor: 'pointer',
            userSelect: 'none'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '18px' }}>⚙️</span>
            <span style={{ fontWeight: '700', fontSize: '14px', letterSpacing: '0.5px', textTransform: 'uppercase', color: 'var(--cyan)' }}>
              {t?.title === 'VK Scanner' && t?.scan_button === 'Escanear' ? 'FEEDS DE INTELIGENCIA EXTERNOS (OPCIONAL)' : 'EXTERNAL INTEL FEEDS (OPTIONAL)'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span 
              className={`badge ${runThirdParty ? 'badge--high' : 'badge--info'}`} 
              style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase' }}
            >
              {runThirdParty 
                ? (t?.title === 'VK Scanner' && t?.scan_button === 'Escanear' ? 'Conectado' : 'ON (External)') 
                : (t?.title === 'VK Scanner' && t?.scan_button === 'Escanear' ? 'Solo Local' : 'OFF (Local Only)')}
            </span>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{isOpen ? '▲' : '▼'}</span>
          </div>
        </div>

        {isOpen && (
          <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-primary)', paddingTop: '16px' }}>
            <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <input 
                id="run-third-party-toggle" 
                type="checkbox" 
                checked={runThirdParty} 
                onChange={(e) => handleToggleThirdParty(e.target.checked)} 
                style={{ width: '18px', height: '18px', cursor: 'pointer' }}
              />
              <label htmlFor="run-third-party-toggle" style={{ fontWeight: '600', fontSize: '13px', cursor: 'pointer' }}>
                {t?.title === 'VK Scanner' && t?.scan_button === 'Escanear'
                  ? '🔌 Habilitar Consultas a Feeds Externos (VT, URLScan, AbuseIPDB)' 
                  : '🔌 Enable External Threat Feeds (VT, URLScan, AbuseIPDB)'}
              </label>
            </div>

            {runThirdParty && (
              <div style={{
                background: 'rgba(244, 63, 94, 0.1)',
                border: '1px solid rgba(244, 63, 94, 0.3)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 16px',
                marginBottom: '16px',
                fontSize: '12px',
                color: '#fda4af'
              }}>
                <strong>⚠️ {t?.title === 'VK Scanner' && t?.scan_button === 'Escanear' ? 'ALERTA OPSEC:' : 'OPSEC WARNING:'}</strong>{' '}
                {t?.title === 'VK Scanner' && t?.scan_button === 'Escanear'
                  ? 'Habilitar consultas externas enviará los hashes de archivos, URLs o IPs detectadas en correos a plataformas de terceros (VirusTotal, urlscan.io, AbuseIPDB) en internet. Esto puede revelar información del archivo analizado.' 
                  : 'Enabling external checks will transmit file hashes, URLs, and email public IPs to public threat databases (VirusTotal, urlscan.io, AbuseIPDB) over the internet. This could expose target metadata.'}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              {/* VirusTotal Key */}
              <div className="form-group" style={{ position: 'relative' }}>
                <label className="form-group__label" style={{ fontSize: '12px' }}>VirusTotal API Key</label>
                <div style={{ position: 'relative' }}>
                  <input 
                    className="form-group__input" 
                    style={{ paddingRight: '40px' }}
                    type={showVt ? 'text' : 'password'} 
                    value={vtKey} 
                    onChange={(e) => handleVtChange(e.target.value)} 
                    placeholder="e.g. abcd1234..."
                  />
                  <button 
                    type="button" 
                    onClick={() => setShowVt(!showVt)} 
                    style={{
                      position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '14px'
                    }}
                  >
                    {showVt ? '👁️' : '🕶️'}
                  </button>
                </div>
              </div>

              {/* URLScan.io Key */}
              <div className="form-group" style={{ position: 'relative' }}>
                <label className="form-group__label" style={{ fontSize: '12px' }}>URLScan.io API Key</label>
                <div style={{ position: 'relative' }}>
                  <input 
                    className="form-group__input" 
                    style={{ paddingRight: '40px' }}
                    type={showUrlscan ? 'text' : 'password'} 
                    value={urlscanKey} 
                    onChange={(e) => handleUrlscanChange(e.target.value)} 
                    placeholder="e.g. xxxx-yyyy-zzzz..."
                  />
                  <button 
                    type="button" 
                    onClick={() => setShowUrlscan(!showUrlscan)} 
                    style={{
                      position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '14px'
                    }}
                  >
                    {showUrlscan ? '👁️' : '🕶️'}
                  </button>
                </div>
              </div>

              {/* AbuseIPDB Key */}
              <div className="form-group" style={{ position: 'relative' }}>
                <label className="form-group__label" style={{ fontSize: '12px' }}>AbuseIPDB API Key</label>
                <div style={{ position: 'relative' }}>
                  <input 
                    className="form-group__input" 
                    style={{ paddingRight: '40px' }}
                    type={showAbuse ? 'text' : 'password'} 
                    value={abuseKey} 
                    onChange={(e) => handleAbuseChange(e.target.value)} 
                    placeholder="e.g. 80-char-key..."
                  />
                  <button 
                    type="button" 
                    onClick={() => setShowAbuse(!showAbuse)} 
                    style={{
                      position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '14px'
                    }}
                  >
                    {showAbuse ? '👁️' : '🕶️'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* URL Form */}
      {tab === 'url' && (
        <form className="scan-form" onSubmit={handleUrlSubmit} id="url-form">
          <div className="form-group">
            <label className="form-group__label" htmlFor="url-input">
              {t?.url_label || 'URL to Analyze'}
            </label>
            <input
              className="form-group__input"
              id="url-input"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={t?.url_placeholder || 'https://suspicious-site.example.com/login'}
              required
            />
          </div>
          <button className="btn btn--primary" type="submit" disabled={loading || !url.trim()} id="scan-url-btn">
            {loading ? <><span className="spinner" /> {t?.scanning || 'Analyzing...'}</> : (t?.scan_button || 'Scan Now')}
          </button>
        </form>
      )}

      {/* Email Form */}
      {tab === 'email' && (
        <form className="scan-form" onSubmit={handleEmailSubmit} id="email-form">
          <div className="form-group">
            <FileUpload
              multiple={true}
              onFileSelect={setEmailFiles}
              t={{
                file_upload_text: t?.email_file_upload_text || 'Drag & drop .eml or .msg files here',
                file_upload_hint: t?.email_file_upload_hint || 'Supports: .eml (RFC 822), .msg (Outlook) · Upload multiple files',
              }}
              accept=".eml,.msg"
            />
          </div>
          <button className="btn btn--primary" type="submit" disabled={loading || emailFiles.length === 0} id="scan-email-file-btn">
            {loading ? <><span className="spinner" /> {t?.scanning || 'Analyzing...'}</> : (t?.scan_button || 'Scan Now')}
          </button>
        </form>
      )}

      {/* Document Form */}
      {tab === 'document' && (
        <form className="scan-form" onSubmit={handleDocSubmit} id="document-form">
          <div className="form-group">
            <FileUpload multiple={true} onFileSelect={setFiles} t={t} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div className="form-group">
              <label className="form-group__label">{t?.password_label || 'Document Password (optional)'}</label>
              <input className="form-group__input" type="password" value={docPassword}
                onChange={e => setDocPassword(e.target.value)}
                placeholder={t?.password_placeholder || 'Enter password if protected'} />
            </div>
            <div className="form-group">
              <label className="form-group__label">{t?.custom_passwords_label || 'Custom Passwords (comma-separated)'}</label>
              <input className="form-group__input" value={customPasswords}
                onChange={e => setCustomPasswords(e.target.value)}
                placeholder={t?.custom_passwords_placeholder || 'pass1, pass2, secret123...'} />
            </div>
          </div>

          {/* Wordlist file upload */}
          <div className="form-group">
            <label className="form-group__label">
              📄 {t?.wordlist_label || 'Wordlist File (.txt)'}
            </label>
            <div
              className={`file-upload`}
              onClick={() => wordlistRef.current?.click()}
              style={{ padding: '20px', cursor: 'pointer' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', justifyContent: 'center' }}>
                <span style={{ fontSize: '24px' }}>📋</span>
                <div>
                  <div className="file-upload__text" style={{ fontSize: '13px' }}>
                     {t?.wordlist_upload_text || 'Upload a wordlist file (e.g. rockyou.txt)'}
                  </div>
                  <div className="file-upload__hint">
                    {t?.wordlist_upload_hint || 'One password per line · .txt format'}
                  </div>
                </div>
              </div>
              {wordlistFile && (
                <div className="file-upload__selected" style={{ marginTop: '8px' }}>
                  📋 {wordlistFile.name} ({formatSize(wordlistFile.size)})
                </div>
              )}
              <input
                ref={wordlistRef}
                type="file"
                accept=".txt"
                onChange={(e) => setWordlistFile(e.target.files[0] || null)}
                style={{ display: 'none' }}
                id="wordlist-input"
              />
            </div>
          </div>

          <button className="btn btn--primary" type="submit" disabled={loading || files.length === 0} id="scan-doc-btn">
            {loading ? <><span className="spinner" /> {t?.scanning || 'Analyzing...'}</> : (t?.scan_button || 'Scan Now')}
          </button>
        </form>
      )}
    </div>
  );
}
