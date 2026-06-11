import React, { useState, useEffect } from 'react';

/**
 * YaraRulesPanel manages dynamic YARA rules uploading and compilation monitoring.
 */
export default function YaraRulesPanel({ t }) {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [expandedRule, setExpandedRule] = useState(null);

  const isEs = t?.scan_button === 'Escanear';

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/scan/yara/rules');
      if (!response.ok) {
        throw new Error(isEs ? 'Error al obtener las reglas YARA' : 'Failed to fetch YARA rules');
      }
      const data = await response.json();
      setRules(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.yar') && !file.name.endsWith('.yara')) {
      setError(isEs ? 'Sólo se permiten archivos .yar o .yara' : 'Only .yar or .yara files are supported');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/scan/yara/rules', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || (isEs ? 'Error al subir la regla YARA' : 'Failed to upload YARA rule'));
      }

      setSuccessMsg(isEs ? 'Firma YARA compilada exitosamente' : 'YARA rule uploaded and compiled successfully');
      fetchRules();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRule = async (filename) => {
    if (!window.confirm(isEs ? `¿Seguro que deseas eliminar la regla '${filename}'?` : `Are you sure you want to delete '${filename}'?`)) {
      return;
    }

    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const response = await fetch(`/api/scan/yara/rules/${filename}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || (isEs ? 'Error al eliminar la regla' : 'Failed to delete YARA rule'));
      }

      setSuccessMsg(isEs ? 'Regla eliminada del motor' : 'YARA rule successfully removed');
      fetchRules();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      marginTop: '32px',
      background: 'rgba(7, 10, 19, 0.4)',
      border: '1px solid var(--border-primary)',
      borderRadius: 'var(--radius-md)',
      padding: '24px',
      boxShadow: 'var(--shadow-border)',
      textAlign: 'left'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            🛡️ {isEs ? 'Gestor Dinámico de Firmas YARA' : 'Dynamic YARA Signatures Manager'}
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {isEs ? 'Carga y compila nuevas reglas estáticas localmente' : 'Upload and compile custom rule blocks offline'}
          </span>
        </div>
        <div>
          <label className="btn btn--primary" style={{ fontSize: '11px', padding: '6px 12px', cursor: 'pointer', height: '28px', textTransform: 'none' }}>
            ➕ {isEs ? 'Subir Regla' : 'Upload Rule'}
            <input type="file" accept=".yar,.yara" onChange={handleFileUpload} style={{ display: 'none' }} />
          </label>
        </div>
      </div>

      {error && (
        <div style={{
          padding: '10px 14px',
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '4px',
          color: 'var(--risk-high)',
          fontSize: '12px',
          marginBottom: '16px'
        }}>
          ❌ {error}
        </div>
      )}

      {successMsg && (
        <div style={{
          padding: '10px 14px',
          background: 'rgba(16, 185, 129, 0.1)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '4px',
          color: 'var(--risk-low)',
          fontSize: '12px',
          marginBottom: '16px'
        }}>
          🟢 {successMsg}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {rules.map((rule, idx) => {
          const isOpen = expandedRule === rule.filename;
          return (
            <div key={idx} style={{
              background: 'rgba(2, 6, 23, 0.4)',
              border: `1px solid ${rule.is_builtin ? 'rgba(6, 182, 212, 0.15)' : 'rgba(217, 70, 239, 0.15)'}`,
              borderRadius: '6px',
              overflow: 'hidden'
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 16px',
                background: rule.is_builtin ? 'rgba(6, 182, 212, 0.04)' : 'rgba(217, 70, 239, 0.04)',
                borderBottom: isOpen ? '1px solid rgba(255, 255, 255, 0.03)' : 'none'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span
                    style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
                    onClick={() => setExpandedRule(isOpen ? null : rule.filename)}
                  >
                    📄 {rule.filename}
                  </span>
                  <span style={{
                    fontSize: '9px',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    textTransform: 'uppercase',
                    background: rule.is_builtin ? 'rgba(6, 182, 212, 0.15)' : 'rgba(217, 70, 239, 0.15)',
                    color: rule.is_builtin ? 'var(--cyan)' : 'var(--violet)',
                    border: `1px solid ${rule.is_builtin ? 'rgba(6, 182, 212, 0.25)' : 'rgba(217, 70, 239, 0.25)'}`
                  }}>
                    {rule.is_builtin ? (isEs ? 'Sistema' : 'System') : (isEs ? 'Personalizada' : 'Custom')}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <button
                    type="button"
                    className="btn btn--secondary"
                    onClick={() => setExpandedRule(isOpen ? null : rule.filename)}
                    style={{ padding: '4px 10px', fontSize: '10px', height: '24px', textTransform: 'none', borderRadius: '4px' }}
                  >
                    {isOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Inspeccionar' : 'Inspect')}
                  </button>
                  {!rule.is_builtin && (
                    <button
                      type="button"
                      className="btn"
                      onClick={() => handleDeleteRule(rule.filename)}
                      style={{
                        padding: '4px 8px',
                        fontSize: '10px',
                        height: '24px',
                        borderRadius: '4px',
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.25)',
                        color: 'var(--risk-high)',
                        cursor: 'pointer'
                      }}
                    >
                      🗑️
                    </button>
                  )}
                </div>
              </div>

              {isOpen && (
                <div style={{ padding: '14px 16px', background: '#020617' }}>
                  <pre style={{
                    margin: 0,
                    padding: '12px 14px',
                    background: '#090d16',
                    color: '#a78bfa',
                    border: '1px solid rgba(255, 255, 255, 0.03)',
                    borderRadius: '4px',
                    fontSize: '11px',
                    lineHeight: '1.5',
                    fontFamily: 'var(--font-mono)',
                    whiteSpace: 'pre-wrap',
                    maxHeight: '300px',
                    overflowY: 'auto'
                  }}>
                    {rule.content}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
