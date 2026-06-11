import React, { useRef, useState } from 'react';

/**
 * Drag-and-drop file upload component.
 */
export default function FileUpload({ onFileSelect, t, accept, multiple }) {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const inputRef = useRef(null);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      const selected = multiple ? files : [files[0]];
      setSelectedFiles(selected);
      onFileSelect(multiple ? selected : selected[0]);
    }
  };

  const handleChange = (e) => {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
      const selected = multiple ? files : [files[0]];
      setSelectedFiles(selected);
      onFileSelect(multiple ? selected : selected[0]);
    }
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  return (
    <div
      className={`file-upload ${dragOver ? 'file-upload--dragover' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      id="file-upload-area"
    >
      <div className="file-upload__icon">📁</div>
      <div className="file-upload__text">
        {t?.file_upload_text || 'Drag & drop a file here, or click to browse'}
      </div>
      <div className="file-upload__hint">
        {t?.file_upload_hint || 'Supports: PDF, Office, RTF, ZIP, SQL, Scripts (Py, PS1, Sh, Bat, Cmd), DLL, EXE'}
      </div>
      {selectedFiles.length > 0 && (
        <div className="file-upload__selected" style={{ marginTop: '12px', textAlign: 'left', display: 'inline-block' }}>
          {selectedFiles.map((file, idx) => (
            <div key={idx} style={{ marginTop: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              📎 {file.name} ({formatSize(file.size)})
            </div>
          ))}
        </div>
      )}
      <input
        ref={inputRef}
        type="file"
        multiple={multiple}
        accept={accept || ".pdf,.docx,.xlsx,.pptx,.doc,.xls,.ppt,.rtf,.zip,.sql,.py,.html,.htm,.txt,.xlsm,.xlm,.sh,.ps1,.ps,.bat,.cmd,.dll,.exe"}
        onChange={handleChange}
        style={{ display: 'none' }}
        id="file-input"
      />
    </div>
  );
}
