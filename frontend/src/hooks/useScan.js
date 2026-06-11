import { useState, useCallback } from 'react';
import { scanUrl, scanEmail, scanEmailFile, scanDocument } from '../utils/api';

/**
 * Hook for managing scan state and API calls.
 */
export function useScan() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  const performUrlScan = useCallback(async (url, followRedirects = true) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await scanUrl(url, followRedirects);
      setResult(data);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const performEmailScan = useCallback(async (emailData) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await scanEmail(emailData);
      setResult(data);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const performEmailFileScan = useCallback(async (fileOrFiles) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      if (Array.isArray(fileOrFiles)) {
        const promises = fileOrFiles.map(f => scanEmailFile(f));
        const data = await Promise.all(promises);
        setResult(data);
        return data;
      } else {
        const data = await scanEmailFile(fileOrFiles);
        setResult(data);
        return data;
      }
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const performDocumentScan = useCallback(async (fileOrFiles, password, customPasswords, wordlistFile) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      if (Array.isArray(fileOrFiles)) {
        const promises = fileOrFiles.map(f => scanDocument(f, password, customPasswords, wordlistFile));
        const data = await Promise.all(promises);
        setResult(data);
        return data;
      } else {
        const data = await scanDocument(fileOrFiles, password, customPasswords, wordlistFile);
        setResult(data);
        return data;
      }
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    loading,
    result,
    setResult,
    error,
    reset,
    performUrlScan,
    performEmailScan,
    performEmailFileScan,
    performDocumentScan,
  };
}
