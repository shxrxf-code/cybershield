import { useEffect, useRef, useState } from 'react'
import { Play, Square, Upload, AlertTriangle, CheckCircle, Clock, FileScan, ShieldCheck } from 'lucide-react'
import { scanAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

export default function DeviceScanner() {
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<any>(null)
  const [scanHistory, setScanHistory] = useState<Array<{ id: number; filename: string; date: string; malicious: boolean }>>([])
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [engineStatus, setEngineStatus] = useState<{ available: boolean; message: string } | null>(null)
  const [error, setError] = useState('')
  const requestController = useRef<AbortController | null>(null)

  useEffect(() => {
    scanAPI.status()
      .then(({ data }) => setEngineStatus({
        available: Boolean(data.clamav_available),
        message: data.clamav_available ? 'ClamAV available' : 'ClamAV unavailable; signature engine will not run',
      }))
      .catch((requestError: unknown) => {
        console.error(requestError)
        setEngineStatus({ available: false, message: 'Scanner status could not be loaded' })
      })
  }, [])

  const startScan = async () => {
    if (!selectedFile || scanning) return
    const controller = new AbortController()
    requestController.current = controller
    setScanning(true)
    setResults(null)
    setError('')
    try {
      const response = await scanAPI.scanFile(selectedFile, controller.signal)
      setResults(response.data)
      setScanHistory(history => [{
        id: Date.now(),
        filename: response.data.filename,
        date: new Date().toLocaleString(),
        malicious: Boolean(response.data.is_malicious),
      }, ...history])
    } catch (requestError) {
      if (controller.signal.aborted) {
        setError('Scan request cancelled. The server may have continued processing the upload.')
      } else {
        console.error(requestError)
        setError('The file could not be scanned. Check the backend connection and try again.')
      }
    } finally {
      if (requestController.current === controller) requestController.current = null
      setScanning(false)
    }
  }

  const stopScan = () => {
    requestController.current?.abort()
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Device Scanner</h2>
          <p className="text-gray-400 text-sm">Submit a file to the configured malware analysis service.</p>
        </div>
        <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-2 text-xs text-slate-300">
          <span className={`h-2 w-2 rounded-full ${engineStatus?.available ? 'bg-sentinel-primary shadow-[0_0_9px_rgba(67,240,162,0.8)]' : 'bg-sentinel-warning'}`} />
          {engineStatus?.message || 'Checking scanner engine'}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2"><FileScan className="h-5 w-5 text-sentinel-info" />File analysis</h3>
            <div className="mb-4 rounded-xl border border-dashed border-sentinel-info/30 bg-sentinel-info/[0.035] p-5 sm:p-6">
                <label htmlFor="file-analysis-input" className="block text-sm font-medium mb-2">Choose a file</label>
                <div className="flex items-center gap-3">
                  <input
                    id="file-analysis-input"
                    type="file"
                    onChange={handleFileSelect}
                    disabled={scanning}
                    className="min-w-0 flex-1 text-sm text-gray-400 file:mr-4 file:rounded-lg file:border file:border-sentinel-border file:bg-sentinel-card file:px-4 file:py-2 file:text-sm file:text-sentinel-primary hover:file:bg-white/10"
                  />
                  <Upload className="w-5 h-5 text-gray-400" />
                </div>
                {selectedFile && (
                  <p className="text-xs text-gray-400 mt-2">Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(2)} KB)</p>
                )}
            </div>
            <p className="mb-4 text-xs leading-5 text-slate-500">System-wide quick and full scans are not available in the connected API. Only the selected file will be uploaded and scanned.</p>

            <div className="flex gap-3">
              {!scanning ? (
                <button
                  onClick={startScan}
                  disabled={!selectedFile}
                  className="flex items-center gap-2 rounded-lg bg-sentinel-primary px-5 py-2.5 font-medium text-slate-950 transition hover:bg-sentinel-primary/90 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Play className="w-4 h-4" />
                  Analyze file
                </button>
              ) : (
                <button
                  onClick={stopScan}
                  className="flex items-center gap-2 rounded-lg border border-sentinel-danger/40 bg-sentinel-danger/10 px-5 py-2.5 font-medium text-sentinel-danger transition hover:bg-sentinel-danger/20"
                >
                  <Square className="w-4 h-4" />
                  Cancel request
                </button>
              )}
            </div>
            {error && <p role="alert" className="mt-4 rounded-lg border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}

            {scanning && (
              <div role="status" className="mt-4 flex items-center gap-3 rounded-lg border border-sentinel-info/20 bg-sentinel-info/[0.05] px-4 py-3 text-sm text-slate-300">
                <LoadingSpinner compact />
                Waiting for analysis response from the backend…
              </div>
            )}
          </div>

          {results && (
            <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                {!results.is_malicious ? (
                  <CheckCircle className="w-5 h-5 text-sentinel-primary" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
                )}
                Scan Results
              </h3>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 bg-sentinel-bg rounded">
                      <div className="text-xs text-gray-400">File</div>
                      <div className="text-sm truncate">{results.filename}</div>
                    </div>
                    <div className="p-3 bg-sentinel-bg rounded">
                      <div className="text-xs text-gray-400">Status</div>
                      <div className={`text-sm font-medium ${results.is_malicious ? 'text-sentinel-danger' : 'text-sentinel-primary'}`}>
                        {results.is_malicious ? 'THREAT INDICATOR' : 'NO INDICATORS REPORTED'}
                      </div>
                    </div>
                  </div>
                  <div className="p-3 bg-sentinel-bg rounded">
                    <div className="text-xs text-gray-400 mb-1">SHA256</div>
                    <div className="text-xs font-mono break-all">{results.file_hash}</div>
                  </div>
                  {results.detections && results.detections.length > 0 && (
                    <div className="p-3 bg-sentinel-danger/10 border border-sentinel-danger/30 rounded">
                      <div className="text-sm font-medium text-sentinel-danger mb-2">Detections</div>
                      {results.detections.map((d: any, i: number) => (
                        <div key={i} className="text-xs text-gray-300 mb-1">{d.engine}: {d.output}</div>
                      ))}
                    </div>
                  )}
                  <div className="flex flex-wrap items-center gap-4 text-sm">
                    <span>Action: <StatusBadge status={results.action === 'quarantine' ? 'danger' : results.action === 'allow' ? 'ok' : 'warning'} text={results.action.toUpperCase()} /></span>
                    <span>Quarantined: {results.quarantined ? 'Yes' : 'No'}</span>
                  </div>
                  {results.risk && (
                    <div className="flex items-center gap-3 text-sm text-slate-300">
                      <span>Risk score</span><strong className="text-slate-100">{results.risk.score} / 100</strong>
                      <span className="capitalize text-slate-400">{results.risk.level}</span>
                    </div>
                  )}
                  {results.detections?.length === 0 && results.risk?.score < 40 && (
                    <div className="flex items-center gap-2 text-sm text-sentinel-primary"><ShieldCheck className="h-4 w-4" />No indicators were reported by the available checks.</div>
                  )}
                </div>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Engine Status</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">ClamAV</span>
                <StatusBadge status={engineStatus?.available ? 'active' : 'warning'} text={engineStatus ? (engineStatus.available ? 'Available' : 'Unavailable') : 'Checking'} />
              </div>
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">YARA Rules</span>
                <StatusBadge status="inactive" text="Not reported by API" />
              </div>
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">Signature DB</span>
                <StatusBadge status="inactive" text="Not reported by API" />
              </div>
            </div>
          </div>

          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5" />
              Scan History
            </h3>
            <p className="mb-3 text-xs text-slate-500">Completed uploads since this screen was opened. History is not persisted.</p>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {scanHistory.length === 0 ? <p className="py-5 text-sm text-slate-500">No files analyzed on this screen yet.</p> : scanHistory.map((scan) => (
                <div key={scan.id} className="p-3 bg-sentinel-bg rounded">
                  <div className="flex items-center justify-between mb-1">
                    <span className="truncate pr-2 text-sm font-medium">{scan.filename}</span>
                    <StatusBadge status={scan.malicious ? 'danger' : 'ok'} text={scan.malicious ? 'Threat' : 'No indicators'} />
                  </div>
                  <div className="text-xs text-gray-400 mb-1">{scan.date}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
