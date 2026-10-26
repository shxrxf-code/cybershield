import { useEffect, useState } from 'react'
import { Package, Upload, AlertTriangle, CheckCircle, FileText, Key } from 'lucide-react'
import { apkAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

export default function APKScanner() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [history, setHistory] = useState<Array<{ id: number; name: string; score: number; malicious: boolean; time: string }>>([])
  const [serviceStatus, setServiceStatus] = useState('Checking')
  const [error, setError] = useState('')

  useEffect(() => {
    apkAPI.status()
      .then(({ data }) => setServiceStatus(data.status === 'operational' ? `Operational · ${data.full_analysis || 'analysis scope unavailable'}` : 'Unavailable'))
      .catch((requestError: unknown) => {
        console.error(requestError)
        setServiceStatus('Unavailable')
      })
  }, [])

  const selectAPK = (file: File | undefined) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('Choose an APK file.')
      setSelectedFile(null)
      return
    }
    if (file.size > 100 * 1024 * 1024) {
      setError('APK files must be 100 MB or smaller.')
      setSelectedFile(null)
      return
    }
    setError('')
    setSelectedFile(file)
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    selectAPK(e.target.files?.[0])
  }

  const scanAPK = async () => {
    if (!selectedFile || scanning) return
    setScanning(true)
    setResult(null)
    setError('')
    try {
      const response = await apkAPI.scan(selectedFile)
      setResult(response.data)
      setHistory(history => [{
        id: Date.now(),
        name: selectedFile.name,
        score: response.data.threat_score,
        malicious: Boolean(response.data.is_malicious),
        time: 'Just now'
      }, ...history])
    } catch (requestError) {
      console.error(requestError)
      setError('APK analysis failed. Check the backend connection and try again.')
    } finally {
      setScanning(false)
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">APK Scanner</h2>
        <p className="text-gray-400 text-sm">Submit an APK to the connected analysis service.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Package className="w-5 h-5" />
              Upload APK for Analysis
            </h3>
            <div
              onDragOver={event => event.preventDefault()}
              onDrop={event => { event.preventDefault(); selectAPK(event.dataTransfer.files[0]) }}
              className="border-2 border-dashed border-sentinel-info/30 rounded-xl bg-sentinel-info/[0.025] p-8 text-center mb-4 transition hover:border-sentinel-info/60"
            >
              <Upload className="w-12 h-12 mx-auto mb-4 text-gray-400" />
              <p className="text-gray-400 mb-2">Drag and drop APK file here or click to browse</p>
              <p className="text-xs text-gray-500 mb-4">Maximum file size: 100MB</p>
              <input
                type="file"
                accept=".apk"
                onChange={handleFileSelect}
                disabled={scanning}
                className="hidden"
                id="apk-upload"
              />
              <label
                htmlFor="apk-upload"
                className="px-6 py-2 bg-sentinel-card border border-sentinel-border rounded-lg cursor-pointer hover:bg-white/10 transition-colors inline-block"
              >
                Select APK File
              </label>
            </div>
            {error && <p role="alert" className="mb-4 rounded-lg border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
            {selectedFile && (
              <div className="p-4 bg-sentinel-bg rounded mb-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <Package className="w-8 h-8 text-sentinel-primary" />
                    <div>
                      <p className="font-medium">{selectedFile.name}</p>
                      <p className="text-sm text-gray-400">{formatFileSize(selectedFile.size)}</p>
                    </div>
                  </div>
                  <button
                    onClick={scanAPK}
                    disabled={scanning}
                    className="px-6 py-2 bg-sentinel-primary text-black font-medium rounded hover:bg-sentinel-primary/90 transition-colors disabled:opacity-50"
                  >
                    {scanning ? 'Analyzing...' : 'Analyze APK'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {result && (
            <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                {result.is_malicious ? (
                  <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-sentinel-primary" />
                )}
                Analysis Report
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className={`text-2xl font-bold ${result.threat_score >= 70 ? 'text-sentinel-danger' : result.threat_score >= 40 ? 'text-sentinel-warning' : 'text-sentinel-primary'}`}>
                    {result.threat_score}
                  </div>
                  <div className="text-xs text-gray-400">Threat Score</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className={`text-sm font-medium ${result.is_malicious ? 'text-sentinel-danger' : 'text-sentinel-primary'}`}>
                  {result.is_malicious ? 'THREAT INDICATOR' : 'NO INDICATOR'}
                  </div>
                  <div className="text-xs text-gray-400">Verdict</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className="text-sm font-medium">{result.permissions?.length || 0}</div>
                  <div className="text-xs text-gray-400">Permissions</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className="text-sm font-medium">{result.dangerous_permissions?.length || 0}</div>
                  <div className="text-xs text-gray-400">Dangerous</div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="p-4 bg-sentinel-bg rounded">
                  <div className="text-sm font-medium mb-2 flex items-center gap-2">
                    <FileText className="w-4 h-4" />
                    File Information
                  </div>
                  <div className="grid grid-cols-1 gap-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Filename</span>
                      <span className="truncate max-w-xs">{result.filename}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">SHA256</span>
                      <span className="font-mono text-xs truncate max-w-xs">{result.apk_hash}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Size</span>
                      <span>{formatFileSize(result.size_bytes)}</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-sentinel-bg rounded">
                  <div className="text-sm font-medium mb-2 flex items-center gap-2">
                    <Key className="w-4 h-4" />
                    Static Analysis
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Manifest Analysis</span>
                      <StatusBadge status="warning" text={result.analysis?.manifest_analysis || 'Pending'} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Certificate Analysis</span>
                      <StatusBadge status="warning" text={result.analysis?.certificate_analysis || 'Pending'} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Code Inspection</span>
                      <StatusBadge status="warning" text="Pending" />
                    </div>
                  </div>
                  {result.analysis?.note && (
                    <p className="text-xs text-gray-500 mt-2">{result.analysis.note}</p>
                  )}
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className="p-4 bg-sentinel-danger/10 border border-sentinel-danger/30 rounded">
                    <div className="text-sm font-medium text-sentinel-danger mb-2">Threat Indicators</div>
                    <ul className="space-y-1">
                      {result.reasons.map((reason: string, i: number) => (
                        <li key={i} className="text-sm text-gray-300">• {reason}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Analysis service</h3>
            <p className="text-sm text-slate-400">Backend status</p>
            <p className="mt-2 text-sm text-sentinel-info">{serviceStatus}</p>
            <p className="mt-3 text-xs leading-5 text-slate-500">The current endpoint reports partial analysis. A response without indicators is not a guarantee that an APK is safe.</p>
          </div>

          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
            <div className="space-y-2">
              {history.length === 0 ? <p className="py-4 text-sm text-slate-500">No APKs analyzed on this screen yet.</p> : history.map((item) => (
                <div key={item.id} className="p-3 bg-sentinel-bg rounded">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium truncate max-w-[150px]">{item.name}</span>
                    <StatusBadge status={item.malicious ? 'danger' : 'ok'} text={item.malicious ? 'INDICATOR' : 'NO INDICATOR'} />
                  </div>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>Score: {item.score}</span>
                    <span>{item.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
