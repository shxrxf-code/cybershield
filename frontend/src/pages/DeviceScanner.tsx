import { useEffect, useRef, useState, DragEvent } from 'react'
import {
  Shield, Upload, FileText, CheckCircle2, AlertTriangle, ShieldAlert,
  RefreshCw, Trash2, Search, X, FileScan, Cpu, Database,
  ArrowRight, ShieldCheck, Copy, Check, AlertOctagon, Terminal
} from 'lucide-react'
import { scanAPI } from '../lib/api'

interface EngineInfo {
  status: 'Available' | 'Unavailable' | 'Initializing' | 'Error' | 'Not configured' | 'Unknown'
  version?: string
  rules_count?: number
  active_signatures?: number
  detail: string
  path?: string
  rules_file?: string
  database_path?: string
}

interface EngineHealthResponse {
  timestamp: string
  clamav: EngineInfo
  yara: EngineInfo
  signature_db: EngineInfo
  overall_status: string
}

interface ScanRecord {
  id: string
  filename: string
  file_hash: string
  md5?: string
  size_bytes: number
  entropy?: number
  scan_engine?: string
  scan_engines?: string[]
  is_malicious: boolean
  status: 'CLEAN' | 'INFECTED' | 'SUSPICIOUS' | 'ERROR'
  threat_name?: string
  threat_severity: 'low' | 'moderate' | 'high' | 'critical' | 'severe'
  duration_ms: number
  recommended_action?: string
  detections: Array<{ engine?: string; threat_name?: string; output?: string; severity?: string; description?: string }>
  risk_score: number
  action: string
  scanned_at: string
}

export default function DeviceScanner() {
  // File upload state
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)

  // Scan state machine: 'idle' | 'selected' | 'uploading' | 'analyzing' | 'completed' | 'failed'
  const [scanState, setScanState] = useState<'idle' | 'selected' | 'uploading' | 'analyzing' | 'completed' | 'failed'>('idle')
  const [currentResult, setCurrentResult] = useState<ScanRecord | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  // Engine diagnostics
  const [engineHealth, setEngineHealth] = useState<EngineHealthResponse | null>(null)
  const [refreshingHealth, setRefreshingHealth] = useState(false)

  // Scan history & search/filtering
  const [historyItems, setHistoryItems] = useState<ScanRecord[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CLEAN' | 'INFECTED' | 'SUSPICIOUS'>('ALL')
  const [selectedHistoryReport, setSelectedHistoryReport] = useState<ScanRecord | null>(null)
  const [confirmClearOpen, setConfirmClearOpen] = useState(false)

  const [copiedHash, setCopiedHash] = useState(false)
  const requestController = useRef<AbortController | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB

  // 1. Fetch Engine Health
  const loadEngineHealth = async (isRefresh = false) => {
    if (isRefresh) setRefreshingHealth(true)
    try {
      const res = isRefresh ? await scanAPI.refreshStatus() : await scanAPI.status()
      setEngineHealth(res.data)
    } catch (err) {
      console.error('Failed to load engine health diagnostics', err)
    } finally {
      if (isRefresh) setRefreshingHealth(false)
    }
  }

  // 2. Fetch Persistent Scan History
  const loadScanHistory = async () => {
    setHistoryLoading(true)
    try {
      const res = await scanAPI.history({
        search: searchQuery || undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        limit: 100
      })
      setHistoryItems(res.data.items || [])
    } catch (err) {
      console.error('Failed to retrieve persistent scan history', err)
    } finally {
      setHistoryLoading(false)
    }
  }

  useEffect(() => {
    loadEngineHealth(false)
  }, [])

  useEffect(() => {
    loadScanHistory()
  }, [searchQuery, statusFilter])

  // Handle Drag & Drop
  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processSelectedFile(e.dataTransfer.files[0])
    }
  }

  const handleFilePickerChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processSelectedFile(e.target.files[0])
    }
  }

  const processSelectedFile = (file: File) => {
    setValidationError(null)
    setErrorMsg(null)

    if (file.size === 0) {
      setValidationError('The selected file is empty (0 bytes).')
      return
    }
    if (file.size > MAX_FILE_SIZE) {
      setValidationError(`File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the maximum allowed limit of 50 MB.`)
      return
    }

    setSelectedFile(file)
    setScanState('selected')
    setCurrentResult(null)
  }

  const handleRemoveFile = () => {
    setSelectedFile(null)
    setScanState('idle')
    setValidationError(null)
    setCurrentResult(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  // Execute Analysis
  const handleStartScan = async () => {
    if (!selectedFile || scanState === 'uploading' || scanState === 'analyzing') return

    const controller = new AbortController()
    requestController.current = controller
    setScanState('uploading')
    setErrorMsg(null)
    setCurrentResult(null)

    // Stage indicator transition
    const analyzeTimer = setTimeout(() => {
      setScanState('analyzing')
    }, 450)

    try {
      const response = await scanAPI.scanFile(selectedFile, controller.signal)
      clearTimeout(analyzeTimer)
      setCurrentResult(response.data)
      setScanState('completed')
      loadScanHistory()
    } catch (err: any) {
      clearTimeout(analyzeTimer)
      if (controller.signal.aborted) {
        setErrorMsg('Malware analysis cancelled by user.')
      } else {
        setErrorMsg(err.response?.data?.detail || err.message || 'File analysis failed. Ensure backend engine is online.')
      }
      setScanState('failed')
    } finally {
      requestController.current = null
    }
  }

  const handleCancelScan = () => {
    requestController.current?.abort()
    setScanState('idle')
  }

  const handleClearHistory = async () => {
    try {
      await scanAPI.clearHistory()
      setConfirmClearOpen(false)
      loadScanHistory()
    } catch (err) {
      console.error('Failed to clear scan history', err)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="space-y-6">
      {/* Top Header Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-[#00f0ff]">
            <Shield className="h-4 w-4 text-[#00f0ff]" />
            <span>Module B / Antivirus Core</span>
          </div>
          <h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
            Device Security Scanner
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            Multi-engine payload analysis combining ClamAV signature verification, YARA rules, and Shannon entropy heuristics.
          </p>
        </div>

        {/* Global Connection Badge */}
        <div className="flex items-center gap-2 rounded-xl border border-[#00f0ff]/20 bg-[#00f0ff]/[0.05] px-4 py-2 text-xs backdrop-blur-md">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#43f0a2] opacity-75" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#43f0a2]" />
          </span>
          <span className="font-semibold text-slate-200">
            {engineHealth?.overall_status === 'operational' ? 'Defense Core Active' : 'Checking Engines...'}
          </span>
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* LEFT / MAIN (2 Cols): File Analysis */}
        <div className="space-y-6 xl:col-span-2">
          {/* Glassmorphic Upload Card */}
          <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-[#0e1626]/80 to-[#070a10]/90 p-6 shadow-2xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
              <div className="flex items-center gap-2.5">
                <div className="grid h-8 w-8 place-items-center rounded-lg border border-[#00f0ff]/30 bg-[#00f0ff]/10 text-[#00f0ff]">
                  <FileScan className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold tracking-wide text-white">Target Payload Analysis</h3>
                  <p className="text-[11px] text-slate-400">Upload executable, document, script, or archive for multi-engine verification</p>
                </div>
              </div>
              <span className="text-[11px] font-mono text-slate-500">Max size: 50 MB</span>
            </div>

            {/* Drag & Drop Area */}
            {!selectedFile ? (
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`mt-5 flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 text-center transition duration-200 ${
                  isDragging
                    ? 'border-[#00f0ff] bg-[#00f0ff]/[0.08] shadow-[0_0_25px_rgba(0,240,255,0.15)]'
                    : 'border-white/15 bg-black/20 hover:border-[#00f0ff]/50 hover:bg-white/[0.02]'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFilePickerChange}
                  className="hidden"
                />
                <div className="grid h-14 w-14 place-items-center rounded-2xl border border-[#00f0ff]/20 bg-[#00f0ff]/[0.08] text-[#00f0ff] shadow-[0_0_20px_rgba(0,240,255,0.1)]">
                  <Upload className="h-7 w-7" />
                </div>
                <p className="mt-4 text-sm font-semibold text-slate-200">
                  Drag and drop files here, or <span className="text-[#00f0ff] underline underline-offset-4">Browse Local Storage</span>
                </p>
                <p className="mt-1.5 text-xs text-slate-400">
                  Supports binaries (.exe, .elf), scripts (.sh, .ps1, .vbs), docs (.pdf, .docx), archives, & EICAR test samples
                </p>
              </div>
            ) : (
              /* Selected File Details Box */
              <div className="mt-5 rounded-xl border border-[#00f0ff]/25 bg-[#00f0ff]/[0.04] p-4 backdrop-blur-md">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3">
                    <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-white/10 bg-black/40 text-[#00f0ff]">
                      <FileText className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-bold text-white">{selectedFile.name}</p>
                      <p className="text-xs text-slate-400">
                        {formatBytes(selectedFile.size)} • {selectedFile.type || 'Binary / Unspecified'}
                      </p>
                    </div>
                  </div>

                  {/* Actions: Replace / Remove */}
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={scanState === 'uploading' || scanState === 'analyzing'}
                      onClick={() => fileInputRef.current?.click()}
                      className="rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:bg-white/[0.08] disabled:opacity-40"
                    >
                      Replace File
                    </button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      onChange={handleFilePickerChange}
                      className="hidden"
                    />
                    <button
                      type="button"
                      disabled={scanState === 'uploading' || scanState === 'analyzing'}
                      onClick={handleRemoveFile}
                      className="rounded-lg border border-red-500/20 bg-red-500/10 p-1.5 text-red-400 transition hover:bg-red-500/20 disabled:opacity-40"
                      title="Remove file"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Scan Action & Animation */}
                <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-white/[0.06] pt-4">
                  {scanState !== 'uploading' && scanState !== 'analyzing' ? (
                    <button
                      type="button"
                      onClick={handleStartScan}
                      className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#00f0ff] to-[#43f0a2] px-6 py-2.5 text-xs font-bold uppercase tracking-wider text-slate-950 shadow-[0_0_20px_rgba(0,240,255,0.3)] transition hover:brightness-110 active:scale-[0.98]"
                    >
                      <FileScan className="h-4 w-4" />
                      Execute Malware Scan
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={handleCancelScan}
                      className="inline-flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-2.5 text-xs font-bold uppercase tracking-wider text-red-300 transition hover:bg-red-500/20"
                    >
                      <AlertOctagon className="h-4 w-4" />
                      Abort Analysis
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Validation / Execution Errors */}
            {validationError && (
              <div className="mt-4 flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                <span>{validationError}</span>
              </div>
            )}

            {errorMsg && (
              <div className="mt-4 flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
                <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Live Scan State Progression Indicator */}
            {(scanState === 'uploading' || scanState === 'analyzing') && (
              <div className="mt-5 rounded-xl border border-[#00f0ff]/20 bg-[#00f0ff]/[0.03] p-4">
                <div className="flex items-center justify-between text-xs text-slate-300">
                  <span className="flex items-center gap-2 font-semibold">
                    <RefreshCw className="h-3.5 w-3.5 animate-spin text-[#00f0ff]" />
                    {scanState === 'uploading'
                      ? 'Securely staging payload in sandbox memory...'
                      : 'Running ClamAV signatures & YARA bytecode engines...'}
                  </span>
                  <span className="font-mono text-[#00f0ff] uppercase">{scanState}</span>
                </div>
                <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-black/40">
                  <div className="h-full w-2/3 animate-[pulse_1s_ease-in-out_infinite] rounded-full bg-gradient-to-r from-[#00f0ff] to-[#43f0a2]" />
                </div>
              </div>
            )}
          </div>

          {/* Holographic Scan Report Card */}
          {currentResult && (
            <div className={`relative overflow-hidden rounded-2xl border p-6 shadow-2xl backdrop-blur-xl ${
              currentResult.status === 'INFECTED'
                ? 'border-red-500/40 bg-gradient-to-b from-red-950/20 to-[#070a10]/95 shadow-[0_0_30px_rgba(255,51,102,0.15)]'
                : currentResult.status === 'SUSPICIOUS'
                ? 'border-amber-500/40 bg-gradient-to-b from-amber-950/20 to-[#070a10]/95 shadow-[0_0_30px_rgba(245,158,11,0.15)]'
                : 'border-[#43f0a2]/30 bg-gradient-to-b from-emerald-950/20 to-[#070a10]/95 shadow-[0_0_30px_rgba(67,240,162,0.1)]'
            }`}>
              {/* Report Header */}
              <div className="flex flex-col gap-3 border-b border-white/[0.08] pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  <div className={`grid h-10 w-10 place-items-center rounded-xl border ${
                    currentResult.status === 'INFECTED'
                      ? 'border-red-500/40 bg-red-500/10 text-red-400'
                      : currentResult.status === 'SUSPICIOUS'
                      ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                      : 'border-[#43f0a2]/30 bg-[#43f0a2]/10 text-[#43f0a2]'
                  }`}>
                    {currentResult.status === 'INFECTED' ? (
                      <AlertTriangle className="h-5 w-5" />
                    ) : currentResult.status === 'SUSPICIOUS' ? (
                      <ShieldAlert className="h-5 w-5" />
                    ) : (
                      <CheckCircle2 className="h-5 w-5" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-base font-extrabold tracking-wide ${
                        currentResult.status === 'INFECTED' ? 'text-red-400' : currentResult.status === 'SUSPICIOUS' ? 'text-amber-400' : 'text-[#43f0a2]'
                      }`}>
                        VERDICT: {currentResult.status}
                      </span>
                      <span className="rounded-full bg-white/10 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                        {currentResult.duration_ms} ms
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{currentResult.filename}</p>
                  </div>
                </div>

                {/* Recommended Action Badge */}
                <div className="text-right">
                  <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 text-xs font-bold uppercase tracking-wider ${
                    currentResult.action === 'quarantine'
                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                      : currentResult.action === 'warn'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  }`}>
                    Action: {currentResult.action}
                  </span>
                </div>
              </div>

              {/* Threat Details Grid */}
              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Threat Signature</p>
                  <p className="mt-1 truncate font-semibold text-white">
                    {currentResult.threat_name || 'None Detected'}
                  </p>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Severity Level</p>
                  <p className={`mt-1 font-semibold uppercase ${
                    currentResult.threat_severity === 'critical' || currentResult.threat_severity === 'severe'
                      ? 'text-red-400'
                      : currentResult.threat_severity === 'high'
                      ? 'text-orange-400'
                      : currentResult.threat_severity === 'moderate'
                      ? 'text-amber-400'
                      : 'text-[#43f0a2]'
                  }`}>
                    {currentResult.threat_severity}
                  </p>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Shannon Entropy</p>
                  <p className="mt-1 font-mono font-semibold text-white">
                    {currentResult.entropy?.toFixed(3) || '0.000'} <span className="text-[10px] text-slate-500">/ 8.0</span>
                  </p>
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">Active Scan Engines</p>
                  <p className="mt-1 truncate text-xs font-semibold text-[#00f0ff]">
                    {currentResult.scan_engines?.join(', ') || 'ClamAV, YARA'}
                  </p>
                </div>
              </div>

              {/* SHA256 & MD5 Hash Copy */}
              <div className="mt-4 rounded-xl border border-white/[0.06] bg-black/40 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400">SHA-256 Fingerprint</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(currentResult.file_hash)}
                    className="flex items-center gap-1 text-[11px] text-[#00f0ff] hover:underline"
                  >
                    {copiedHash ? <Check className="h-3.5 w-3.5 text-[#43f0a2]" /> : <Copy className="h-3.5 w-3.5" />}
                    {copiedHash ? 'Copied' : 'Copy Hash'}
                  </button>
                </div>
                <p className="mt-1 break-all font-mono text-xs text-slate-300">{currentResult.file_hash}</p>
              </div>

              {/* Specific Engine Detections */}
              {currentResult.detections && currentResult.detections.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-xs font-bold uppercase tracking-wider text-red-400">Detections Reported By Engines:</p>
                  <div className="space-y-1.5">
                    {currentResult.detections.map((d, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 rounded-lg border border-red-500/20 bg-red-500/10 p-2.5 text-xs text-red-200">
                        <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                        <div>
                          <span className="font-bold text-white">[{d.engine || 'Engine'}]: </span>
                          <span>{d.threat_name || d.output || d.description}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendation Box */}
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-white/[0.08] bg-black/30 p-3.5 text-xs">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[#00f0ff]" />
                <div>
                  <span className="font-bold text-white">Analysis Guidance: </span>
                  <span className="text-slate-300">{currentResult.recommended_action}</span>
                  {currentResult.status === 'CLEAN' && (
                    <p className="mt-1 text-[11px] text-slate-500">
                      Note: File passed active ClamAV & YARA inspection rules. Defense in depth recommends monitoring execution behavior.
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT SECTION (1 Col): Engine Diagnostics & Health */}
        <div className="space-y-6">
          {/* Engines Diagnostics Card */}
          <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-[#0e1626]/80 to-[#070a10]/90 p-5 shadow-2xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3.5">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-[#00f0ff]" />
                <h3 className="text-sm font-bold text-white">Antivirus Engines</h3>
              </div>
              <button
                type="button"
                onClick={() => loadEngineHealth(true)}
                disabled={refreshingHealth}
                title="Refresh Engine Health"
                className="rounded-lg border border-white/10 bg-white/[0.04] p-1.5 text-slate-400 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-40"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${refreshingHealth ? 'animate-spin text-[#00f0ff]' : ''}`} />
              </button>
            </div>

            <div className="mt-4 space-y-3">
              {/* ClamAV Engine Box */}
              <div className="rounded-xl border border-white/[0.06] bg-black/25 p-3.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">ClamAV Scanner</span>
                  <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                    engineHealth?.clamav.status === 'Available'
                      ? 'border border-[#43f0a2]/30 bg-[#43f0a2]/15 text-[#43f0a2]'
                      : 'border border-amber-500/30 bg-amber-500/15 text-amber-400'
                  }`}>
                    {engineHealth?.clamav.status || 'Checking...'}
                  </span>
                </div>
                <p className="mt-1.5 font-mono text-xs text-slate-300">
                  {engineHealth?.clamav.version || 'Checking binary...'}
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  {engineHealth?.clamav.detail || 'High-performance daemon signature matching'}
                </p>
              </div>

              {/* YARA Rules Box */}
              <div className="rounded-xl border border-white/[0.06] bg-black/25 p-3.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">YARA Rules Engine</span>
                  <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                    engineHealth?.yara.status === 'Available'
                      ? 'border border-[#00f0ff]/30 bg-[#00f0ff]/15 text-[#00f0ff]'
                      : 'border border-slate-500/30 bg-slate-500/15 text-slate-400'
                  }`}>
                    {engineHealth?.yara.status || 'Checking...'}
                  </span>
                </div>
                <p className="mt-1.5 text-xs text-slate-300">
                  {engineHealth?.yara.rules_count ? `${engineHealth.yara.rules_count} Compiled Rules` : 'Bytecode matcher active'}
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  {engineHealth?.yara.detail || 'Heuristic pattern detection'}
                </p>
              </div>

              {/* Signature Database Box */}
              <div className="rounded-xl border border-white/[0.06] bg-black/25 p-3.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">Signature Database</span>
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#43f0a2]/30 bg-[#43f0a2]/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-[#43f0a2]">
                    {engineHealth?.signature_db.status || 'Active'}
                  </span>
                </div>
                <p className="mt-1.5 text-xs text-slate-300">
                  {engineHealth?.signature_db.active_signatures} Verified Signatures
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  Local hash signatures & threat heuristics
                </p>
              </div>
            </div>

            {/* Last Health Check Time */}
            {engineHealth?.timestamp && (
              <div className="mt-4 border-t border-white/[0.06] pt-3 text-[11px] text-slate-500">
                Last checked: {new Date(engineHealth.timestamp).toLocaleTimeString()}
              </div>
            )}
          </div>

          {/* Quick Capability Notes */}
          <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-[#0e1626]/80 to-[#070a10]/90 p-5 shadow-2xl backdrop-blur-xl">
            <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
              <Terminal className="h-3.5 w-3.5 text-[#00f0ff]" />
              Analysis Engine Specs
            </h4>
            <div className="mt-3 space-y-2 text-xs text-slate-400">
              <p>• <strong className="text-slate-200">Zero-day Heuristics:</strong> Computes byte Shannon entropy to unmask encrypted payloads.</p>
              <p>• <strong className="text-slate-200">Quarantine Isolation:</strong> Confirmed malware is safely moved to an encrypted vault.</p>
              <p>• <strong className="text-slate-200">Full Audit:</strong> Every file hash and analysis result is persisted to the database.</p>
            </div>
          </div>
        </div>
      </div>

      {/* LOWER SECTION: Persistent Scan History */}
      <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-[#0e1626]/80 to-[#070a10]/90 p-6 shadow-2xl backdrop-blur-xl">
        <div className="flex flex-col gap-4 border-b border-white/[0.08] pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-[#00f0ff]/30 bg-[#00f0ff]/10 text-[#00f0ff]">
              <Database className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Persistent Scan History</h3>
              <p className="text-xs text-slate-400">Records stored securely in database, preserved across server reloads</p>
            </div>
          </div>

          {/* Actions: Search, Filter & Clear */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search file or hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-44 rounded-xl border border-white/10 bg-black/40 py-1.5 pl-8 pr-3 text-xs text-white placeholder:text-slate-600 focus:border-[#00f0ff] focus:outline-none sm:w-56"
              />
            </div>

            {/* Filter Tabs */}
            <div className="flex rounded-xl border border-white/10 bg-black/30 p-1 text-xs">
              {(['ALL', 'INFECTED', 'SUSPICIOUS', 'CLEAN'] as const).map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={`rounded-lg px-2.5 py-1 text-[11px] font-semibold transition ${
                    statusFilter === st
                      ? 'bg-[#00f0ff] text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Clear History Button */}
            {historyItems.length > 0 && (
              <button
                type="button"
                onClick={() => setConfirmClearOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-red-500/20 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </button>
            )}
          </div>
        </div>

        {/* History Table */}
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-white/[0.06] bg-black/30 uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3 font-semibold">Verdict</th>
                <th className="px-4 py-3 font-semibold">Filename</th>
                <th className="px-4 py-3 font-semibold">SHA-256 Hash</th>
                <th className="px-4 py-3 font-semibold">Size</th>
                <th className="px-4 py-3 font-semibold">Threat Info</th>
                <th className="px-4 py-3 font-semibold">Scan Date</th>
                <th className="px-4 py-3 text-right font-semibold">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {historyLoading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    <RefreshCw className="mx-auto h-5 w-5 animate-spin text-[#00f0ff]" />
                    <p className="mt-2 text-xs">Loading historical records from database...</p>
                  </td>
                </tr>
              ) : historyItems.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No scan records matching current search or status filter.
                  </td>
                </tr>
              ) : (
                historyItems.map((item) => (
                  <tr key={item.id} className="transition hover:bg-white/[0.02]">
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-full px-2.5 py-0.5 text-[10px] font-extrabold uppercase tracking-wider ${
                        item.status === 'INFECTED'
                          ? 'border border-red-500/30 bg-red-500/20 text-red-400'
                          : item.status === 'SUSPICIOUS'
                          ? 'border border-amber-500/30 bg-amber-500/20 text-amber-400'
                          : 'border border-emerald-500/30 bg-emerald-500/20 text-[#43f0a2]'
                      }`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">
                      {item.filename}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                      {item.file_hash.substring(0, 16)}...
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {formatBytes(item.size_bytes)}
                    </td>
                    <td className="px-4 py-3">
                      {item.threat_name ? (
                        <span className="font-semibold text-red-400">{item.threat_name}</span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {item.scanned_at ? new Date(item.scanned_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedHistoryReport(item)}
                        className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[11px] font-semibold text-[#00f0ff] transition hover:bg-white/[0.08]"
                      >
                        Details
                        <ArrowRight className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report Modal */}
      {selectedHistoryReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-md">
          <div className="w-full max-w-xl rounded-2xl border border-white/15 bg-[#0e1626] p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
              <div className="flex items-center gap-2">
                <FileScan className="h-5 w-5 text-[#00f0ff]" />
                <h3 className="text-base font-bold text-white">Scan Report: {selectedHistoryReport.filename}</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedHistoryReport(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase text-slate-500">Verdict</p>
                  <p className={`mt-1 font-bold ${selectedHistoryReport.status === 'INFECTED' ? 'text-red-400' : 'text-[#43f0a2]'}`}>
                    {selectedHistoryReport.status}
                  </p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                  <p className="text-[10px] uppercase text-slate-500">File Size</p>
                  <p className="mt-1 font-semibold text-white">{formatBytes(selectedHistoryReport.size_bytes)}</p>
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                <p className="text-[10px] uppercase text-slate-500">SHA-256 Fingerprint</p>
                <p className="mt-1 break-all font-mono text-slate-300">{selectedHistoryReport.file_hash}</p>
              </div>

              {selectedHistoryReport.threat_name && (
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3">
                  <p className="text-[10px] font-bold uppercase text-red-400">Threat Identified</p>
                  <p className="mt-1 font-semibold text-white">{selectedHistoryReport.threat_name}</p>
                  <p className="mt-1 text-red-200">Action Taken: {selectedHistoryReport.action.toUpperCase()}</p>
                </div>
              )}

              <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                <p className="text-[10px] uppercase text-slate-500">Analysis Guidance</p>
                <p className="mt-1 text-slate-200">{selectedHistoryReport.recommended_action || 'No anomalous indicators reported'}</p>
              </div>
            </div>

            <div className="mt-6 flex justify-end border-t border-white/[0.08] pt-4">
              <button
                type="button"
                onClick={() => setSelectedHistoryReport(null)}
                className="rounded-xl bg-[#00f0ff] px-4 py-2 text-xs font-bold text-slate-950 hover:brightness-110"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Clear History Confirmation Modal */}
      {confirmClearOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-md">
          <div className="w-full max-w-sm rounded-2xl border border-red-500/30 bg-[#0e1626] p-6 shadow-2xl">
            <h3 className="text-base font-bold text-white">Clear Scan History?</h3>
            <p className="mt-2 text-xs text-slate-400">
              This action will permanently delete all saved scan logs from the local database.
            </p>
            <div className="mt-5 flex justify-end gap-2.5">
              <button
                type="button"
                onClick={() => setConfirmClearOpen(false)}
                className="rounded-xl border border-white/10 px-4 py-2 text-xs text-slate-400 hover:bg-white/5"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleClearHistory}
                className="rounded-xl bg-red-600 px-4 py-2 text-xs font-bold text-white hover:bg-red-500"
              >
                Confirm Clear
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
