import { useState, useEffect } from 'react'
import { Archive, AlertTriangle, RotateCcw, Trash2, RefreshCw } from 'lucide-react'
import { quarantineAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

export default function Quarantine() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedItem, setSelectedItem] = useState<any>(null)
  const [showRestoreDialog, setShowRestoreDialog] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [actionLoading, setActionLoading] = useState(false)

  const fetchQuarantine = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await quarantineAPI.list()
      setItems(response.data.items || [])
    } catch (requestError) {
      console.error(requestError)
      setError('Quarantine inventory could not be loaded.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchQuarantine()
  }, [])

  const handleRestore = async () => {
    if (!selectedItem) return
    setActionLoading(true)
    setNotice('')
    try {
      const { data } = await quarantineAPI.restore(selectedItem.name)
      if (data.restored) {
        setNotice(data.message || 'File restored.')
        setShowRestoreDialog(false)
        await fetchQuarantine()
      } else {
        setNotice(data.message || 'The backend did not restore this file.')
      }
    } catch (requestError) {
      console.error(requestError)
      setError('Restore request failed.')
    } finally {
      setActionLoading(false)
    }
  }

  const handleDelete = async () => {
    if (!selectedItem) return
    setActionLoading(true)
    setNotice('')
    try {
      const { data } = await quarantineAPI.remove(selectedItem.name)
      if (data.deleted) {
        setNotice(data.message || 'File deleted.')
        setShowDeleteDialog(false)
        await fetchQuarantine()
      } else {
        setNotice(data.message || 'The backend did not delete this file.')
      }
    } catch (requestError) {
      console.error(requestError)
      setError('Deletion request failed.')
    } finally {
      setActionLoading(false)
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
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Quarantine Manager</h2>
          <p className="text-gray-400 text-sm">Manage quarantined files and threats</p>
        </div>
        <button onClick={fetchQuarantine} disabled={loading} className="flex items-center gap-2 px-4 py-2 bg-sentinel-card border border-sentinel-border rounded hover:bg-sentinel-border transition-colors disabled:opacity-50">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>
      {error && <p role="alert" className="rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-sentinel-warning/25 bg-sentinel-warning/10 px-4 py-3 text-sm text-amber-100">{notice}</p>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Total Quarantined</span>
            <Archive className="w-5 h-5 text-sentinel-warning" />
          </div>
          <div className="text-2xl font-bold">{items.length}</div>
        </div>
        <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Risk metadata</span>
            <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
          </div>
          <div className="text-2xl font-bold text-slate-500">Not provided</div>
        </div>
        <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Quarantine policy</span>
            <AlertTriangle className="w-5 h-5 text-sentinel-warning" />
          </div>
          <div className="text-sm font-medium text-slate-400">Not exposed by API</div>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border rounded-lg overflow-hidden">
        <div className="p-6 border-b border-sentinel-border">
          <h3 className="text-lg font-semibold">Quarantined Items</h3>
        </div>
        {loading ? (
          <LoadingSpinner />
        ) : items.length === 0 ? (
          <div className="p-12 text-center">
            <Archive className="w-12 h-12 mx-auto mb-4 text-gray-600" />
            <p className="text-gray-400 mb-2">No quarantined files</p>
            <p className="text-sm text-gray-500">Files detected as threats will appear here</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-sentinel-bg">
                <tr>
                  <th className="text-left text-sm font-medium text-gray-400 p-4">File Name</th>
                  <th className="text-left text-sm font-medium text-gray-400 p-4">Size</th>
                  <th className="text-left text-sm font-medium text-gray-400 p-4">Threat Type</th>
                  <th className="text-left text-sm font-medium text-gray-400 p-4">Status</th>
                  <th className="text-left text-sm font-medium text-gray-400 p-4">Quarantined</th>
                  <th className="text-right text-sm font-medium text-gray-400 p-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.name} className="border-b border-sentinel-border/50 hover:bg-sentinel-bg/50 transition-colors">
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-sentinel-danger" />
                        <span className="text-sm font-medium truncate max-w-xs">{item.name}</span>
                      </div>
                    </td>
                    <td className="p-4 text-sm text-gray-400">{formatFileSize(item.size)}</td>
                    <td className="p-4">
                      <StatusBadge status="inactive" text="Not classified" />
                    </td>
                    <td className="p-4">
                      <StatusBadge status="warning" text="Quarantined" />
                    </td>
                    <td className="p-4 text-sm text-gray-400">Unavailable</td>
                    <td className="p-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => { setSelectedItem(item); setShowRestoreDialog(true); }}
                          className="p-2 hover:bg-sentinel-primary/10 text-sentinel-primary rounded transition-colors"
                          title="Restore"
                        >
                          <RotateCcw className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => { setSelectedItem(item); setShowDeleteDialog(true); }}
                          className="p-2 hover:bg-sentinel-danger/10 text-sentinel-danger rounded transition-colors"
                          title="Delete Permanently"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showRestoreDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <RotateCcw className="w-5 h-5 text-sentinel-primary" />
              Restore File
            </h3>
            <p className="text-gray-400 mb-4">
              Are you sure you want to restore <span className="text-white font-medium">{selectedItem?.name}</span>?
            </p>
            <p className="text-sm text-sentinel-warning mb-6">
              Warning: Only restore files you are confident are safe.
            </p>
            <div className="flex gap-3">
              <button onClick={handleRestore} disabled={actionLoading} className="flex-1 px-4 py-2 bg-sentinel-primary text-black font-medium rounded hover:bg-sentinel-primary/90 disabled:opacity-50">
                {actionLoading ? 'Submitting…' : 'Request restore'}
              </button>
              <button onClick={() => setShowRestoreDialog(false)} disabled={actionLoading} className="flex-1 px-4 py-2 bg-sentinel-bg border border-sentinel-border rounded hover:bg-sentinel-border disabled:opacity-50">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showDeleteDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Trash2 className="w-5 h-5 text-sentinel-danger" />
              Delete Permanently
            </h3>
            <p className="text-gray-400 mb-4">
              Are you sure you want to permanently delete <span className="text-white font-medium">{selectedItem?.name}</span>?
            </p>
            <p className="text-sm text-sentinel-danger mb-6">
              This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button onClick={handleDelete} disabled={actionLoading} className="flex-1 px-4 py-2 bg-sentinel-danger text-white font-medium rounded hover:bg-sentinel-danger/90 disabled:opacity-50">
                {actionLoading ? 'Submitting…' : 'Request deletion'}
              </button>
              <button onClick={() => setShowDeleteDialog(false)} disabled={actionLoading} className="flex-1 px-4 py-2 bg-sentinel-bg border border-sentinel-border rounded hover:bg-sentinel-border disabled:opacity-50">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
