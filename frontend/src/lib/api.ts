import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message)
    return Promise.reject(error)
  }
)

export const healthAPI = {
  check: () => axios.get('/health', { timeout: 30000 }),
}

export const urlAPI = {
  scan: (url: string) => api.post('/url/scan', { url }),
  status: () => api.get('/url/status'),
}

export const scanAPI = {
  scanFile: (file: File, signal?: AbortSignal) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/scan/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      signal,
    })
  },
  scanHash: (file_hash: string, filename: string) => api.post('/scan/hash', { file_hash, filename }),
  status: () => api.get('/scan/status'),
}

export const quarantineAPI = {
  list: () => api.get('/quarantine/'),
  restore: (filename: string) => api.post('/quarantine/restore', null, { params: { filename } }),
  remove: (filename: string) => api.delete(`/quarantine/${encodeURIComponent(filename)}`),
  status: () => api.get('/quarantine/status'),
}

export const emailAPI = {
  scan: (data: any) => api.post('/email/scan', data),
  status: () => api.get('/email/status'),
}

export const apkAPI = {
  scan: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/apk/scan', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  status: () => api.get('/apk/status'),
}

export const networkAPI = {
  analyze: (data: any) => api.post('/network/analyze', data),
  status: () => api.get('/network/status'),
}

export const devicesAPI = {
  list: () => api.get('/devices/'),
  status: () => api.get('/devices/status'),
  sync: () => api.get('/devices/sync'),
}

export const threatsAPI = {
  list: () => api.get('/threats/'),
  status: () => api.get('/threats/status'),
}

export const permissionsAPI = {
  list: () => api.get('/permissions/'),
  status: () => api.get('/permissions/status'),
}

export const auditAPI = {
  logs: (limit = 50) => api.get('/audit/logs', { params: { limit } }),
  status: () => api.get('/audit/status'),
}

export const reportsAPI = {
  list: () => api.get('/reports/'),
  generate: (reportType = 'summary') => api.get('/reports/generate', { params: { report_type: reportType } }),
  status: () => api.get('/reports/status'),
}

export const aiAPI = {
  analyze: (data: any) => api.post('/ai/analyze', data),
  status: () => api.get('/ai/status'),
}

export default api
