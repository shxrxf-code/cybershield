import { Shield, AlertTriangle, CheckCircle, Activity, Archive, Network } from 'lucide-react'

export default function Overview() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card title="Security Score" value="85" icon={Shield} color="primary" subtitle="Good" />
        <Card title="Threats Blocked" value="12" icon={AlertTriangle} color="warning" subtitle="Last 24h" />
        <Card title="Protected Devices" value="3" icon={CheckCircle} color="primary" subtitle="All online" />
        <Card title="Quarantined" value="2" icon={Archive} color="danger" subtitle="Pending review" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-sentinel-primary" />
            Active Protection Modules
          </h2>
          <div className="space-y-2">
            <ModuleStatus name="URL & Phishing Protection" active />
            <ModuleStatus name="File & Malware Scanning" active />
            <ModuleStatus name="Network Shield" active />
            <ModuleStatus name="Ransomware Protection" active />
            <ModuleStatus name="Permission Monitor" active />
            <ModuleStatus name="Email Security" active />
          </div>
        </div>

        <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Network className="w-5 h-5 text-sentinel-info" />
            Recent Security Events
          </h2>
          <div className="space-y-3">
            <EventItem severity="warning" message="Suspicious URL blocked: phishing attempt" time="2 min ago" />
            <EventItem severity="info" message="Scheduled scan completed - no threats" time="1 hour ago" />
            <EventItem severity="danger" message="Malicious file quarantined" time="3 hours ago" />
            <EventItem severity="info" message="Network threat intelligence updated" time="5 hours ago" />
          </div>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">System Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatusItem label="Database" status="Connected" ok />
          <StatusItem label="ClamAV Engine" status="Available" ok />
          <StatusItem label="AI Threat Engine" status="Operational" ok />
        </div>
      </div>
    </div>
  )
}

function Card({ title, value, icon: Icon, color, subtitle }: any) {
  const colors: any = {
    primary: 'text-sentinel-primary',
    warning: 'text-sentinel-warning',
    danger: 'text-sentinel-danger',
    info: 'text-sentinel-info',
  }
  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-400">{title}</span>
        <Icon className={`w-5 h-5 ${colors[color]}`} />
      </div>
      <div className="text-2xl font-bold mb-1">{value}</div>
      <div className="text-xs text-gray-500">{subtitle}</div>
    </div>
  )
}

function ModuleStatus({ name, active }: { name: string, active: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 bg-sentinel-bg rounded">
      <span className="text-sm">{name}</span>
      <span className={`text-xs px-2 py-1 rounded ${active ? 'bg-sentinel-primary/20 text-sentinel-primary' : 'bg-gray-700 text-gray-400'}`}>
        {active ? 'Active' : 'Inactive'}
      </span>
    </div>
  )
}

function EventItem({ severity, message, time }: { severity: string, message: string, time: string }) {
  const colors: any = {
    info: 'bg-sentinel-info',
    warning: 'bg-sentinel-warning',
    danger: 'bg-sentinel-danger',
  }
  return (
    <div className="flex items-start gap-3">
      <div className={`w-2 h-2 rounded-full mt-2 ${colors[severity]}`}></div>
      <div className="flex-1">
        <p className="text-sm">{message}</p>
        <p className="text-xs text-gray-500">{time}</p>
      </div>
    </div>
  )
}

function StatusItem({ label, status, ok }: { label: string, status: string, ok: boolean }) {
  return (
    <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
      <span className="text-sm">{label}</span>
      <span className={`text-sm ${ok ? 'text-sentinel-primary' : 'text-sentinel-danger'}`}>{status}</span>
    </div>
  )
}
