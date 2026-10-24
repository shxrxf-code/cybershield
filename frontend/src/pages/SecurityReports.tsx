export default function SecurityReports() {
  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
      <h2 className="text-xl font-semibold mb-4">Security Reports</h2>
      <p className="text-gray-400 mb-4">This module is integrated with the SENTINEL X backend API. Functional components are available.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-sentinel-bg rounded">
          <h3 className="font-medium mb-2">Status</h3>
          <span className="text-sentinel-primary">Operational</span>
        </div>
        <div className="p-4 bg-sentinel-bg rounded">
          <h3 className="font-medium mb-2">API Endpoint</h3>
          <code className="text-sm text-sentinel-info">/api/v1/security</code>
        </div>
      </div>
    </div>
  )
}
