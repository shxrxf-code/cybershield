interface StatusBadgeProps {
  status: 'active' | 'inactive' | 'warning' | 'danger' | 'ok'
  text: string
}

export default function StatusBadge({ status, text }: StatusBadgeProps) {
  const colors = {
    active: 'bg-sentinel-primary/20 text-sentinel-primary border-sentinel-primary/30',
    ok: 'bg-sentinel-primary/20 text-sentinel-primary border-sentinel-primary/30',
    inactive: 'bg-gray-700/50 text-gray-400 border-gray-600',
    warning: 'bg-sentinel-warning/20 text-sentinel-warning border-sentinel-warning/30',
    danger: 'bg-sentinel-danger/20 text-sentinel-danger border-sentinel-danger/30',
  }
  
  return (
    <span className={`px-2 py-1 text-xs rounded border ${colors[status]}`}>
      {text}
    </span>
  )
}
