interface LoadingSpinnerProps {
  compact?: boolean
}

export default function LoadingSpinner({ compact = false }: LoadingSpinnerProps) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={compact ? 'inline-flex' : 'flex items-center justify-center p-8'}
    >
      <span aria-hidden="true" className={`animate-spin rounded-full border-b-2 border-sentinel-primary ${compact ? 'h-5 w-5' : 'h-8 w-8'}`} />
    </span>
  )
}
