import React from 'react';
import './QueueRow.css'; // Import the CSS file

// Assuming type definition is similar to the one in App.tsx
type ScanQueueItem = {
  scanId: string;
  status: 'Queued' | 'Running' | 'Completed' | 'Error';
  baseRequestUrl: string;
  baseRequestId: string;
  progress?: number;
};

interface QueueRowProps {
  item: ScanQueueItem;
}

// Helper to get CSS class based on status
const getStatusClass = (status: ScanQueueItem['status']) => {
  switch (status.toLowerCase()) {
    case 'running': return 'c-status-running';
    case 'completed': return 'c-status-completed';
    case 'error': return 'c-status-error';
    case 'queued':
    default: return 'c-status-queued';
  }
};

const QueueRow: React.FC<QueueRowProps> = ({ item }) => {
  const statusClass = getStatusClass(item.status);

  return (
    <div className="c-queue-row">
      <span className={`c-queue-status ${statusClass}`}>{item.status}</span>
      <span className="c-queue-url">{item.baseRequestUrl}</span>
      {item.status === 'Running' && item.progress !== undefined && (
        <span className="c-queue-progress">{item.progress}%</span>
      )}
      {/* Optionally add more details like start time, number of requests sent, etc. */}
    </div>
  );
};

export default QueueRow; 