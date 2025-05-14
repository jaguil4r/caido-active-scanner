import React from 'react';
import './IssueRow.css'; // Import the CSS file

// Assuming type definition is similar to the one in App.tsx
// It's better to define this in a shared types file (e.g., lib/types.ts)
type Issue = {
  id: string;
  title: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: 'Certain' | 'Firm' | 'Tentative';
  description: string;
  affectedRequestId: string;
  url?: string;
};

interface IssueRowProps {
  issue: Issue;
}

// Helper to get CSS class based on severity
const getSeverityClass = (severity: Issue['severity']) => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'c-severity-critical';
    case 'high': return 'c-severity-high';
    case 'medium': return 'c-severity-medium';
    case 'low': return 'c-severity-low';
    case 'info':
    default: return 'c-severity-info';
  }
};

const IssueRow: React.FC<IssueRowProps> = ({ issue }) => {
  const severityClass = getSeverityClass(issue.severity);

  return (
    <div className="c-issue-row">
      <span className={`c-severity-badge ${severityClass}`}>{issue.severity}</span>
      <div className="c-issue-details">
          <div className="c-issue-title">{issue.title}</div>
          <div className="c-issue-url">{issue.url || 'N/A'}</div> 
      </div>
      {/* Optionally add confidence or other info here */}
    </div>
  );
};

export default IssueRow; 