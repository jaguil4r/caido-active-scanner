import React, { useState, useEffect, useCallback } from 'react';
import {
    Caido,
    CommandType,
    ContextType,
    useCaidoContext,
    CommandActionArgs,
    Issue as CaidoIssue, // Rename imported Issue to avoid conflict
    Severity as CaidoSeverity,
    Confidence as CaidoConfidence,
} from '@caido/sdk-frontend';
import { Tabs, TabList, Tab, TabPanels, TabPanel, Heading, List, ListItem, Text, Spinner, Box, Button } from '@caido/sdk-frontend'; // Assuming these UI components exist

// Assuming IssueRow and QueueRow components exist
import IssueRow from './components/IssueRow';
import QueueRow from './components/QueueRow';

const PLUGIN_ID = "burp-like-scanner"; // Matches backend

// --- Types (Should match backend/issue format ideally) ---
type IssueSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
type IssueConfidence = 'Certain' | 'Firm' | 'Tentative';

type Issue = {
  id: string; // Caido Issue ID
  title: string;
  severity: IssueSeverity;
  confidence: IssueConfidence;
  description: string;
  affectedRequestId: string;
  url?: string; // Populated from request if possible
};

type ScanQueueItem = {
  scanId: string;
  status: 'Queued' | 'Running' | 'Completed' | 'Error';
  baseRequestUrl: string; // For display
  baseRequestId: string;
  // Add progress details if available
  progress?: number; // e.g., 0-100
};

// Type for the update payload from backend
interface ScanStatusUpdatePayload {
    scanId: string;
    status: ScanQueueItem['status'];
    baseRequestId: string;
    baseRequestUrl?: string;
    // Add other fields like progress if needed later
}

// Helper to map Caido SDK Severity enum to our string type
const mapSeverity = (severity: CaidoSeverity): IssueSeverity => {
    switch (severity) {
        case CaidoSeverity.CRITICAL: return 'Critical';
        case CaidoSeverity.HIGH: return 'High';
        case CaidoSeverity.MEDIUM: return 'Medium';
        case CaidoSeverity.LOW: return 'Low';
        case CaidoSeverity.INFO:
        default: return 'Info';
    }
}

// Helper to map Caido SDK Confidence enum to our string type
const mapConfidence = (confidence: CaidoConfidence): IssueConfidence => {
    switch (confidence) {
        case CaidoConfidence.CERTAIN: return 'Certain';
        case CaidoConfidence.FIRM: return 'Firm';
        case CaidoConfidence.TENTATIVE:
        default: return 'Tentative';
    }
}

// --- Components ---
// Explicitly type props for IssueTable
interface IssueTableProps {
  issues: Issue[];
  caido: Caido;
}
const IssueTable: React.FC<IssueTableProps> = ({ issues, caido }) => {
  const handleRowClick = (issue: Issue) => {
    caido.command.invoke(CommandType.OPEN_REQUEST, { id: issue.affectedRequestId });
  };

  if (issues.length === 0) {
    return <Text>No issues found yet.</Text>;
  }

  return (
    <List>
      {issues.map((issue: Issue) => (
        <ListItem key={issue.id} onClick={() => handleRowClick(issue)}>
          <IssueRow issue={issue} />
        </ListItem>
      ))}
    </List>
  );
};

// Explicitly type props for ScanQueue
interface ScanQueueProps {
  queue: ScanQueueItem[];
  caido: Caido;
}
const ScanQueue: React.FC<ScanQueueProps> = ({ queue, caido }) => {
  const handleRowClick = (item: ScanQueueItem) => {
    // Optionally open the base request or show scan details
    caido.command.invoke(CommandType.OPEN_REQUEST, { id: item.baseRequestId });
  };

  if (queue.length === 0) {
    return <Text>Scan queue is empty.</Text>;
  }

  return (
    <List>
      {queue.map((item: ScanQueueItem) => (
        <ListItem key={item.scanId} onClick={() => handleRowClick(item)}>
          <QueueRow item={item} />
        </ListItem>
      ))}
    </List>
  );
};

// --- Main App Component ---
const App = () => {
  const caido = useCaidoContext();
  const [issues, setIssues] = useState<Issue[]>([]);
  const [scanQueue, setScanQueue] = useState<ScanQueueItem[]>([]);
  const [isLoadingIssues, setIsLoadingIssues] = useState(true); // Start loading

  // --- Issue Fetching ---
  const fetchIssues = useCallback(async () => {
    setIsLoadingIssues(true);
    try {
        const allIssues = await caido.issues.getAll();
        caido.log.info(`Fetched ${allIssues.length} total issues.`);
        
        const pluginIssues = allIssues
            .filter(issue => issue.pluginId === PLUGIN_ID)
            .map((issue: CaidoIssue): Issue => ({
                id: issue.id,
                title: issue.name,
                severity: mapSeverity(issue.severity),
                confidence: mapConfidence(issue.confidence),
                description: issue.description || '',
                affectedRequestId: issue.affectedEntries[0]?.id || '',
                url: issue.affectedEntries[0]?.url || 'URL not available',
            }));
            
        caido.log.info(`Found ${pluginIssues.length} issues for plugin ${PLUGIN_ID}.`);
        setIssues(pluginIssues);
    } catch (error) {
        caido.log.error(`Failed to fetch issues: ${error}`);
        setIssues([]); 
        caido.ui.showToast({
            message: "Failed to load issues.",
            type: "error",
            duration: 3000,
        });
    } finally {
        setIsLoadingIssues(false);
    }
  }, [caido]);

  // --- Backend Communication Handlers ---
  const handleScanStatusUpdate = useCallback((args: CommandActionArgs<ScanStatusUpdatePayload>) => {
    const update = args.params;
    if (!update) {
        caido.log.error("Received scan status update with no parameters.");
        return;
    }
    
    caido.log.info(`Received scan status update: ${update.scanId} -> ${update.status}`);

    setScanQueue((prevQueue: ScanQueueItem[]) => {
        const existingIndex = prevQueue.findIndex(item => item.scanId === update.scanId);

        if (existingIndex !== -1) {
            // Update existing item
            const updatedItem = { ...prevQueue[existingIndex], status: update.status };
            const newQueue = [...prevQueue];
            newQueue[existingIndex] = updatedItem;
            
            // Optionally remove completed/errored items after a delay or keep them
            if (update.status === 'Completed' || update.status === 'Error') {
                 // For now, keep them in the list with their final status.
                 // Could remove them like this: return newQueue.filter(item => item.scanId !== update.scanId);
                 return newQueue;
            } else {
                return newQueue;
            }
        } else if (update.status === 'Queued') {
            // Add new item if it's being queued and doesn't exist
            const newItem: ScanQueueItem = {
                scanId: update.scanId,
                status: update.status,
                baseRequestId: update.baseRequestId,
                baseRequestUrl: update.baseRequestUrl || 'Loading details...', // Provide a default
            };
            return [...prevQueue, newItem];
        } else if (update.status !== 'Queued' && existingIndex === -1) { 
            // If it's not a 'Queued' status and we don't know the scanId, it's unusual.
            caido.log.warning(`Received status update for unknown scanId: ${update.scanId} with status ${update.status}`);
            return prevQueue;
        } else {
            // This case should ideally not be reached if logic is sound (e.g. update for existing, or new 'Queued' item)
            caido.log.debug(`Unhandled case in scan status update for scanId: ${update.scanId}`);
            return prevQueue; 
        }
    });
  }, [caido]);

  const handleContextMenuScan = useCallback(async (context: any) => {
    if (context.type === ContextType.REQUEST && context.data.id) {
      const requestId = context.data.id;
      caido.log.info(`Context menu triggered for request: ${requestId}`);
      try {
        await caido.command.invoke('runtime:command', {
           command: 'burpLikeScanner:scanActive', 
           params: { requestId: requestId },
        });
        caido.log.info(`Active scan command invoked successfully for request: ${requestId}.`);
        caido.ui.showToast({
            message: "Active scan initiated.",
            type: "success",
            duration: 2000,
        });
        // The backend should send a 'Queued' status update via 'burpLikeScanner:updateScanStatus'
        // which will then update the scanQueue state.
      } catch (error) {
        caido.log.error(`Failed to invoke active scan command for request ${requestId}: ${error}`);
        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (typeof error === 'string') {
            errorMessage = error;
        }
        caido.ui.showToast({
            message: `Failed to start scan: ${errorMessage}`,
            type: "error",
            duration: 3000,
        });
      }
    } else {
        caido.log.warning('Context menu action called with unexpected context:', context);
    }
  }, [caido]);

  // --- Effects ---
  useEffect(() => {
    fetchIssues(); // Fetch issues on initial mount

    // --- Register Commands ---
    const contextMenuCommand = 'burpLikeScanner:sendToActiveScan';
    const updateStatusCommand = 'burpLikeScanner:updateScanStatus';

    caido.command.register({
      name: contextMenuCommand,
      displayName: 'Actively scan with Burp-Like Scanner',
      icon: 'radar',
      contextType: ContextType.REQUEST,
      action: handleContextMenuScan,
    });
    caido.log.info('Context menu item registered.');

    caido.command.register({
        name: updateStatusCommand,
        action: handleScanStatusUpdate,
    });
    caido.log.info('Scan status update handler registered.');

    // Cleanup function
    return () => {
      caido.command.unregister(contextMenuCommand);
      caido.command.unregister(updateStatusCommand);
      caido.log.info('Commands unregistered.');
    };
  }, [caido, handleContextMenuScan, handleScanStatusUpdate, fetchIssues]); // Added fetchIssues to dependency array

  // --- Render ---
  return (
    <Box p="var(--c-spacing-2)">
      <Heading level={3} mb="var(--c-spacing-2)">Burp-Like Scanner</Heading>
      <Tabs>
        <TabList>
          <Tab>
            Issues ({issues.length})
            <Button onClick={fetchIssues} variant="ghost" size="sm" ml="var(--c-spacing-1)">
                Refresh
            </Button>
          </Tab>
          <Tab>Scan Queue ({scanQueue.length})</Tab>
        </TabList>
        <TabPanels>
          <TabPanel>
            {/* Use separate loading state for issues */}
            {isLoadingIssues ? <Spinner /> : <IssueTable issues={issues} caido={caido} />}
          </TabPanel>
          <TabPanel>
             {/* Queue is managed by updates, so no dedicated loading state needed here for now */}
             <ScanQueue queue={scanQueue} caido={caido} /> 
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Box>
  );
};

export default App; 