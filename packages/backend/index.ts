import {
  Caido,
  HttpResponse,
  HttpRequest,
  Command,
  CommandParameterType,
  CommandInvocation,
  QueryParameter,
  Header,
} from "@caido/sdk-backend";
import { runPassiveChecks } from "./passiveScanner"; // Import from the new file
import { performSingleScan } from "./activeScanner"; // Import from the new file
import { PLUGIN_ID, FRONTEND_UPDATE_COMMAND, MAX_CONCURRENT_SCANS } from "./constants"; // Import constants

// --- Constants ---
// const MAX_CONCURRENT_SCANS = 5; // Moved to constants.ts or define if specific to this file
// const PLUGIN_ID = "burp-like-scanner"; // MOVED to constants.ts
// const FRONTEND_UPDATE_COMMAND = 'burpLikeScanner:updateScanStatus'; // MOVED to constants.ts

// --- State ---
// Store only necessary info in the queue to save memory
type ScanQueueEntry = {
    baseRequestId: string;
    scanId: string;
    status: 'Queued' | 'Running' | 'Completed' | 'Error';
};
let activeScanQueue: ScanQueueEntry[] = [];
let runningScans = 0;

// --- Passive Scanner Helpers --- MOVED to passiveScanner.ts ---

// --- Main Passive Scanner Logic --- MOVED to passiveScanner.ts ---

// --- Active Scanner ---

const runActiveScan = async (caido: Caido, baseRequest: HttpRequest) => {
    const baseRequestId = baseRequest.getId();
    const baseRequestUrl = baseRequest.getUrl(); // Get URL for frontend

    // Prevent duplicate scans
    const existingScan = activeScanQueue.find(s => s.baseRequestId === baseRequestId && (s.status === 'Queued' || s.status === 'Running'));
    if (existingScan) {
        caido.log.info(`Scan for request ${baseRequestId} is already in the queue (Status: ${existingScan.status}). Skipping.`);
        return;
    }

    const scanId = `scan-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const newEntry: ScanQueueEntry = { baseRequestId, scanId, status: "Queued" };
    activeScanQueue.push(newEntry);
    caido.log(`Queued active scan ${scanId} for request ${baseRequestId}`);

    // Notify frontend about the new queue item
    try {
        await caido.command.invoke(FRONTEND_UPDATE_COMMAND, {
             scanId: newEntry.scanId,
             status: newEntry.status,
             baseRequestId: newEntry.baseRequestId,
             baseRequestUrl: baseRequestUrl, // Send URL
        });
    } catch (e) {
        caido.log.error(`Failed to invoke frontend update command (${FRONTEND_UPDATE_COMMAND}): ${e}`);
    }

    processScanQueue(caido);
};

const processScanQueue = async (caido: Caido) => {
  if (runningScans >= MAX_CONCURRENT_SCANS || activeScanQueue.length === 0) {
    return;
  }

  const entryToRun = activeScanQueue.find(e => e.status === 'Queued');
  if (!entryToRun) {
    return;
  }

  runningScans++;
  entryToRun.status = 'Running';
  caido.log(`Starting scan ${entryToRun.scanId} for request ${entryToRun.baseRequestId}. Running scans: ${runningScans}`);

  // Notify frontend that scan is now Running
  try {
    await caido.command.invoke(FRONTEND_UPDATE_COMMAND, {
      scanId: entryToRun.scanId,
      status: entryToRun.status,
      baseRequestId: entryToRun.baseRequestId,
      // baseRequestUrl is not strictly needed for a status update if already sent
    });
  } catch (e) {
    caido.log.error(`Failed to invoke frontend update for ${entryToRun.scanId} (Running): ${e}`);
  }
  
  const baseRequest = await caido.http.getRequest(entryToRun.baseRequestId);
  if (!baseRequest) {
      caido.log.error(`Failed to fetch base request ${entryToRun.baseRequestId} for scan ${entryToRun.scanId}. Marking as Error.`);
      entryToRun.status = 'Error';
      // Notify frontend
      try {
        await caido.command.invoke(FRONTEND_UPDATE_COMMAND, {
          scanId: entryToRun.scanId,
          status: entryToRun.status,
          baseRequestId: entryToRun.baseRequestId,
        });
      } catch (fe) {
        caido.log.error(`Failed to invoke frontend update for ${entryToRun.scanId} (Error Status): ${fe}`);
      }
      activeScanQueue = activeScanQueue.filter(s => s.scanId !== entryToRun.scanId); // Or mark as completed with error
      runningScans--;
      processScanQueue(caido); // Try to process next
      return;
  }

  try {
    await performSingleScan(caido, baseRequest, entryToRun.scanId);
    entryToRun.status = 'Completed';
    caido.log(`Scan ${entryToRun.scanId} completed successfully.`);
  } catch (error) {
    caido.log.error(`Error during scan ${entryToRun.scanId}: ${error}`);
    entryToRun.status = 'Error';
  } finally {
    runningScans--;
    activeScanQueue = activeScanQueue.filter(s => s.scanId !== entryToRun.scanId); // Remove from active, keep history elsewhere if needed
    
    // Notify frontend of final status (Completed/Error)
    try {
      await caido.command.invoke(FRONTEND_UPDATE_COMMAND, {
        scanId: entryToRun.scanId,
        status: entryToRun.status, 
        baseRequestId: entryToRun.baseRequestId,
      });
    } catch (e) {
      caido.log.error(`Failed to invoke frontend update for ${entryToRun.scanId} (Final Status): ${e}`);
    }

    caido.log(`Finished scan ${entryToRun.scanId}. Running scans: ${runningScans}. Queue length: ${activeScanQueue.length}`);
    processScanQueue(caido); // Attempt to process the next item in the queue
  }
};

// --- Caido Integration ---
export const init = (caido: Caido) => {
  caido.log("Plugin Burp-Like Scanner initializing...");

  // Register hook for passive scanning
  caido.hooks.on("response", (response: HttpResponse) => {
    runPassiveChecks(caido, response); // Use imported function
  });

  // Register command for active scanning (triggered by frontend context menu)
  caido.commands.register("burpLikeScanner:scanActive", {
    displayName: "Start Active Scan (Burp-Like)",
    description: "Initiates an active scan on the selected request.",
    parameters: {
      requestId: { type: CommandParameterType.STRING, displayName: "Request ID", description: "The ID of the request to scan" },
    },
    action: async (invocation: CommandInvocation) => {
      const requestId = invocation.args.requestId as string;
      if (!requestId) {
        caido.log.error("burpLikeScanner:scanActive invoked without requestId.");
        return;
      }

      caido.log(`burpLikeScanner:scanActive invoked for request ID: ${requestId}`);
      
      try {
        // Fetch the base HTTP request using its ID
        const baseRequest = await caido.http.getRequest(requestId); 
        if (!baseRequest) {
          caido.log.error(`Failed to fetch request with ID: ${requestId}`);
          // Optionally notify frontend of this specific error if possible
          return;
        }
        
        await runActiveScan(caido, baseRequest);
      } catch (error) {
        caido.log.error(`Error during active scan initiation for request ${requestId}: ${error}`);
        // Optionally, try to send an error status to the frontend if a scanId was generated
        // or if we can link this error to a specific scan attempt.
      }
    },
  });

   // Register Context Menu Item (Triggered by Frontend)
   // The actual registration of the menu item itself happens in the frontend code.
   // This backend setup just ensures the command it calls exists.

  caido.log("Plugin Burp-Like Scanner initialized successfully.");
}; 