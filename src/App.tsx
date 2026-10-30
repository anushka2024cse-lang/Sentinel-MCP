import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header.js';
import { Sidebar, NavPage } from './components/Sidebar.js';
import { PrimaryDemoModal } from './components/PrimaryDemoModal.js';
import { OverviewDashboard } from './views/OverviewDashboard.js';
import { ServerInventory } from './views/ServerInventory.js';
import { ToolInventory } from './views/ToolInventory.js';
import { IdentityAccess } from './views/IdentityAccess.js';
import { SecurityPolicies } from './views/SecurityPolicies.js';
import { RuntimeMonitor } from './views/RuntimeMonitor.js';
import { ThreatDetection } from './views/ThreatDetection.js';
import { DataProtectionDLP } from './views/DataProtectionDLP.js';
import { ApprovalCentre } from './views/ApprovalCentre.js';
import { SecurityIncidents } from './views/SecurityIncidents.js';
import { AuditTrail } from './views/AuditTrail.js';
import { SupplyChainScanner } from './views/SupplyChainScanner.js';
import { SecurityTestingLab } from './views/SecurityTestingLab.js';
import { TestResultsReports } from './views/TestResultsReports.js';
import { SettingsView } from './views/SettingsView.js';
import { api } from './services/api.js';
import {
  UserRole,
  IdentityProfile,
  MCPServer,
  MCPTool,
  SecurityPolicy,
  SecurityRequest,
  SecurityEvent,
  SensitiveDataFinding,
  ApprovalRequest,
  SecurityIncident,
  SecurityTestScenario,
  SecurityTestRun,
  SystemStats
} from './types/index.js';

export default function App() {
  const [currentPage, setCurrentPage] = useState<NavPage>('dashboard');
  const [currentRole, setCurrentRole] = useState<UserRole>('Administrator');
  const [currentIdentityId, setCurrentIdentityId] = useState<string>('user-admin');

  // Core Data State
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [tools, setTools] = useState<MCPTool[]>([]);
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [requests, setRequests] = useState<SecurityRequest[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [findings, setFindings] = useState<SensitiveDataFinding[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [scenarios, setScenarios] = useState<SecurityTestScenario[]>([]);
  const [testRuns, setTestRuns] = useState<SecurityTestRun[]>([]);
  const [identities, setIdentities] = useState<IdentityProfile[]>([]);

  // Navigation & Modals
  const [selectedServerForTools, setSelectedServerForTools] = useState<string | undefined>();
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [
        statsData,
        serversData,
        toolsData,
        policiesData,
        requestsData,
        eventsData,
        findingsData,
        approvalsData,
        incidentsData,
        scenariosData,
        runsData,
        identitiesData
      ] = await Promise.all([
        api.getStats(),
        api.getServers(),
        api.getTools(),
        api.getPolicies(),
        api.getRequests(),
        api.getAuditLogs(),
        api.getFindings(),
        api.getApprovals(),
        api.getIncidents(),
        api.getScenarios(),
        api.getTestRuns(),
        api.getIdentities()
      ]);

      setStats(statsData);
      setServers(serversData);
      setTools(toolsData);
      setPolicies(policiesData);
      setRequests(requestsData);
      setEvents(eventsData);
      setFindings(findingsData);
      setApprovals(approvalsData);
      setIncidents(incidentsData);
      setScenarios(scenariosData);
      setTestRuns(runsData);
      setIdentities(identitiesData);
    } catch (err) {
      console.error('Failed to load Sentinel state:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Poll data periodically to keep events and stats in sync
    const interval = setInterval(loadData, 6000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleRoleChange = (role: UserRole) => {
    setCurrentRole(role);
    const matchingIdentity = identities.find(i => i.role === role);
    if (matchingIdentity) {
      setCurrentIdentityId(matchingIdentity.id);
    }
  };

  const handleIdentityChange = (id: string) => {
    setCurrentIdentityId(id);
    const ident = identities.find(i => i.id === id);
    if (ident) {
      setCurrentRole(ident.role);
    }
  };

  const handleResetSandbox = async () => {
    if (!confirm('Reset synthetic MCP sandbox and database to default baseline?')) return;
    setIsResetting(true);
    try {
      await api.resetDemo();
      await loadData();
    } catch (e: any) {
      alert(`Reset failed: ${e.message}`);
    } finally {
      setIsResetting(false);
    }
  };

  const pendingApprovalsCount = approvals.filter(a => a.status === 'PENDING').length;
  const openIncidentsCount = incidents.filter(i => i.status === 'Open' || i.status === 'Investigating').length;

  return (
    <div className="min-h-screen bg-[#080D18] text-slate-100 flex flex-col font-sans antialiased">
      {/* Top Application Header */}
      <Header
        currentRole={currentRole}
        onRoleChange={handleRoleChange}
        identities={identities}
        currentIdentityId={currentIdentityId}
        onIdentityChange={handleIdentityChange}
        onRunPrimaryDemo={() => setIsDemoModalOpen(true)}
        onResetDemo={handleResetSandbox}
        isResetting={isResetting}
      />

      {/* Main Layout Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Persistent 15-Module Sidebar */}
        <Sidebar
          currentPage={currentPage}
          onNavigate={(page) => {
            setCurrentPage(page);
            setSelectedServerForTools(undefined);
          }}
          pendingApprovalsCount={pendingApprovalsCount}
          openIncidentsCount={openIncidentsCount}
        />

        {/* Dynamic Main Content Workspace */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 bg-[#080D18] scrollbar-thin scrollbar-thumb-slate-800">
          <div className="max-w-7xl mx-auto">
            {currentPage === 'dashboard' && (
              <OverviewDashboard
                stats={stats}
                recentEvents={events}
                recentTestRuns={testRuns}
                onNavigate={setCurrentPage}
                onOpenDemo={() => setIsDemoModalOpen(true)}
              />
            )}

            {currentPage === 'servers' && (
              <ServerInventory
                servers={servers}
                tools={tools}
                currentRole={currentRole}
                onRefresh={loadData}
                onSelectToolView={(srvId) => {
                  setSelectedServerForTools(srvId);
                  setCurrentPage('tools');
                }}
              />
            )}

            {currentPage === 'tools' && (
              <ToolInventory
                tools={tools}
                servers={servers}
                selectedServerId={selectedServerForTools}
                currentRole={currentRole}
                onRefresh={loadData}
              />
            )}

            {currentPage === 'access' && (
              <IdentityAccess
                identities={identities}
                tools={tools}
                currentRole={currentRole}
                onRefresh={loadData}
              />
            )}

            {currentPage === 'policies' && (
              <SecurityPolicies
                policies={policies}
                servers={servers}
                tools={tools}
                currentRole={currentRole}
                onRefresh={loadData}
              />
            )}

            {currentPage === 'monitor' && (
              <RuntimeMonitor
                servers={servers}
                tools={tools}
                identities={identities}
                currentRole={currentRole}
                recentRequests={requests}
                onRefresh={loadData}
              />
            )}

            {currentPage === 'threats' && (
              <ThreatDetection events={events} />
            )}

            {currentPage === 'dlp' && (
              <DataProtectionDLP findings={findings} />
            )}

            {currentPage === 'approvals' && (
              <ApprovalCentre
                approvals={approvals}
                currentRole={currentRole}
                onRefresh={loadData}
              />
            )}

            {currentPage === 'incidents' && (
              <SecurityIncidents
                incidents={incidents}
                currentRole={currentRole}
                onRefresh={loadData}
                onViewAuditTrail={() => setCurrentPage('audit')}
              />
            )}

            {currentPage === 'audit' && (
              <AuditTrail events={events} />
            )}

            {currentPage === 'supply-chain' && (
              <SupplyChainScanner />
            )}

            {currentPage === 'testing-lab' && (
              <SecurityTestingLab
                scenarios={scenarios}
                testRuns={testRuns}
                currentRole={currentRole}
                onRefresh={loadData}
                onViewReports={() => setCurrentPage('reports')}
              />
            )}

            {currentPage === 'reports' && (
              <TestResultsReports
                testRuns={testRuns}
                scenarios={scenarios}
              />
            )}

            {currentPage === 'settings' && (
              <SettingsView
                currentRole={currentRole}
                onResetDemo={handleResetSandbox}
                isResetting={isResetting}
              />
            )}
          </div>
        </main>
      </div>

      {/* Section 33 Master Demonstration Walkthrough Modal */}
      <PrimaryDemoModal
        isOpen={isDemoModalOpen}
        onClose={() => setIsDemoModalOpen(false)}
        onNavigateTo={(page) => setCurrentPage(page)}
        onRefreshData={loadData}
      />
    </div>
  );
}
