/**
 * OmniVault BCS — Frontend Application
 * Full-Stack Client Layer connecting to Python REST API
 * Supports Multi-Theme, Multi-Domain, Dedicated Uploader & Requester Portals,
 * Multi-Tenant Organizations, Technical Estimator, and Emergency Break-Glass.
 */

// --- API Service Layer ---
const API_BASE = (window.location.protocol === 'file:' || !window.location.origin || window.location.origin === 'null')
  ? 'http://localhost:8000/api'
  : `${window.location.origin}/api`;

const api = {
  async get(endpoint, params = {}) {
    const url = new URL(`${API_BASE}${endpoint}`);
    Object.keys(params).forEach(k => {
      if (params[k] !== undefined && params[k] !== null) {
        url.searchParams.append(k, params[k]);
      }
    });
    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async post(endpoint, data = {}) {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(data)
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(json.error || `HTTP ${res.status}`);
    }
    return json;
  }
};

// --- Application State ---
const state = {
  currentView: 'dashboard',
  activeUserId: 'sarah_cfo',
  activeTheme: localStorage.getItem('omnivault_theme') || 'cyber',
  users: [],
  files: [],
  organizations: [],
  customClassifications: [],
  activeOrgId: null,
  activeOrgPageId: 'org_hospital',
  authenticatedOrgs: new Set(['org_general']),
  activeFileSession: null,
  sessionInterval: null,
  emergencyIncidents: [],
  emergencyLockdowns: [],
  auditLogs: [],
  overview: null,
  benchmarks: null,
  uploadMode: 'file', // 'file' or 'text'
  selectedFile: null,  // { file, base64, name, size, type }
  lastDecrypted: null,  // { plaintext, base64Data, fileName, mimeType, isBinary, size }
  activeCountdownInterval: null,
  targetProofData: null,
  currentModalUserForVc: null
};

// --- Utility Helpers ---
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTime(timestamp) {
  if (!timestamp) return '--';
  const d = new Date(timestamp * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString();
}

// --- Toast Notifications ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span style="font-size:1.15rem; font-weight:800;">
      ${type === 'success' ? '✓' : type === 'error' ? '✕' : type === 'warning' ? '⚠' : 'ℹ'}
    </span>
    <div style="flex:1; line-height:1.4;">${escapeHtml(message)}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// --- Theme Management ---
function applyTheme(themeName) {
  state.activeTheme = themeName;
  localStorage.setItem('omnivault_theme', themeName);
  document.body.className = `theme-${themeName}`;

  document.querySelectorAll('.theme-opt-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-theme') === themeName);
  });
}

// --- Navigation & View Switching ---
function switchView(viewName) {
  // Backward compatibility alias routing
  if (viewName === 'upload') viewName = 'uploader';
  if (viewName === 'access') viewName = 'requester';
  if (viewName === 'revocation') viewName = 'uploader';

  state.currentView = viewName;
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-view') === viewName);
  });

  document.querySelectorAll('.content-view').forEach(el => {
    el.style.display = 'none';
  });

  const activeEl = document.getElementById(`view-${viewName}`);
  if (activeEl) {
    activeEl.style.display = 'block';
  }

  // Update breadcrumb
  const titles = {
    dashboard: 'Executive Overview',
    uploader: 'Data Uploader Studio',
    requester: 'Access Requester Portal',
    organizations: 'Organizations Hub',
    'org-portal': 'Dedicated Organization Page',
    estimator: 'Technical Performance Estimator',
    emergency: 'Emergency Break-Glass Console',
    files: 'Cloud File Repository',
    users: 'Identity & Cryptographic Attributes',
    audit: 'Immutable On-Chain Audit Log',
    benchmarks: 'Performance & Gas Benchmarks'
  };
  const titleEl = document.getElementById('breadcrumb-current');
  if (titleEl) titleEl.textContent = titles[viewName] || viewName;

  // Refresh view specific data
  if (viewName === 'dashboard') loadDashboard();
  if (viewName === 'uploader') renderUploaderFilesTable();
  if (viewName === 'requester') renderRequesterFilesTable();
  if (viewName === 'organizations') renderOrganizationCards();
  if (viewName === 'org-portal') renderOrgPortal();
  if (viewName === 'estimator') computeLiveEstimates();
  if (viewName === 'emergency') refreshEmergencyConsole();
  if (viewName === 'files') renderFilesTable();
  if (viewName === 'users') renderUsersTable();
  if (viewName === 'audit') loadAuditLogs();
  if (viewName === 'benchmarks') loadBenchmarks();

  // Close mobile sidebar if open
  document.getElementById('sidebar')?.classList.remove('mobile-open');
}

// --- User & Identity Sync ---
async function loadUsers() {
  try {
    state.users = await api.get('/users');
    document.getElementById('nav-user-count').textContent = state.users.length;

    // Check if activeUserId exists in list
    if (!state.users.some(u => u.userId === state.activeUserId) && state.users.length > 0) {
      state.activeUserId = state.users[0].userId;
    }

    populateUserSelects();
    updateActiveUserDisplay();
  } catch (err) {
    console.error('Failed to load users:', err);
  }
}

function populateUserSelects() {
  const activeSelect = document.getElementById('active-user-select');
  const uploaderOwner = document.getElementById('upload-owner');
  const issueUserSelect = document.getElementById('issue-attr-user-select');

  const optionsHtml = state.users.map(u => 
    `<option value="${u.userId}" ${u.userId === state.activeUserId ? 'selected' : ''}>${escapeHtml(u.name)} (${escapeHtml(u.role)})</option>`
  ).join('');

  if (activeSelect) activeSelect.innerHTML = optionsHtml;
  if (uploaderOwner) uploaderOwner.innerHTML = optionsHtml;
  if (issueUserSelect) issueUserSelect.innerHTML = optionsHtml;
}

function updateActiveUserDisplay() {
  const current = state.users.find(u => u.userId === state.activeUserId);
  if (!current) return;

  // Header User Capsule
  const headerName = document.getElementById('header-user-name');
  const headerOrg = document.getElementById('header-user-org');
  const headerAvatar = document.getElementById('header-user-avatar');
  if (headerName) headerName.textContent = current.name;
  if (headerOrg) {
    const org = state.organizations.find(o => o.orgId === current.organizationId);
    headerOrg.textContent = org ? org.name : (current.organizationId || 'Enterprise Commons');
  }
  if (headerAvatar) headerAvatar.textContent = (current.name || current.userId).charAt(0).toUpperCase();

  // Sidebar Authenticated Card
  const sbUsername = document.getElementById('sidebar-auth-username');
  const sbClearance = document.getElementById('sidebar-auth-clearance-badge');
  if (sbUsername) sbUsername.textContent = `${current.name} (${current.userId})`;
  if (sbClearance) sbClearance.textContent = current.clearance || 'Level-3';

  // Sidebar Role Badge & Role Switcher
  const activeRole = current.activeRole || current.role;
  const roleBadge = document.getElementById('active-user-role-badge');
  if (roleBadge) roleBadge.textContent = `${activeRole} • ${current.department}`;

  const roleSelect = document.getElementById('active-user-role-select');
  if (roleSelect) {
    const roles = (current.roles && current.roles.length > 0) ? current.roles : [current.role];
    roleSelect.innerHTML = roles.map(r => 
      `<option value="${escapeHtml(r)}" ${r === activeRole ? 'selected' : ''}>Role: ${escapeHtml(r)}</option>`
    ).join('');
  }

  // Sidebar Attributes
  const attrBox = document.getElementById('active-user-attrs');
  if (attrBox) {
    attrBox.innerHTML = (current.attributes || []).map(a => 
      `<span class="policy-chip match">${escapeHtml(a)}</span>`
    ).join('');
  }

  // Uploader Tab Display
  const uploaderIdLabel = document.getElementById('uploader-current-id');
  if (uploaderIdLabel) uploaderIdLabel.textContent = `${current.userId} (${current.name})`;

  // Requester Tab Display
  const reqName = document.getElementById('requester-name-display');
  const reqDid = document.getElementById('requester-did-display');
  const reqAvatar = document.getElementById('requester-avatar');
  const reqOrgBadge = document.getElementById('requester-org-badge');
  const reqClearance = document.getElementById('requester-clearance-badge');
  const reqAttrsPills = document.getElementById('requester-attrs-pill-box');

  if (reqName) reqName.textContent = current.name;
  if (reqDid) reqDid.textContent = current.did || `did:bcs:${current.userId}`;
  if (reqAvatar) reqAvatar.textContent = (current.name || current.userId).charAt(0).toUpperCase();
  if (reqOrgBadge) reqOrgBadge.textContent = `Org: ${current.organizationId || 'General'}`;
  if (reqClearance) reqClearance.textContent = current.clearance || 'Level-3';

  if (reqAttrsPills) {
    reqAttrsPills.innerHTML = (current.attributes || []).map(a => 
      `<span class="policy-chip match" style="font-size:0.75rem;">${escapeHtml(a)}</span>`
    ).join('') || '<span style="font-size:0.75rem; color:var(--text-dim);">No attributes assigned yet.</span>';
  }

  // Refresh current view if applicable
  if (state.currentView === 'uploader') renderUploaderFilesTable();
  if (state.currentView === 'requester') renderRequesterFilesTable();
}

// --- Organizations & Workspaces ---
async function loadOrganizations() {
  try {
    state.organizations = await api.get('/organizations');
    document.getElementById('nav-org-count').textContent = state.organizations.length;
    populateOrgSelects();
    renderOrganizationCards();
  } catch (err) {
    console.error('Failed to load organizations:', err);
  }
}

function populateOrgSelects() {
  const uploadOrgSelect = document.getElementById('upload-organization-select');
  const newUserOrgSelect = document.getElementById('new-user-org');
  const reqOrgFilter = document.getElementById('requester-org-filter');
  const frontdoorRegOrg = document.getElementById('frontdoor-reg-org');

  const defaultOrgs = [
    { orgId: 'org_hospital', name: 'Metro General Hospital', sector: 'Healthcare & Clinical PHI' },
    { orgId: 'org_defense', name: 'Defense Cyber Command (DoD / Army)', sector: 'Defense & Military' },
    { orgId: 'org_apex', name: 'Apex Financial Corp', sector: 'FinTech & Sovereign Assets' },
    { orgId: 'org_cyber_labs', name: 'Quantum Cyber Labs', sector: 'Research & Advanced Tech' },
    { orgId: 'org_general', name: 'General Public Commons', sector: 'Open Public Workspace' }
  ];

  const orgList = (Array.isArray(state.organizations) && state.organizations.length > 0)
    ? state.organizations
    : defaultOrgs;

  const options = orgList.map(o => 
    `<option value="${o.orgId}">${escapeHtml(o.name)} (${escapeHtml(o.sector)})</option>`
  ).join('');

  if (uploadOrgSelect) uploadOrgSelect.innerHTML = options;
  if (newUserOrgSelect) newUserOrgSelect.innerHTML = options;
  if (frontdoorRegOrg) frontdoorRegOrg.innerHTML = options;
  if (reqOrgFilter) {
    reqOrgFilter.innerHTML = '<option value="all">All Organizations</option>' + options;
  }
}

function renderOrganizationCards() {
  const container = document.getElementById('org-cards-container');
  if (!container) return;

  container.innerHTML = state.organizations.map(org => {
    const isUnlocked = state.activeOrgId === org.orgId || !org.requirePassword;
    const isLockedDown = org.isLockedDown;
    return `
      <div class="org-card ${state.activeOrgId === org.orgId ? 'active-workspace' : ''}">
        <div class="org-card-header">
          <span class="org-sector-tag">${escapeHtml(org.sector)}</span>
          ${org.requirePassword
            ? `<span class="badge badge-amber">🔒 Password Required</span>`
            : `<span class="badge badge-emerald">🌐 Public Open</span>`}
        </div>
        <div>
          <h3 style="font-size:1.15rem; font-weight:800; color:var(--text-main);">${escapeHtml(org.name)}</h3>
          <p style="font-size:0.8rem; color:var(--text-muted); margin-top:4px;">${escapeHtml(org.description)}</p>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:var(--text-dim); border-top:1px solid var(--border-subtle); padding-top:10px;">
          <span>Workers: <strong>${org.userCount || org.workerCount || 1}</strong></span>
          <span>Files: <strong>${org.fileCount || 0}</strong></span>
          <span>Min: <strong>${escapeHtml(org.minClearance || 'Level-1')}</strong></span>
        </div>
        <div style="display:flex; gap:8px; margin-top:auto;">
          <button class="header-btn btn-sm btn-primary" style="flex:1; justify-content:center;" onclick="openDedicatedOrgPage('${org.orgId}')">
            <span>Enter Org Page ↗</span>
          </button>
          <button class="header-btn btn-sm ${isUnlocked ? 'btn-teal' : 'btn-secondary'}" style="flex:1; justify-content:center;" onclick="enterOrganizationWorkspace('${org.orgId}')">
            ${isUnlocked ? 'Quick View' : 'Authenticate 🔒'}
          </button>
        </div>
      </div>
    `;
  }).join('');
}

let pendingOrgToUnlock = null;
window.enterOrganizationWorkspace = function(orgId) {
  const org = state.organizations.find(o => o.orgId === orgId);
  if (!org) return;

  if (!org.requirePassword || state.activeOrgId === orgId) {
    // Open workspace directly
    openOrgWorkspacePartition(org);
    return;
  }

  // Prompt worker password
  pendingOrgToUnlock = org;
  document.getElementById('verify-worker-modal-title').textContent = `Unlock: ${org.name}`;
  document.getElementById('verify-worker-password-input').value = '';
  document.getElementById('modal-verify-worker')?.classList.add('active');
};

function openOrgWorkspacePartition(org) {
  state.activeOrgId = org.orgId;
  const partition = document.getElementById('org-workspace-partition');
  if (!partition) return;

  partition.style.display = 'block';
  document.getElementById('active-org-sector-tag').textContent = org.sector;
  document.getElementById('active-org-name-title').textContent = `${org.name} Workspace`;
  document.getElementById('active-org-desc').textContent = org.description;

  // Filter files belonging to this org
  const orgFiles = state.files.filter(f => f.organizationId === org.orgId);
  const tbody = document.getElementById('org-workspace-files-body');
  if (tbody) {
    if (orgFiles.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-dim);">No files uploaded in this organization yet.</td></tr>`;
    } else {
      tbody.innerHTML = orgFiles.map(f => `
        <tr>
          <td><span class="badge badge-blue font-mono">${escapeHtml(f.fileId)}</span></td>
          <td>
            <strong style="color:var(--text-main);">${escapeHtml(f.fileName)}</strong>
            <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(f.description)}</div>
          </td>
          <td><span class="badge badge-indigo">${escapeHtml(f.owner)}</span></td>
          <td>${renderImportanceBadge(f.importanceLevel)}</td>
          <td>${f.requiredAttrs.map(a => `<span class="policy-chip">${escapeHtml(a)}</span>`).join('')}</td>
          <td>${f.revokedAll ? '<span class="badge badge-coral">Revoked</span>' : '<span class="badge badge-emerald">Active</span>'}</td>
          <td>
            <button class="header-btn btn-sm btn-primary" onclick="quickRequestAccess('${f.fileId}')">Access</button>
          </td>
        </tr>
      `).join('');
    }
  }

  renderOrganizationCards();
  showToast(`Unlocked workspace: ${org.name}`, 'success');
}

window.openDedicatedOrgPage = function(orgId) {
  state.activeOrgPageId = orgId;
  switchView('org-portal');
};

// --- Dedicated Organization Page Implementation ---
async function renderOrgPortal() {
  const orgSelect = document.getElementById('org-portal-select');
  if (orgSelect && state.organizations.length > 0) {
    orgSelect.innerHTML = state.organizations.map(o => 
      `<option value="${o.orgId}" ${o.orgId === state.activeOrgPageId ? 'selected' : ''}>🏢 ${escapeHtml(o.name)}</option>`
    ).join('');
  }

  const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId) || state.organizations[0];
  if (!activeOrg) return;

  state.activeOrgPageId = activeOrg.orgId;

  const isUnlocked = !activeOrg.requirePassword || state.authenticatedOrgs.has(activeOrg.orgId) || (state.tempAuthenticatedOrg === activeOrg.orgId);
  const gateEl = document.getElementById('org-gate-container');
  const unlockedEl = document.getElementById('org-unlocked-container');
  const badgeEl = document.getElementById('nav-org-portal-badge');

  if (!isUnlocked) {
    if (gateEl) gateEl.style.display = 'block';
    if (unlockedEl) unlockedEl.style.display = 'none';
    if (badgeEl) {
      badgeEl.textContent = 'Locked 🔒';
      badgeEl.style.background = 'var(--coral-danger)';
    }

    document.getElementById('gate-sector-badge').textContent = activeOrg.sector || 'Private Enclave';
    document.getElementById('gate-org-title').textContent = `${activeOrg.name} Workspace`;
    const creatorEl = document.getElementById('gate-org-creator');
    if (creatorEl) creatorEl.textContent = activeOrg.creator || 'dr_priya';
    const whitelistEl = document.getElementById('gate-whitelisted-count');
    const authList = (activeOrg.authorizedMembers || []).filter(m => m !== '*');
    if (whitelistEl) whitelistEl.textContent = `${authList.length} verified personnel roster`;
    document.getElementById('gate-allowed-roles').textContent = (activeOrg.allowedRoles || ['Staff']).join(', ');
    document.getElementById('gate-min-clearance').textContent = activeOrg.minClearance || 'Level-2';

    // Populate worker select in gate: group by Whitelisted vs Outsider
    const gateUserSelect = document.getElementById('gate-worker-user-select');
    if (gateUserSelect) {
      const authorizedSet = new Set(authList);
      const authorizedUsers = state.users.filter(u => authorizedSet.has(u.userId));
      const outsiderUsers = state.users.filter(u => !authorizedSet.has(u.userId));

      let optHtml = '';
      if (authorizedUsers.length > 0) {
        optHtml += `<optgroup label="✅ Whitelisted Organization Personnel (${authorizedUsers.length})">` +
          authorizedUsers.map(u => 
            `<option value="${u.userId}" ${u.userId === state.activeUserId ? 'selected' : ''}>${escapeHtml(u.name)} (${escapeHtml(u.role)}) [${escapeHtml(u.userId)}]</option>`
          ).join('') + `</optgroup>`;
      } else if (authList.length > 0) {
        optHtml += `<optgroup label="✅ Whitelisted Organization Personnel (${authList.length})">` +
          authList.map(uid => 
            `<option value="${uid}">${escapeHtml(uid)} (Whitelisted)</option>`
          ).join('') + `</optgroup>`;
      }

      if (outsiderUsers.length > 0) {
        optHtml += `<optgroup label="⛔ Outsiders / Non-Whitelisted (Security Rejection Test)">` +
          outsiderUsers.map(u => 
            `<option value="${u.userId}">⚠️ ${escapeHtml(u.name)} (${escapeHtml(u.role)}) [Outsider - Will Be Blocked]</option>`
          ).join('') + `</optgroup>`;
      }
      gateUserSelect.innerHTML = optHtml;
    }
  } else {
    if (gateEl) gateEl.style.display = 'none';
    if (unlockedEl) unlockedEl.style.display = 'block';
    if (badgeEl) {
      badgeEl.textContent = 'Active ✓';
      badgeEl.style.background = 'var(--emerald-success)';
    }

    // Update Hero Banner
    document.getElementById('portal-org-name').textContent = activeOrg.name;
    document.getElementById('portal-org-desc').textContent = activeOrg.description || `${activeOrg.name} dedicated private workspace.`;

    const activeUser = state.users.find(u => u.userId === state.activeUserId) || state.users[0];
    if (activeUser) {
      document.getElementById('portal-worker-avatar').textContent = (activeUser.name || 'W').charAt(0).toUpperCase();
      document.getElementById('portal-worker-name').textContent = activeUser.name;
      document.getElementById('portal-worker-role').textContent = `${activeUser.role} • ${activeOrg.name}`;
    }

    // Load Files for this Org
    const orgFiles = state.files.filter(f => f.organizationId === activeOrg.orgId);
    document.getElementById('portal-file-count').textContent = orgFiles.length;

    const filesTbody = document.getElementById('org-portal-files-tbody');
    if (filesTbody) {
      if (orgFiles.length === 0) {
        filesTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-dim);">No files in this organization repository yet. Use the Worker Uploader tab above to encrypt and add documents.</td></tr>`;
      } else {
        filesTbody.innerHTML = orgFiles.map(f => {
          const myAttrs = new Set((activeUser ? activeUser.attributes : []));
          const hasAll = f.requiredAttrs.every(a => myAttrs.has(a));
          return `
            <tr>
              <td><span class="badge badge-blue font-mono">${escapeHtml(f.fileId)}</span></td>
              <td>
                <div style="font-weight:700; color:var(--text-main);">${escapeHtml(f.fileName)}</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(f.description)}</div>
              </td>
              <td><span class="badge badge-teal">${escapeHtml(f.owner)}</span></td>
              <td>${renderImportanceBadge(f.importanceLevel)}</td>
              <td><div>${f.requiredAttrs.map(a => `<span class="policy-chip ${myAttrs.has(a)?'match':'missing'}">${escapeHtml(a)}</span>`).join('')}</div></td>
              <td>${f.revokedAll ? '<span class="badge badge-coral">Locked Down</span>' : (hasAll ? '<span class="badge badge-emerald">Authorized ✓</span>' : '<span class="badge badge-amber">Restricted</span>')}</td>
              <td>
                <div style="display:flex; gap:6px;">
                  <button class="header-btn btn-sm btn-primary" onclick="quickRequestAccess('${f.fileId}')">Access</button>
                  <button class="header-btn btn-sm btn-teal" onclick="decryptInOrgPortal('${f.fileId}')">Decrypt & View</button>
                </div>
              </td>
            </tr>
          `;
        }).join('');
      }
    }

    // Load Authorized Members for this Org
    try {
      const members = await api.get(`/organizations/${activeOrg.orgId}/members`);
      document.getElementById('portal-worker-count').textContent = members.length;
      const workersContainer = document.getElementById('org-workers-list-container');
      if (workersContainer) {
        if (members.length === 0) {
          workersContainer.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-dim);">No workers registered specifically under this organization yet. Click "+ Add Worker to this Organization" to whitelist personnel.</div>`;
        } else {
          workersContainer.innerHTML = members.map(w => {
            const isCreator = w.isCreator || w.userId === activeOrg.creator;
            return `
              <div class="org-worker-row" style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:var(--bg-surface); border-radius:var(--radius-md); margin-bottom:8px; border:1px solid var(--border-subtle);">
                <div style="display:flex; align-items:center; gap:12px;">
                  <div class="user-avatar" style="width:38px; height:38px; font-size:0.85rem;">${(w.name || w.userId).charAt(0).toUpperCase()}</div>
                  <div>
                    <div style="font-weight:700; color:var(--text-main); display:flex; align-items:center; gap:8px;">
                      ${escapeHtml(w.name || w.userId)} 
                      <span style="font-size:0.75rem; color:var(--text-dim); font-family:monospace;">(${escapeHtml(w.userId)})</span>
                      ${isCreator ? '<span class="badge badge-amber" style="font-size:0.68rem; padding:2px 6px;">👑 Creator / Admin</span>' : '<span class="badge badge-emerald" style="font-size:0.68rem; padding:2px 6px;">Whitelisted Worker ✓</span>'}
                    </div>
                    <div style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">${escapeHtml(w.role || 'Staff')} • ${escapeHtml(w.department || activeOrg.sector || 'General')}</div>
                  </div>
                </div>
                <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                  <span class="badge badge-indigo">${escapeHtml(w.clearance || 'Level-2 Restricted')}</span>
                  <div style="display:flex; gap:4px;">${(w.attributes || []).map(a => `<span class="policy-chip match" style="font-size:0.72rem;">${escapeHtml(a)}</span>`).join('')}</div>
                  <button type="button" class="header-btn btn-sm btn-primary" onclick="openEditOrgMemberModal('${activeOrg.orgId}', '${w.userId}', '${escapeHtml(w.role || '')}', '${escapeHtml(w.clearance || 'Level-3')}')" style="padding:4px 8px; font-size:0.72rem;" title="Edit member role and confidentiality clearance">
                    ✏️ Edit
                  </button>
                  ${!isCreator ? `
                    <button type="button" class="header-btn btn-sm btn-secondary" onclick="removeOrgMember('${activeOrg.orgId}', '${w.userId}')" style="color:var(--coral-danger); border-color:rgba(239,68,68,0.3); padding:4px 8px; font-size:0.72rem;" title="Revoke member authorization">
                      Revoke Access
                    </button>
                  ` : ''}
                </div>
              </div>
            `;
          }).join('');
        }
      }
    } catch(e) {
      console.warn('Failed to load workers:', e);
    }

    // Load Org Specific Audit & Dwell Times
    try {
      const orgLogs = await api.get('/audit', { org: activeOrg.orgId });
      const auditTbody = document.getElementById('org-portal-audit-tbody');
      if (auditTbody) {
        if (orgLogs.length === 0) {
          auditTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-dim);">No access activity logged yet for this organization.</td></tr>`;
        } else {
          auditTbody.innerHTML = orgLogs.map(l => `
            <tr>
              <td>
                <div class="time-cell">
                  <span class="time-cell-primary">${escapeHtml(l.formattedTime || l.isoTimestamp || '--')}</span>
                  <span class="time-cell-sub">${escapeHtml(l.relativeTime || '')}</span>
                </div>
              </td>
              <td><span class="badge badge-blue font-mono">${escapeHtml(l.event)}</span></td>
              <td><span class="badge badge-indigo font-mono">${escapeHtml(l.fileId || '--')}</span></td>
              <td><strong>${escapeHtml(l.user || l.requester || l.caller || '--')}</strong></td>
              <td>
                ${l.event === 'FileSessionDuration'
                  ? `<span class="dwell-badge">⏱️ ${escapeHtml(l.formattedDwellTime || '2m 15s')} dwell</span>`
                  : (l.executionMs ? `<span class="badge badge-emerald font-mono">${l.executionMs}ms</span>` : `<span style="color:var(--text-dim); font-size:0.75rem;">--</span>`)}
              </td>
              <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${escapeHtml(l.details || l.action || l.justification || '')}
              </td>
              <td><button class="header-btn btn-sm btn-secondary" onclick="openMerkleProofModal(${l.logIndex})">Proof &rarr;</button></td>
            </tr>
          `).join('');
        }
      }
    } catch(e) {
      console.warn('Failed to load org logs:', e);
    }

    // Set Policy Presets for this org in Uploader subtab
    const presetBox = document.getElementById('org-upload-policy-presets');
    if (presetBox) {
      const presets = (activeOrg.allowedRoles || ['Doctor', 'Nurse']).map(r => `Role:${r}`);
      presetBox.innerHTML = presets.map(p => 
        `<button type="button" class="btn-sm btn-secondary" onclick="document.getElementById('org-upload-policy').value='${p}'">${p}</button>`
      ).join('');
    }
  }
}

// --- Organization Member Roster Management ---
window.removeOrgMember = async function(orgId, userId) {
  if (!confirm(`Are you sure you want to remove '${userId}' from this organization's authorized roster? They will no longer be able to access this workspace.`)) return;
  try {
    const res = await api.post(`/organizations/${orgId}/remove-member`, { userId, caller: state.activeUserId });
    if (res.success) {
      showToast(`Removed ${userId} from organization whitelist`, 'info');
      await loadOrganizations();
      await renderOrgPortal();
    }
  } catch(err) {
    showToast(`Failed to remove member: ${err.message}`, 'error');
  }
};

// --- Direct Decryption inside Dedicated Org Portal ---
window.decryptInOrgPortal = async function(fileId) {
  try {
    await api.post(`/files/${fileId}/request-access`, { requester: state.activeUserId }).catch(() => {});
    const res = await api.post(`/files/${fileId}/decrypt`, { userId: state.activeUserId });
    if (res.success) {
      state.lastDecrypted = res;
      showToast(`Decrypted ${res.fileName} inside Org Portal in ${res.decryptionTimeMs}ms!`, 'success');

      const box = document.getElementById('org-decrypt-result-box');
      const filenameEl = document.getElementById('org-decrypted-filename');
      const contentEl = document.getElementById('org-decrypted-content');

      if (box) box.style.display = 'block';
      if (filenameEl) filenameEl.textContent = `${res.fileName} (${formatBytes(res.size)})`;
      if (contentEl) {
        contentEl.textContent = res.isBinary
          ? `[Binary Encrypted Object recovered. Ready to download: ${res.fileName}]`
          : res.plaintext;
      }

      startFileDwellTimer(res.fileId, res.fileName, res.organizationId || state.activeOrgPageId, 'org');
      box?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else {
      showToast(`Decryption failed: ${res.error}`, 'error');
    }
  } catch (err) {
    showToast(`Decryption error: ${err.message}`, 'error');
  }
};

// --- Real-Time File Reading Dwell Stopwatch & Audit Logger ---
function startFileDwellTimer(fileId, fileName, orgId, target = 'requester') {
  if (state.sessionInterval) {
    clearInterval(state.sessionInterval);
    state.sessionInterval = null;
  }

  state.activeFileSession = {
    fileId,
    fileName,
    orgId,
    target,
    startTime: Date.now()
  };

  const updateStopwatch = () => {
    if (!state.activeFileSession) return;
    const elapsed = Math.floor((Date.now() - state.activeFileSession.startTime) / 1000);
    const m = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const s = String(elapsed % 60).padStart(2, '0');
    const str = `${m}:${s}`;
    const reqEl = document.getElementById('requester-session-stopwatch');
    const orgEl = document.getElementById('org-session-stopwatch');
    if (reqEl) reqEl.textContent = str;
    if (orgEl) orgEl.textContent = str;
  };

  updateStopwatch();
  state.sessionInterval = setInterval(updateStopwatch, 1000);
}

window.resetDecryptedSession = function() {
  if (state.sessionInterval) {
    clearInterval(state.sessionInterval);
    state.sessionInterval = null;
  }
  state.activeFileSession = null;
  state.lastDecrypted = null;

  // Requester Portal Decrypted Box
  const reqBox = document.getElementById('requester-decrypt-result-box');
  const reqFilename = document.getElementById('decrypted-result-filename');
  const reqContent = document.getElementById('decrypted-plaintext-content');
  const reqStopwatch = document.getElementById('requester-session-stopwatch');
  if (reqBox) reqBox.style.display = 'none';
  if (reqFilename) reqFilename.textContent = '';
  if (reqContent) reqContent.textContent = '';
  if (reqStopwatch) reqStopwatch.textContent = '00:00';

  // Org Portal Decrypted Box
  const orgBox = document.getElementById('org-decrypt-result-box');
  const orgFilename = document.getElementById('org-decrypted-filename');
  const orgContent = document.getElementById('org-decrypted-content');
  const orgStopwatch = document.getElementById('org-session-stopwatch');
  if (orgBox) orgBox.style.display = 'none';
  if (orgFilename) orgFilename.textContent = '';
  if (orgContent) orgContent.textContent = '';
  if (orgStopwatch) orgStopwatch.textContent = '00:00';
};

window.finishFileSession = async function() {
  if (!state.activeFileSession) {
    window.resetDecryptedSession();
    return;
  }
  const elapsedSec = Math.max(1, (Date.now() - state.activeFileSession.startTime) / 1000);
  const sessionData = { ...state.activeFileSession };

  // Immediately close and hide decrypted boxes from UI
  window.resetDecryptedSession();

  try {
    const res = await api.post('/audit/log-session', {
      fileId: sessionData.fileId,
      userId: state.activeUserId,
      dwellTimeSeconds: elapsedSec,
      action: 'File Reading & Diagnostic Review',
      details: `Active inspection session completed (${Math.round(elapsedSec)}s total dwell duration)`
    });
    showToast(`Logged ${res.formattedDwellTime || Math.round(elapsedSec) + 's'} spent on ${sessionData.fileName} to on-chain Merkle audit trail! File closed.`, 'success');
    await loadAuditLogs();
    if (state.currentView === 'org-portal') {
      renderOrgPortal();
    }
  } catch (err) {
    showToast(`File closed (audit trail notice: ${err.message})`, 'info');
  }
};

// --- Files Data ---
async function loadFiles() {
  try {
    state.files = await api.get('/files');
    document.getElementById('nav-file-count').textContent = state.files.length;
    renderFilesTable();
    renderUploaderFilesTable();
    renderRequesterFilesTable();
    populateEmergencyFilesSelect();
  } catch (err) {
    console.error('Failed to load files:', err);
  }
}

async function loadClassifications() {
  try {
    state.customClassifications = await api.get('/classifications');
    const select = document.getElementById('upload-importance');
    if (select) {
      const currentVal = select.value;
      select.innerHTML = state.customClassifications.map(c => 
        `<option value="${escapeHtml(c.label)}">${escapeHtml(c.label)} (${c.sensitivityScore}%)</option>`
      ).join('');
      if (currentVal && state.customClassifications.some(c => c.label === currentVal)) {
        select.value = currentVal;
      } else if (state.customClassifications.length > 1) {
        select.value = state.customClassifications[1].label;
      }
    }
  } catch (err) {
    console.error('Failed to load classifications:', err);
  }
}

function renderImportanceBadge(level) {
  if (level === 'Tier-0 Sovereign Critical') {
    return `<span class="badge badge-importance-t0">⚡ Tier-0 Sovereign</span>`;
  }
  if (level === 'Tier-1 High Enterprise') {
    return `<span class="badge badge-importance-t1">🛡️ Tier-1 Enterprise</span>`;
  }
  if (level === 'Tier-2 Medium Operational') {
    return `<span class="badge badge-importance-t2">🔒 Tier-2 Operational</span>`;
  }
  if (level === 'Tier-3 Standard Public') {
    return `<span class="badge badge-importance-t3">📄 Tier-3 Public</span>`;
  }
  const custom = (state.customClassifications || []).find(c => c.label === level || c.id === level);
  if (custom) {
    return `<span class="custom-classification-badge" style="background-color:${custom.color}22; border-color:${custom.color}; color:${custom.color};">🏷️ ${escapeHtml(custom.label)} (${custom.sensitivityScore}%)</span>`;
  }
  return `<span class="badge badge-indigo">🏷️ ${escapeHtml(level || 'Custom')}</span>`;
}

// 1. GLOBAL CLOUD REPOSITORY TABLE
function renderFilesTable() {
  const tbody = document.getElementById('files-table-body');
  if (!tbody) return;

  const search = document.getElementById('file-search-input')?.value.toLowerCase() || '';
  const filter = document.getElementById('file-status-filter')?.value || 'all';

  const filtered = state.files.filter(f => {
    if (filter === 'active' && f.revokedAll) return false;
    if (filter === 'revoked' && !f.revokedAll) return false;
    if (search) {
      const hay = `${f.fileId} ${f.fileName} ${f.owner} ${f.organizationId || ''} ${f.requiredAttrs.join(' ')}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:30px; color:var(--text-dim);">No matching cloud files found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(f => `
    <tr>
      <td><span class="badge badge-blue font-mono">${escapeHtml(f.fileId)}</span></td>
      <td>
        <div style="font-weight:700; color:var(--text-main);">${escapeHtml(f.fileName)}</div>
        <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(f.description)}</div>
      </td>
      <td><span class="badge badge-indigo">${escapeHtml(f.organizationId || 'org_general')}</span></td>
      <td>${renderImportanceBadge(f.importanceLevel)}</td>
      <td><span class="badge badge-teal">${escapeHtml(f.owner)}</span></td>
      <td>
        <div>${f.requiredAttrs.map(a => `<span class="policy-chip">${escapeHtml(a)}</span>`).join('')}</div>
      </td>
      <td>
        <span class="code-hash" title="${f.ipfsCid || f.contentHash}">
          ${f.ipfsCid ? 'ipfs://' + f.ipfsCid.substring(0, 10) + '...' : (f.contentHash ? f.contentHash.substring(0, 12) + '...' : '--')}
        </span>
      </td>
      <td>
        ${f.revokedAll
          ? '<span class="badge badge-coral">Revoked All</span>'
          : '<span class="badge badge-emerald">Active • Synced</span>'}
      </td>
      <td>
        <div style="display:flex; gap:6px;">
          <button class="header-btn btn-sm btn-primary" onclick="quickRequestAccess('${f.fileId}')">Access</button>
          <button class="header-btn btn-sm btn-teal" onclick="quickDecrypt('${f.fileId}')">Decrypt</button>
          <button class="header-btn btn-sm btn-secondary" onclick="openS3PresignModal('${f.fileId}')" title="Generate AWS S3 Presigned URL">S3</button>
        </div>
      </td>
    </tr>
  `).join('');
}

// 2. UPLOADER STUDIO FILES TABLE
function renderUploaderFilesTable() {
  const tbody = document.getElementById('uploader-files-table-body');
  if (!tbody) return;

  const myFiles = state.files.filter(f => f.owner === state.activeUserId);
  const countBadge = document.getElementById('uploader-files-count');
  if (countBadge) countBadge.textContent = `${myFiles.length} Owned Files`;

  if (myFiles.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--text-dim);">No files registered under ${state.activeUserId} yet. Upload an asset above!</td></tr>`;
    return;
  }

  tbody.innerHTML = myFiles.map(f => `
    <tr>
      <td>
        <strong style="color:var(--text-main); font-size:0.85rem;">${escapeHtml(f.fileName)}</strong>
        <div style="font-size:0.72rem; color:var(--text-muted); font-family:monospace;">${escapeHtml(f.fileId)}</div>
      </td>
      <td><span class="badge badge-indigo" style="font-size:0.68rem;">${escapeHtml(f.organizationId || 'General')}</span></td>
      <td>${renderImportanceBadge(f.importanceLevel)}</td>
      <td>
        ${f.revokedAll
          ? '<span class="badge badge-coral">Frozen</span>'
          : `<span class="badge badge-emerald">Active (${f.activeGrantsCount || 0} grants)</span>`}
      </td>
      <td>
        <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
          <button class="header-btn btn-sm btn-teal" onclick="quickDecrypt('${f.fileId}')" title="Decrypt File Plaintext">
            🔓 Decrypt
          </button>
          <button class="header-btn btn-sm btn-primary" onclick="openFileAccessModal('${f.fileId}')" title="Grant or revoke direct file decryption access for usernames">
            🔑 File Access
          </button>
          <button class="header-btn btn-sm btn-secondary" onclick="openFileLogViewersModal('${f.fileId}')" title="Manage who can see the audit log for this file">
            📋 Log Viewers
          </button>
          <button class="header-btn btn-sm btn-danger" onclick="openFileEmergencyWhitelistModal('${f.fileId}')" title="Whitelist usernames for emergency access">
            🚨 Whitelist
          </button>
          ${f.revokedAll
            ? `<button class="header-btn btn-sm btn-secondary" onclick="restoreFileAccess('${f.fileId}')">Restore</button>`
            : `<button class="header-btn btn-sm btn-danger" onclick="triggerFileKillSwitch('${f.fileId}')">Kill-Switch</button>`}
        </div>
      </td>
    </tr>
  `).join('');
}

// 3. REQUESTER PORTAL FILES TABLE
function renderRequesterFilesTable() {
  const tbody = document.getElementById('requester-files-table-body');
  if (!tbody) return;

  const search = document.getElementById('requester-search-input')?.value.toLowerCase() || '';
  const orgFilter = document.getElementById('requester-org-filter')?.value || 'all';
  const impFilter = document.getElementById('requester-importance-filter')?.value || 'all';

  const currentUser = state.users.find(u => u.userId === state.activeUserId);
  const myAttrs = new Set(currentUser ? currentUser.attributes : []);
  const myOrgId = currentUser ? currentUser.organizationId : 'org_general';
  const scope = state.requesterScope || 'all';

  // Update tab labels with user's org
  const myOrgTab = document.getElementById('scope-btn-my-org');
  if (myOrgTab && currentUser) {
    const orgObj = state.organizations.find(o => o.orgId === myOrgId);
    myOrgTab.textContent = `🏢 My Org (${orgObj ? orgObj.name : myOrgId})`;
  }

  const filtered = state.files.filter(f => {
    const isUniversal = f.isUniversal || f.organizationId === 'org_general';
    const isMyOrg = f.organizationId === myOrgId;
    const isEmergencyWhitelisted = (f.emergencyWhitelistedUsers || []).includes(state.activeUserId) || f.owner === state.activeUserId;

    // Multi-Tenant Zero-Trust Isolation:
    // Files of OTHER private organizations are NEVER visible to the requester
    if (!isUniversal && !isMyOrg && !isEmergencyWhitelisted) {
      return false;
    }

    // Segmented Scope Controls
    if (scope === 'universal' && !isUniversal) return false;
    if (scope === 'org' && (!isMyOrg || isUniversal)) return false;
    if (scope === 'emergency' && !isEmergencyWhitelisted) return false;

    if (orgFilter !== 'all' && f.organizationId !== orgFilter) return false;
    if (impFilter !== 'all' && f.importanceLevel !== impFilter) return false;
    if (search) {
      const hay = `${f.fileId} ${f.fileName} ${f.owner} ${f.description || ''} ${f.requiredAttrs.join(' ')}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-dim);">No files found for selected scope in your workspace (${escapeHtml(myOrgId)}).</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(f => {
    // Check if user satisfies required attributes
    const hasAll = f.requiredAttrs.every(a => myAttrs.has(a));
    const isOwner = (f.owner === state.activeUserId);
    const fileOrg = state.organizations.find(o => o.orgId === f.organizationId);
    const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);
    const isAuthorizedUser = (f.authorizedUsers || []).includes(state.activeUserId);
    const isGrantedOnChain = (f.activeGrants || []).includes(state.activeUserId) || isOwner || isAuthorizedUser;
    const isUniversal = f.isUniversal || f.organizationId === 'org_general';
    const isEmergencyWhitelisted = (f.emergencyWhitelistedUsers || []).includes(state.activeUserId) || isOwner || isCreator;

    return `
      <tr>
        <td><span class="badge badge-blue font-mono">${escapeHtml(f.fileId)}</span></td>
        <td>
          <div style="font-weight:700; color:var(--text-main);">${escapeHtml(f.fileName)}</div>
          <div style="font-size:0.74rem; color:var(--text-muted);">${escapeHtml(f.description)}</div>
          <div style="display:flex; gap:6px; margin-top:4px; flex-wrap:wrap;">
            ${isUniversal ? '<span class="badge badge-emerald" style="font-size:0.68rem;">🌐 Universal Commons (Public)</span>' : '<span class="badge badge-indigo" style="font-size:0.68rem;">🔒 Private Org Asset</span>'}
            ${isEmergencyWhitelisted ? '<span class="badge badge-coral" style="font-size:0.68rem;">🚨 Emergency Whitelisted</span>' : ''}
            ${isOwner ? '<span class="badge badge-emerald" style="font-size:0.68rem;">👑 File Owner</span>' : ''}
          </div>
        </td>
        <td><span class="badge badge-indigo">${escapeHtml(f.organizationId || 'org_general')}</span></td>
        <td>${renderImportanceBadge(f.importanceLevel)}</td>
        <td>
          <div>
            ${f.requiredAttrs.map(a => {
              const matched = myAttrs.has(a);
              return `<span class="policy-chip ${matched ? 'match' : 'missing'}">${escapeHtml(a)}</span>`;
            }).join('')}
          </div>
        </td>
        <td>
          ${f.revokedAll
            ? '<span class="badge badge-coral">File Locked Down</span>'
            : isOwner
              ? '<span class="badge badge-emerald">Owner ✓</span>'
              : (isGrantedOnChain || isAuthorizedUser)
                ? '<span class="badge badge-emerald">Authorized ✓</span>'
                : hasAll
                  ? '<span class="badge badge-teal">Policy Eligible</span>'
                  : '<span class="badge badge-coral">Missing Attrs</span>'}
        </td>
        <td>
          <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
            ${(isOwner || isGrantedOnChain || isAuthorizedUser) ? `
              <button class="header-btn btn-sm btn-teal" onclick="quickDecrypt('${f.fileId}')" title="Decrypt File Plaintext">
                🔓 Decrypt File
              </button>
            ` : `
              <button class="header-btn btn-sm btn-primary" onclick="quickRequestAccess('${f.fileId}')">
                Request Access
              </button>
              <button class="header-btn btn-sm btn-teal" onclick="quickDecrypt('${f.fileId}')">
                Decrypt File
              </button>
            `}
            ${(!hasAll || isEmergencyWhitelisted) && !f.revokedAll && !isOwner && !isGrantedOnChain && !isAuthorizedUser ? `
              <button class="header-btn btn-sm btn-danger" onclick="openRequesterBreakGlassModal('${f.fileId}')" title="Emergency Break-Glass Decryption Override">
                🚨 Break-Glass
              </button>
            ` : ''}
            ${(isOwner || isCreator) ? `
              <button class="header-btn btn-sm btn-primary" onclick="openFileAccessModal('${f.fileId}')" title="Grant or revoke direct file decryption access for usernames">
                🔑 File Access
              </button>
              <button class="header-btn btn-sm btn-secondary" onclick="openFileLogViewersModal('${f.fileId}')" title="Manage who can see the audit log for this file">
                📋 Log Viewers
              </button>
              <button class="header-btn btn-sm btn-danger" onclick="openFileEmergencyWhitelistModal('${f.fileId}')" title="Whitelist usernames for emergency access">
                🚨 Whitelist
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// --- Direct File Actions ---
window.quickRequestAccess = async function(fileId) {
  try {
    const res = await api.post(`/files/${fileId}/request-access`, {
      requester: state.activeUserId
    });

    if (res.granted) {
      showToast(`Access GRANTED by Smart Contract for ${fileId}!`, 'success');
    } else {
      showToast(`Access DENIED: ${res.reason || 'Missing required attributes'}`, 'warning');
    }

    await loadFiles();
    loadDashboard();
  } catch (err) {
    showToast(`Access request failed: ${err.message}`, 'error');
  }
};

window.quickDecrypt = async function(fileId) {
  try {
    // 1. First ensure on-chain request is executed
    await api.post(`/files/${fileId}/request-access`, { requester: state.activeUserId }).catch(() => {});

    // 2. Decrypt at cryptographic CP-ABE layer
    const res = await api.post(`/files/${fileId}/decrypt`, {
      userId: state.activeUserId
    });

    if (res.success) {
      state.lastDecrypted = res;
      showToast(`Decrypted ${res.fileName} locally in ${res.decryptionTimeMs}ms!`, 'success');

      // Surface result box in Requester Portal
      const box = document.getElementById('requester-decrypt-result-box');
      const filenameEl = document.getElementById('decrypted-result-filename');
      const contentEl = document.getElementById('decrypted-plaintext-content');

      if (box) box.style.display = 'block';
      if (filenameEl) filenameEl.textContent = `${res.fileName} (${formatBytes(res.size)})`;
      if (contentEl) {
        contentEl.textContent = res.isBinary
          ? `[Binary Encrypted Object recovered successfully. Ready to download: ${res.fileName}]`
          : res.plaintext;
      }

      // Start real-time file dwell session timer
      startFileDwellTimer(res.fileId, res.fileName, res.organizationId || 'org_general', 'requester');

      // Switch to requester view to see result if on another tab
      if (state.currentView !== 'requester') {
        switchView('requester');
      }

      contentEl?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else {
      showToast(`Decryption failed: ${res.error}`, 'error');
    }
  } catch (err) {
    showToast(`Decryption error: ${err.message}`, 'error');
  }
};

window.downloadLastDecryptedFile = function() {
  if (!state.lastDecrypted) {
    showToast('No decrypted file ready to download', 'warning');
    return;
  }

  const { fileName, isBinary, base64Data, plaintext, mimeType } = state.lastDecrypted;
  let blob;

  if (isBinary && base64Data) {
    const byteChars = atob(base64Data);
    const byteNumbers = new Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) {
      byteNumbers[i] = byteChars.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    blob = new Blob([byteArray], { type: mimeType || 'application/octet-stream' });
  } else {
    blob = new Blob([plaintext || ''], { type: mimeType || 'text/plain;charset=utf-8' });
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName.replace(/\.enc$/, '') || 'decrypted_file.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Downloaded: ${a.download}`, 'success');
};

window.triggerFileKillSwitch = async function(fileId) {
  try {
    await api.post(`/files/${fileId}/revoke-all`, { caller: state.activeUserId });
    showToast(`Emergency kill-switch enabled for file: ${fileId}`, 'warning');
    await loadFiles();
    loadDashboard();
  } catch (err) {
    showToast(`Kill-switch error: ${err.message}`, 'error');
  }
};

window.restoreFileAccess = async function(fileId) {
  try {
    await api.post(`/files/${fileId}/restore-all`, { caller: state.activeUserId });
    showToast(`Access restored for file: ${fileId}`, 'success');
    await loadFiles();
    loadDashboard();
  } catch (err) {
    showToast(`Restore error: ${err.message}`, 'error');
  }
};

// --- Technical Performance Estimator ---
function computeLiveEstimates() {
  const sizeInput = document.getElementById('slider-file-size');
  const attrsInput = document.getElementById('slider-attribute-count');
  const logicInput = document.getElementById('estimator-logic-type');
  const storageInput = document.getElementById('estimator-storage-backend');

  const sizeKb = parseFloat(sizeInput?.value || 5000);
  const attrs = parseInt(attrsInput?.value || 5);
  const logic = logicInput?.value || 'AND';
  const storage = storageInput?.value || 'IPFS';

  document.getElementById('est-size-display').textContent = sizeKb >= 1000
    ? `${(sizeKb / 1000).toFixed(1)} MB (${sizeKb.toLocaleString()} KB)`
    : `${sizeKb.toLocaleString()} KB`;
  document.getElementById('est-attrs-display').textContent = `${attrs} Attributes`;

  // Mathematical Client-Side Estimation
  const logicMult = logic === 'AND' ? 1.0 : (logic === 'OR' ? 1.35 : 1.6);
  const encLatency = (3.2 + (0.038 * sizeKb) + (0.85 * attrs * logicMult)).toFixed(2);
  const decLatency = (1.9 + (0.015 * sizeKb) + (0.42 * attrs * logicMult)).toFixed(2);
  const gasBase = 21000;
  const gasContract = 46200 + (11400 * attrs);
  const totalGas = Math.round(gasBase + gasContract);
  const gasUsd = ((totalGas * 25e-9) * 3450.0).toFixed(2);
  const merkleTimeUs = (12.4 + 3.2 * Math.log2(Math.max(attrs, 2))).toFixed(2);
  const speedup = Math.round((parseFloat(decLatency) * 45.0 + 180.0) / Math.max(0.12, parseFloat(decLatency) * 0.05));

  document.getElementById('res-enc-latency').textContent = `${encLatency} ms`;
  document.getElementById('res-dec-latency').textContent = `${decLatency} ms`;
  document.getElementById('res-gas-units').textContent = `${totalGas.toLocaleString()} gas`;
  document.getElementById('res-gas-cost').textContent = `~$${gasUsd} USD equivalent`;
  document.getElementById('res-merkle-time').textContent = `${merkleTimeUs} µs`;
  document.getElementById('res-speedup').textContent = `${speedup.toLocaleString()}x Faster`;
}

// --- Emergency Break-Glass & Lockdown ---
function populateEmergencyFilesSelect() {
  const select = document.getElementById('emergency-file-select');
  const lockdownSelect = document.getElementById('lockdown-target-select');

  if (select) {
    select.innerHTML = state.files.map(f => 
      `<option value="${f.fileId}">${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
    ).join('');
  }

  if (lockdownSelect) {
    let html = '<optgroup label="Organizations">';
    state.organizations.forEach(o => {
      html += `<option value="org:${o.orgId}">Organization: ${escapeHtml(o.name)}</option>`;
    });
    html += '</optgroup><optgroup label="Protected Files">';
    state.files.forEach(f => {
      html += `<option value="file:${f.fileId}">File: ${escapeHtml(f.fileName)}</option>`;
    });
    html += '</optgroup>';
    lockdownSelect.innerHTML = html;
  }
}

window.openBreakGlassForFile = function(fileId) {
  switchView('emergency');
  const select = document.getElementById('emergency-file-select');
  if (select) select.value = fileId;
  const incInput = document.getElementById('emergency-incident-id');
  if (incInput) incInput.value = `INC-ER-${Date.now().toString().slice(-6)}`;
};

async function handleEmergencyBreakGlassSubmit(e) {
  e.preventDefault();
  const fileId = document.getElementById('emergency-file-select')?.value;
  const incidentId = document.getElementById('emergency-incident-id')?.value.trim();
  const justification = document.getElementById('emergency-justification')?.value.trim();
  const ttlSeconds = parseInt(document.getElementById('emergency-ttl')?.value || 900);

  if (!fileId || !incidentId || !justification) {
    showToast('Please fill in all incident details', 'warning');
    return;
  }

  try {
    const res = await api.post('/emergency/break-glass', {
      fileId,
      requester: state.activeUserId,
      incidentId,
      justification,
      ttlSeconds,
      dualWitness: `DualWitness-Enclave-${state.activeUserId}`
    });

    showToast(`🚨 BREAK-GLASS GRANTED for ${fileId}!`, 'error');
    await loadFiles();
    await refreshEmergencyConsole();
    loadDashboard();
  } catch (err) {
    showToast(`Break-glass error: ${err.message}`, 'error');
  }
}

window.resolveEmergencyIncident = async function(incidentId, fileId) {
  try {
    const res = await api.post('/emergency/resolve', {
      incidentId,
      caller: state.activeUserId
    });
    showToast(`Emergency incident ${incidentId} terminated! Override closed.`, 'success');
    window.resetDecryptedSession();
    await refreshEmergencyConsole();
    await loadFiles();
    if (state.currentView === 'requester') renderRequesterFilesTable();
    if (state.currentView === 'uploader') renderUploaderFilesTable();
    await loadAuditLogs();
  } catch (err) {
    showToast(`Failed to resolve emergency: ${err.message}`, 'error');
  }
};

window.resolveAllEmergencies = async function() {
  try {
    const res = await api.post('/emergency/resolve-all', {
      caller: state.activeUserId
    });
    showToast(`All active emergency overrides terminated! System returned to normal zero-trust state.`, 'success');
    window.resetDecryptedSession();
    await refreshEmergencyConsole();
    await loadFiles();
    if (state.currentView === 'requester') renderRequesterFilesTable();
    if (state.currentView === 'uploader') renderUploaderFilesTable();
    await loadAuditLogs();
  } catch (err) {
    showToast(`Failed to terminate emergencies: ${err.message}`, 'error');
  }
};

async function refreshEmergencyConsole() {
  try {
    const status = await api.get('/emergency/status');
    const container = document.getElementById('active-incidents-container');
    const alertBanner = document.getElementById('emergency-header-alert');
    const alertDetails = document.getElementById('emergency-banner-details');
    const navBadge = document.getElementById('nav-emergency-counter');

    if (status.activeIncidentCount > 0) {
      const topInc = status.activeIncidents[0];
      if (alertBanner) alertBanner.style.display = 'flex';
      if (alertDetails) alertDetails.textContent = `Incident: ${topInc.incidentId} | File: ${topInc.fileName} | User: ${topInc.requester}`;
      if (navBadge) navBadge.style.display = 'inline-block';

      // Start countdown timer
      startCountdownTimer(topInc.expiresAt);

      if (container) {
        container.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; padding-bottom:8px; border-bottom:1px solid rgba(239,68,68,0.3);">
            <span style="font-size:0.85rem; font-weight:700; color:#ef4444;">Active Incidents (${status.activeIncidentCount})</span>
            <button type="button" class="header-btn btn-sm btn-danger" onclick="window.resolveAllEmergencies()" title="Terminate all active emergencies immediately">
              ⏹ Terminate All Emergencies
            </button>
          </div>
        ` + status.activeIncidents.map(inc => `
          <div style="background:var(--bg-card); border:1px solid #ef4444; border-radius:var(--radius-md); padding:14px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="badge badge-coral">INCIDENT: ${escapeHtml(inc.incidentId)}</span>
              <span style="font-family:monospace; color:#f87171; font-weight:700;">TTL: ${Math.max(0, Math.round((inc.expiresAt - Date.now()/1000)/60))} min left</span>
            </div>
            <div style="font-weight:700; color:var(--text-main); margin-top:6px;">Target: ${escapeHtml(inc.fileName)} (${escapeHtml(inc.fileId)})</div>
            <div style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">Actor: <strong>${escapeHtml(inc.requester)}</strong></div>
            <div style="font-size:0.78rem; color:#fca5a5; margin-top:6px; background:rgba(239,68,68,0.1); padding:6px 10px; border-radius:var(--radius-sm);">
              Justification: ${escapeHtml(inc.justification)}
            </div>
            <div style="display:flex; justify-content:flex-end; margin-top:10px;">
              <button type="button" class="header-btn btn-sm btn-danger" onclick="window.resolveEmergencyIncident('${escapeHtml(inc.incidentId)}', '${escapeHtml(inc.fileId)}')">
                ⏹ Resolve & Terminate Emergency
              </button>
            </div>
          </div>
        `).join('');
      }
    } else {
      if (alertBanner) alertBanner.style.display = 'none';
      if (navBadge) navBadge.style.display = 'none';
      if (container) {
        container.innerHTML = `
          <div style="padding:16px; background:var(--bg-surface); border-radius:var(--radius-md); text-align:center; color:var(--text-dim);">
            No active break-glass emergency incidents. Ledger is operating normally.
          </div>
        `;
      }
      if (state.activeCountdownInterval) {
        clearInterval(state.activeCountdownInterval);
      }
    }
  } catch (err) {
    console.error('Failed to refresh emergency status:', err);
  }
}

function startCountdownTimer(expiresAtEpoch) {
  if (state.activeCountdownInterval) clearInterval(state.activeCountdownInterval);

  function update() {
    const diff = Math.max(0, Math.floor(expiresAtEpoch - (Date.now() / 1000)));
    const mins = Math.floor(diff / 60).toString().padStart(2, '0');
    const secs = (diff % 60).toString().padStart(2, '0');
    const el = document.getElementById('emergency-banner-timer');
    if (el) el.textContent = `${mins}:${secs}`;
    if (diff <= 0) {
      clearInterval(state.activeCountdownInterval);
      refreshEmergencyConsole();
    }
  }

  update();
  state.activeCountdownInterval = setInterval(update, 1000);
}

// --- Dashboard & Analytics Charts ---
async function loadDashboard() {
  try {
    const overview = await api.get('/overview');
    state.overview = overview;

    // KPI numbers
    document.getElementById('kpi-files').textContent = overview.totalFiles;
    document.getElementById('kpi-grants').textContent = overview.grantsCount;
    document.getElementById('kpi-denials').textContent = overview.denialsCount;
    document.getElementById('kpi-users').textContent = overview.totalUsers;
    document.getElementById('kpi-gas').textContent = `${Math.round(overview.estimatedGasUsed / 1000)}k`;

    renderDecisionsChart(overview);
    renderGasChart();
  } catch (err) {
    console.error('Failed to load dashboard:', err);
  }
}

function renderDecisionsChart(overview) {
  const container = document.getElementById('chart-decisions');
  if (!container) return;

  const grants = overview.grantsCount || 1;
  const denials = overview.denialsCount || 1;
  const uploads = overview.uploadsCount || 1;
  const revocations = overview.revocationsCount || 1;
  const total = grants + denials + uploads + revocations;

  const gPct = Math.round((grants / total) * 100);
  const dPct = Math.round((denials / total) * 100);
  const uPct = Math.round((uploads / total) * 100);
  const rPct = Math.round((revocations / total) * 100);

  container.innerHTML = `
    <div style="width:100%; display:flex; flex-direction:column; gap:16px;">
      <div style="display:flex; justify-content:space-around; align-items:flex-end; height:150px; padding-top:10px;">
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
          <div style="font-size:0.75rem; font-weight:700; color:var(--emerald-success);">${grants} (${gPct}%)</div>
          <div style="width:48px; height:${Math.max(20, gPct * 1.2)}px; background:var(--grad-success); border-radius:6px 6px 0 0; box-shadow:var(--glow-emerald);"></div>
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Grants</div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
          <div style="font-size:0.75rem; font-weight:700; color:var(--coral-danger);">${denials} (${dPct}%)</div>
          <div style="width:48px; height:${Math.max(20, dPct * 1.2)}px; background:var(--grad-danger); border-radius:6px 6px 0 0; box-shadow:var(--glow-coral);"></div>
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Denials</div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
          <div style="font-size:0.75rem; font-weight:700; color:var(--royal-blue-light);">${uploads} (${uPct}%)</div>
          <div style="width:48px; height:${Math.max(20, uPct * 1.2)}px; background:var(--grad-primary); border-radius:6px 6px 0 0; box-shadow:var(--glow-blue);"></div>
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Uploads</div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
          <div style="font-size:0.75rem; font-weight:700; color:var(--amber-warning);">${revocations} (${rPct}%)</div>
          <div style="width:48px; height:${Math.max(20, rPct * 1.2)}px; background:var(--grad-warning); border-radius:6px 6px 0 0;"></div>
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Revokes</div>
        </div>
      </div>
      <div style="display:flex; justify-content:center; gap:16px; font-size:0.75rem; color:var(--text-dim);">
        <span>Smart contract policy evaluation pipeline • 100% automated</span>
      </div>
    </div>
  `;
}

function renderGasChart() {
  const container = document.getElementById('chart-gas');
  if (!container) return;

  container.innerHTML = `
    <div style="width:100%; display:flex; flex-direction:column; gap:12px;">
      <div style="display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
          <span style="color:var(--text-muted);">uploadFile()</span>
          <span style="font-family:monospace; color:var(--royal-blue-light); font-weight:700;">118,542 gas</span>
        </div>
        <div style="height:8px; background:var(--border-subtle); border-radius:4px; overflow:hidden;">
          <div style="width:90%; height:100%; background:var(--grad-primary);"></div>
        </div>
      </div>

      <div style="display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
          <span style="color:var(--text-muted);">requestAccess() [Granted]</span>
          <span style="font-family:monospace; color:var(--emerald-success); font-weight:700;">46,210 gas</span>
        </div>
        <div style="height:8px; background:var(--border-subtle); border-radius:4px; overflow:hidden;">
          <div style="width:38%; height:100%; background:var(--grad-success);"></div>
        </div>
      </div>

      <div style="display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
          <span style="color:var(--text-muted);">revokeAccess()</span>
          <span style="font-family:monospace; color:var(--amber-warning); font-weight:700;">28,430 gas</span>
        </div>
        <div style="height:8px; background:var(--border-subtle); border-radius:4px; overflow:hidden;">
          <div style="width:24%; height:100%; background:var(--grad-warning);"></div>
        </div>
      </div>
    </div>
  `;
}

function renderUsersTable() {
  const tbody = document.getElementById('users-table-body');
  if (!tbody) return;

  tbody.innerHTML = state.users.map(u => {
    const activeR = u.activeRole || u.role;
    const userRoles = (u.roles && u.roles.length > 0) ? u.roles : [u.role];

    return `
    <tr>
      <td>
        <span class="badge badge-teal font-mono">${escapeHtml(u.userId)}</span>
        <div style="font-size:0.68rem; color:var(--royal-blue-light); margin-top:3px; font-family:monospace; max-width:180px; overflow:hidden; text-overflow:ellipsis;" title="${u.did}">${escapeHtml(u.did || 'did:bcs:...')}</div>
      </td>
      <td>
        <strong style="color:var(--text-main);">${escapeHtml(u.name)}</strong>
        <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(u.email || '--')}</div>
      </td>
      <td>
        <div style="display:flex; flex-wrap:wrap; gap:4px; align-items:center;">
          ${userRoles.map(r => `
            <span class="badge ${r === activeR ? 'badge-emerald' : 'badge-indigo'}" title="${r === activeR ? 'Active Role' : 'Assigned Role'}">
              ${escapeHtml(r)}${r === activeR ? ' ✓' : ''}
            </span>
          `).join('')}
          <button type="button" class="btn-sm btn-outline" style="font-size:0.68rem; padding:1px 6px; cursor:pointer;" onclick="openAddRoleModalFor('${u.userId}')" title="Add another role to this identity">+ Add Role</button>
        </div>
        <div style="font-size:0.75rem; color:var(--text-dim); margin-top:4px;">${escapeHtml(u.organizationId || 'General')} • ${escapeHtml(u.department)}</div>
      </td>
      <td><span class="badge badge-indigo">${escapeHtml(u.clearance)}</span></td>
      <td>
        <div style="display:flex; flex-wrap:wrap; gap:4px;">
          ${(u.attributes || []).map(a => `
            <span class="policy-chip match">
              ${escapeHtml(a)}
              <span style="cursor:pointer; margin-left:4px; color:var(--coral-danger);" onclick="revokeUserAttribute('${u.userId}', '${a}')" title="Revoke Attribute">&times;</span>
            </span>
          `).join('')}
        </div>
      </td>
      <td>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <button class="header-btn btn-sm btn-secondary" onclick="openIssueAttrModalFor('${u.userId}')">+ Attr</button>
          <button class="header-btn btn-sm btn-teal" onclick="showVerifiableCredentials('${u.userId}')">Inspect VC</button>
          <button class="header-btn btn-sm btn-primary" onclick="generateZkProofForUser('${u.userId}')">zk-Proof</button>
        </div>
      </td>
    </tr>
  `}).join('');
}

window.openAddRoleModalFor = function(userId) {
  const user = state.users.find(u => u.userId === userId) || state.users[0];
  const sel = document.getElementById('modal-role-user-select');
  if (sel) {
    sel.innerHTML = state.users.map(u => 
      `<option value="${u.userId}" ${u.userId === userId ? 'selected' : ''}>${escapeHtml(u.name)} (${escapeHtml(u.userId)})</option>`
    ).join('');
  }
  const nameEl = document.getElementById('modal-role-user-name');
  if (nameEl && user) nameEl.textContent = user.name;
  const roleInput = document.getElementById('modal-role-input');
  if (roleInput) roleInput.value = '';
  const deptInput = document.getElementById('modal-role-dept-input');
  if (deptInput) deptInput.value = user ? user.department : '';
  document.getElementById('modal-add-user-role')?.classList.add('active');
};

window.revokeUserAttribute = async function(userId, attribute) {
  try {
    await api.post('/users/revoke-attribute', { userId, attribute });
    showToast(`Revoked attribute '${attribute}' from ${userId}`, 'warning');
    await loadUsers();
    renderUsersTable();
  } catch (err) {
    showToast(`Failed to revoke attribute: ${err.message}`, 'error');
  }
};

window.openIssueAttrModalFor = function(userId) {
  const sel = document.getElementById('issue-attr-user-select');
  if (sel) sel.value = userId;
  document.getElementById('modal-issue-attr')?.classList.add('active');
};

// --- Audit Log View ---
async function loadAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  const eventFilter = document.getElementById('audit-event-filter')?.value || 'all';
  const orgFilter = document.getElementById('audit-org-filter')?.value || 'all';
  const search = document.getElementById('audit-search-input')?.value.trim() || '';

  // Populate org filter options if empty
  const orgSelect = document.getElementById('audit-org-filter');
  if (orgSelect && orgSelect.options.length <= 1 && state.organizations.length > 0) {
    orgSelect.innerHTML = '<option value="all">All Organizations</option>' + state.organizations.map(o => 
      `<option value="${o.orgId}">${escapeHtml(o.name)}</option>`
    ).join('');
  }

  try {
    const params = {};
    if (eventFilter !== 'all') params.event = eventFilter;
    if (orgFilter !== 'all') params.org = orgFilter;
    if (search) params.search = search;
    params.caller = state.activeUserId;

    state.auditLogs = await api.get('/audit', params);

    // Update root in banner
    const rootRes = await api.get('/audit/merkle-root');
    const rootEl = document.getElementById('onchain-merkle-root');
    if (rootEl) rootEl.textContent = rootRes.merkleRoot;

    if (state.auditLogs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:30px; color:var(--text-dim);">No audit logs matching query.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.auditLogs.map(log => {
      let badgeClass = 'badge-blue';
      if (log.event === 'AccessGranted') badgeClass = 'badge-emerald';
      if (log.event === 'AccessDenied') badgeClass = 'badge-coral';
      if (log.event === 'AccessRevoked') badgeClass = 'badge-amber';
      if (log.event === 'EmergencyBreakGlass') badgeClass = 'badge-coral';
      if (log.event === 'FileSessionDuration') badgeClass = 'badge-teal';

      let timeSpentCell = '<span style="color:var(--text-dim); font-size:0.75rem;">--</span>';
      if (log.event === 'FileSessionDuration') {
        timeSpentCell = `<span class="dwell-badge">⏱️ ${escapeHtml(log.formattedDwellTime || '3m 15s')} dwell</span>`;
      } else if (log.executionMs) {
        timeSpentCell = `<span class="badge badge-emerald font-mono">${log.executionMs}ms</span>`;
      } else if (log.event === 'FileUploaded') {
        timeSpentCell = `<span class="badge badge-blue font-mono">Upload: 12ms</span>`;
      } else if (log.event === 'AccessRevoked') {
        timeSpentCell = `<span class="badge badge-amber font-mono">Revoked: 0.1ms</span>`;
      }

      return `
        <tr>
          <td>
            <div class="time-cell">
              <span class="time-cell-primary">${escapeHtml(log.formattedTime || log.isoTimestamp || '--')}</span>
              <span class="time-cell-sub">${escapeHtml(log.relativeTime || '')}</span>
            </div>
          </td>
          <td>
            <span class="font-mono" style="font-weight:700; color:var(--royal-blue-light);">#${log.logIndex}</span>
            <div style="font-size:0.7rem; color:var(--text-dim);">Block #${log.blockIndex}</div>
          </td>
          <td><span class="badge ${badgeClass}">${escapeHtml(log.event)}</span></td>
          <td>
            <div>
              <span class="badge badge-indigo font-mono">${escapeHtml(log.fileId || '--')}</span>
              ${log.organizationId ? `<div style="font-size:0.7rem; color:var(--text-dim); margin-top:2px;">${escapeHtml(log.organizationId)}</div>` : ''}
            </div>
          </td>
          <td><strong>${escapeHtml(log.user || log.requester || log.owner || log.caller || '--')}</strong></td>
          <td>${timeSpentCell}</td>
          <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${escapeHtml(log.details || log.justification || log.reason || JSON.stringify(log.action || ''))}
          </td>
          <td>
            <span class="code-hash font-mono">${escapeHtml((log.txHash || log.eventHash || '0x' + (log.timestamp || '0')).substring(0, 14))}...</span>
          </td>
          <td>
            <button class="header-btn btn-sm btn-secondary" onclick="openMerkleProofModal(${log.logIndex})">Proof &rarr;</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load audit logs:', err);
  }
}

// --- Benchmarks View ---
async function loadBenchmarks() {
  try {
    state.benchmarks = await api.get('/benchmarks');
    renderBenchmarks(state.benchmarks);
  } catch (err) {
    console.error('Failed to load benchmarks:', err);
  }
}

function renderBenchmarks(b) {
  const container = document.getElementById('benchmarks-display-container');
  if (!container || !b) return;

  container.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:20px;">
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:16px;">
        <div style="background:var(--bg-surface); padding:16px; border-radius:var(--radius-md); border:1px solid var(--border-subtle);">
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:700;">POLICY EVALUATION LATENCY</div>
          <div style="font-size:1.6rem; font-weight:800; color:var(--emerald-success);">${b.accessGrantLatencyMs} ms</div>
          <div style="font-size:0.7rem; color:var(--text-dim);">Contract state-machine verification</div>
        </div>

        <div style="background:var(--bg-surface); padding:16px; border-radius:var(--radius-md); border:1px solid var(--border-subtle);">
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:700;">BCS REVOCATION LATENCY</div>
          <div style="font-size:1.6rem; font-weight:800; color:var(--royal-blue-light);">${b.bcsRevocationTimeMs} ms</div>
          <div style="font-size:0.7rem; color:var(--text-dim);">Smart contract credential revocation</div>
        </div>

        <div style="background:var(--bg-surface); padding:16px; border-radius:var(--radius-md); border:1px solid var(--border-subtle);">
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:700;">BASELINE RE-ENCRYPTION</div>
          <div style="font-size:1.6rem; font-weight:800; color:var(--coral-danger);">${b.baselineReencryptionTimeMs} ms</div>
          <div style="font-size:0.7rem; color:var(--text-dim);">Traditional heavy ciphertext rewriting</div>
        </div>

        <div style="background:var(--bg-surface); padding:16px; border-radius:var(--radius-md); border:1px solid var(--border-subtle);">
          <div style="font-size:0.75rem; color:var(--text-muted); font-weight:700;">EFFICIENCY GAIN</div>
          <div style="font-size:1.6rem; font-weight:800; color:var(--teal-bright);">${b.revocationEfficiencyGain}</div>
          <div style="font-size:0.7rem; color:var(--text-dim);">Instant off-chain revocation gain</div>
        </div>
      </div>
    </div>
  `;
}

// --- Upload Handling ---
function handleFileSelection(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    state.selectedFile = {
      file: file,
      base64: e.target.result,
      name: file.name,
      size: file.size,
      type: file.type
    };

    document.getElementById('file-dropzone').style.display = 'none';
    const card = document.getElementById('file-selected-card');
    if (card) {
      card.style.display = 'flex';
      document.getElementById('file-selected-name').textContent = file.name;
      document.getElementById('file-selected-size').textContent = formatBytes(file.size);
    }

    // Auto-fill filename and ID
    const nameInput = document.getElementById('upload-file-name');
    const idInput = document.getElementById('upload-file-id');
    if (nameInput && !nameInput.value) nameInput.value = file.name;
    if (idInput && !idInput.value) idInput.value = `file_${Date.now().toString().slice(-6)}`;
  };
  reader.readAsDataURL(file);
}

async function handleUploadFormSubmit(e) {
  e.preventDefault();

  const fileId = document.getElementById('upload-file-id')?.value.trim();
  const fileName = document.getElementById('upload-file-name')?.value.trim();
  const fileType = document.getElementById('upload-file-type')?.value;
  const description = document.getElementById('upload-description')?.value.trim();
  const owner = document.getElementById('upload-owner')?.value || state.activeUserId;
  const policyStr = document.getElementById('upload-policy-input')?.value.trim();
  const importanceLevel = document.getElementById('upload-importance')?.value;
  const orgId = document.getElementById('upload-organization-select')?.value || 'org_general';
  const authUsersRaw = document.getElementById('upload-authorized-users')?.value.trim() || '';
  const alsoEmergencyWhitelist = Boolean(document.getElementById('upload-also-emergency-whitelist')?.checked);

  let content = '';
  let isBinary = false;
  let mimeType = 'text/plain';

  if (state.uploadMode === 'file' && state.selectedFile) {
    content = state.selectedFile.base64;
    isBinary = true;
    mimeType = state.selectedFile.type || 'application/octet-stream';
  } else {
    content = document.getElementById('upload-plaintext')?.value;
    if (!content) {
      showToast('Please provide text or select a file to encrypt', 'warning');
      return;
    }
  }

  const policy = policyStr.split(',').map(s => s.trim()).filter(Boolean);
  const authorizedUsers = authUsersRaw
    ? authUsersRaw.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean)
    : [];
  const emergencyWhitelist = alsoEmergencyWhitelist ? authorizedUsers : [];

  try {
    const res = await api.post('/files/upload', {
      fileId,
      fileName,
      description,
      fileType,
      owner,
      policy,
      content,
      isBinary,
      mimeType,
      organizationId: orgId,
      importanceLevel: importanceLevel,
      authorizedUsers,
      emergencyWhitelist
    });

    const authInp = document.getElementById('upload-authorized-users');
    if (authInp) authInp.value = '';
    const extraMsg = authorizedUsers.length > 0 ? ` (${authorizedUsers.length} user(s) whitelisted)` : '';
    showToast(`Successfully encrypted and registered '${fileName}' on-chain!${extraMsg}`, 'success');
    await loadUsers();
    await loadFiles();
    loadDashboard();
    switchView('uploader');
  } catch (err) {
    showToast(`Upload failed: ${err.message}`, 'error');
  }
}

function fillSampleUpload() {
  const samples = [
    {
      id: `file_fin_${Date.now().toString().slice(-4)}`,
      name: 'q4_sovereign_liquidity_audit.pdf',
      desc: 'Annualized liquidity reserve assessment and risk hedging framework.',
      type: 'Financial & Treasury',
      policy: 'Role:Finance,Clearance:High',
      content: 'CONFIDENTIAL AUDIT: Sovereign multi-asset treasury liquidity surplus: $620M USD.',
      whitelist: 'dr_priya, nurse_arjun, er_triage_doc'
    },
    {
      id: `file_ai_${Date.now().toString().slice(-4)}`,
      name: 'neural_weights_quantized.bin',
      desc: 'Trained weights matrix for private inference model.',
      type: 'AI Model & Patent',
      policy: 'Role:Engineer,Clearance:High',
      content: 'WEIGHTS_MANIFEST: SHA256(7f8a9b2c3d4e5f) Model parameters initialized.',
      whitelist: 'dr_priya, dr_chen, nurse_arjun'
    }
  ];

  const s = samples[Math.floor(Math.random() * samples.length)];
  document.getElementById('upload-file-id').value = s.id;
  document.getElementById('upload-file-name').value = s.name;
  document.getElementById('upload-description').value = s.desc;
  document.getElementById('upload-file-type').value = s.type;
  document.getElementById('upload-policy-input').value = s.policy;
  document.getElementById('upload-plaintext').value = s.content;
  const authInp = document.getElementById('upload-authorized-users');
  if (authInp && !authInp.value) authInp.value = s.whitelist;
}

// --- Window Functions for Modals & Actions ---
window.appendPolicyToken = function(token) {
  const input = document.getElementById('upload-policy-input');
  if (!input) return;
  if (input.value && !input.value.endsWith(' ') && !token.startsWith(' ') && !token.startsWith(',')) {
    input.value += ', ' + token;
  } else {
    input.value += token;
  }
};

window.evaluateActivePolicy = async function() {
  const expr = document.getElementById('upload-policy-input')?.value.trim();
  const resultBadge = document.getElementById('policy-eval-result');
  if (!expr) {
    showToast('Enter a policy formula to test', 'warning');
    return;
  }

  const activeUser = state.users.find(u => u.userId === state.activeUserId);
  const attrs = activeUser ? activeUser.attributes : [];

  try {
    const res = await api.post('/policy/evaluate', {
      expression: expr.includes(' AND ') || expr.includes(' OR ') ? expr : expr.split(',').map(s=>s.trim()).join(' AND '),
      attributes: attrs
    });

    if (res.satisfied) {
      resultBadge.className = 'badge badge-emerald';
      resultBadge.textContent = `Satisfied by ${state.activeUserId} ✓`;
      showToast(`Policy satisfied by ${state.activeUserId}`, 'success');
    } else {
      resultBadge.className = 'badge badge-coral';
      resultBadge.textContent = `Denied for ${state.activeUserId} ✕`;
      showToast(`Active user does not satisfy this policy`, 'warning');
    }
  } catch (err) {
    resultBadge.className = 'badge badge-coral';
    resultBadge.textContent = 'Syntax Error';
    showToast(`Policy evaluation error: ${err.message}`, 'error');
  }
};

window.openMerkleProofModal = async function(logIndex) {
  try {
    const proof = await api.get('/audit/proof', { index: logIndex });
    state.targetProofData = proof;

    document.getElementById('proof-leaf-hash').textContent = proof.leafHashHex;
    document.getElementById('proof-root-hash').textContent = proof.rootHex;
    document.getElementById('proof-path-display').textContent = JSON.stringify(proof.proofPath, null, 2);
    document.getElementById('proof-verification-badge').innerHTML = '<span class="badge badge-blue">Ready to Verify Against Cryptographic Root</span>';

    document.getElementById('modal-merkle-proof')?.classList.add('active');
  } catch (err) {
    showToast(`Failed to load Merkle proof: ${err.message}`, 'error');
  }
};

window.showVerifiableCredentials = async function(userId) {
  try {
    state.currentModalUserForVc = userId;
    const didDoc = await api.get(`/identity/did/${userId}`);
    const vcData = await api.get(`/identity/vc/${userId}`);

    document.getElementById('modal-did-uri').textContent = didDoc.id;
    document.getElementById('modal-vc-json').textContent = JSON.stringify(vcData.credentials[0] || didDoc, null, 2);

    document.getElementById('modal-view-vc')?.classList.add('active');
  } catch (err) {
    showToast(`Failed to load credentials: ${err.message}`, 'error');
  }
};

window.generateZkProofForUser = async function(userId) {
  const user = state.users.find(u => u.userId === userId);
  const attr = (user && user.attributes && user.attributes[0]) || 'Role:Staff';

  try {
    const zk = await api.post('/zk/generate-proof', { userId, attribute: attr });
    showToast(`zk-SNARK proof generated for ${userId} (${attr})! Commitment: ${zk.commitment.substring(0, 16)}...`, 'success');
  } catch (err) {
    showToast(`zk-Proof error: ${err.message}`, 'error');
  }
};

window.openS3PresignModal = async function(fileId) {
  try {
    const res = await api.post('/storage/s3-presign', { fileId, action: 'PUT' });
    document.getElementById('modal-s3-url').textContent = res.url;
    document.getElementById('modal-s3-presign')?.classList.add('active');
  } catch (err) {
    showToast(`S3 Presign failed: ${err.message}`, 'error');
  }
};

// --- DOM Initialization & Event Handlers ---
document.addEventListener('DOMContentLoaded', async () => {
  // Apply saved theme
  applyTheme(state.activeTheme);

  // Theme switch buttons
  document.querySelectorAll('.theme-opt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.getAttribute('data-theme');
      if (t) applyTheme(t);
    });
  });

  // Navigation items
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => {
    el.addEventListener('click', () => {
      const v = el.getAttribute('data-view');
      if (v) switchView(v);
    });
  });

  // Mobile menu toggle
  document.getElementById('mobile-toggle-btn')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('mobile-open');
  });

  // Quick header upload button
  document.getElementById('btn-quick-upload')?.addEventListener('click', () => switchView('uploader'));
  document.getElementById('btn-open-upload-modal')?.addEventListener('click', () => switchView('uploader'));

  // Active user identity switcher
  document.getElementById('active-user-select')?.addEventListener('change', (e) => {
    state.activeUserId = e.target.value;
    window.resetDecryptedSession();
    updateActiveUserDisplay();
    if (state.currentView === 'requester') renderRequesterFilesTable();
    if (state.currentView === 'uploader') renderUploaderFilesTable();
    showToast(`Switched active identity to: ${state.activeUserId}`, 'info');
  });

  // Decrypted Session Finish & Close Buttons
  document.getElementById('btn-finish-file-session')?.addEventListener('click', window.finishFileSession);
  document.getElementById('btn-org-finish-session')?.addEventListener('click', window.finishFileSession);
  document.getElementById('btn-close-requester-decrypted-box')?.addEventListener('click', () => {
    window.finishFileSession();
  });
  document.getElementById('btn-close-org-decrypted-box')?.addEventListener('click', () => {
    window.finishFileSession();
  });

  // Header & Sidebar Sign-Out / Switch Identity buttons
  document.getElementById('btn-header-switch-user')?.addEventListener('click', () => {
    window.logoutUser();
  });

  document.getElementById('btn-sidebar-signout')?.addEventListener('click', () => {
    window.logoutUser();
  });

  document.getElementById('btn-quick-new-user')?.addEventListener('click', () => {
    window.logoutUser();
    document.getElementById('tab-frontdoor-register')?.click();
  });

  document.getElementById('btn-requester-register-modal')?.addEventListener('click', () => {
    window.logoutUser();
    document.getElementById('tab-frontdoor-register')?.click();
  });

  // Upload Mode Tabs
  document.getElementById('tab-mode-file')?.addEventListener('click', () => {
    state.uploadMode = 'file';
    document.getElementById('tab-mode-file').classList.add('active');
    document.getElementById('tab-mode-text').classList.remove('active');
    document.getElementById('file-dropzone-container').style.display = 'block';
    document.getElementById('plaintext-container').style.display = 'none';
  });

  document.getElementById('tab-mode-text')?.addEventListener('click', () => {
    state.uploadMode = 'text';
    document.getElementById('tab-mode-text').classList.add('active');
    document.getElementById('tab-mode-file').classList.remove('active');
    document.getElementById('plaintext-container').style.display = 'block';
    document.getElementById('file-dropzone-container').style.display = 'none';
  });

  // File Dropzone & File Input
  const dropzone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('upload-file-input');

  dropzone?.addEventListener('click', () => fileInput?.click());
  document.getElementById('btn-change-file')?.addEventListener('click', () => fileInput?.click());

  fileInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelection(e.target.files[0]);
    }
  });

  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });

  dropzone?.addEventListener('dragleave', () => {
    dropzone.classList.remove('drag-over');
  });

  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelection(e.dataTransfer.files[0]);
    }
  });

  // Download Decrypted File
  document.getElementById('btn-download-decrypted-file')?.addEventListener('click', downloadLastDecryptedFile);

  // Copy Plaintext
  document.getElementById('btn-copy-plaintext')?.addEventListener('click', () => {
    const text = document.getElementById('decrypted-plaintext-content')?.textContent;
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        showToast('Decrypted text copied to clipboard!', 'info');
      }).catch(() => {
        showToast('Clipboard error', 'warning');
      });
    }
  });

  // Upload Form
  document.getElementById('upload-form')?.addEventListener('submit', handleUploadFormSubmit);
  document.getElementById('btn-upload-fill-sample')?.addEventListener('click', fillSampleUpload);

  // Policy preset buttons
  document.querySelectorAll('.policy-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('upload-policy-input').value = btn.getAttribute('data-policy');
    });
  });

  // Filters & Search
  document.getElementById('file-search-input')?.addEventListener('input', renderFilesTable);
  document.getElementById('file-status-filter')?.addEventListener('change', renderFilesTable);
  document.getElementById('requester-search-input')?.addEventListener('input', renderRequesterFilesTable);
  document.getElementById('requester-org-filter')?.addEventListener('change', renderRequesterFilesTable);
  document.getElementById('requester-importance-filter')?.addEventListener('change', renderRequesterFilesTable);

  // Estimator Sliders Real-Time Reactive Listeners
  document.getElementById('slider-file-size')?.addEventListener('input', computeLiveEstimates);
  document.getElementById('slider-attribute-count')?.addEventListener('input', computeLiveEstimates);
  document.getElementById('estimator-logic-type')?.addEventListener('change', computeLiveEstimates);
  document.getElementById('estimator-storage-backend')?.addEventListener('change', computeLiveEstimates);
  document.getElementById('btn-recalculate-estimator')?.addEventListener('click', computeLiveEstimates);

  // Emergency Break-Glass Form
  document.getElementById('emergency-break-glass-form')?.addEventListener('submit', handleEmergencyBreakGlassSubmit);

  // Emergency Lockdown Controls
  document.getElementById('btn-trigger-lockdown')?.addEventListener('click', async () => {
    const targetVal = document.getElementById('lockdown-target-select')?.value;
    if (!targetVal) return;
    const [targetType, targetId] = targetVal.split(':');

    try {
      await api.post('/emergency/lockdown', {
        targetType,
        targetId,
        caller: state.activeUserId,
        reason: 'Quarantine lockdown executed from Emergency Console'
      });
      showToast(`Quarantine lockdown activated for ${targetType}: ${targetId}!`, 'error');
      await loadFiles();
      await loadOrganizations();
      await refreshEmergencyConsole();
    } catch (err) {
      showToast(`Lockdown error: ${err.message}`, 'error');
    }
  });

  document.getElementById('btn-restore-lockdown')?.addEventListener('click', async () => {
    const targetVal = document.getElementById('lockdown-target-select')?.value;
    if (!targetVal) return;
    const [targetType, targetId] = targetVal.split(':');

    try {
      await api.post('/emergency/restore', { targetType, targetId, caller: state.activeUserId });
      showToast(`Lockdown restored for ${targetType}: ${targetId}`, 'success');
      await loadFiles();
      await loadOrganizations();
      await refreshEmergencyConsole();
    } catch (err) {
      showToast(`Restore error: ${err.message}`, 'error');
    }
  });

  // Organization Workspace Verification Submit
  document.getElementById('btn-submit-verify-worker')?.addEventListener('click', async () => {
    if (!pendingOrgToUnlock) return;
    const pwd = document.getElementById('verify-worker-password-input')?.value.trim();

    try {
      const res = await api.post('/organizations/verify-worker', {
        orgId: pendingOrgToUnlock.orgId,
        userId: state.activeUserId,
        password: pwd
      });

      if (res.verified) {
        state.authenticatedOrgs.add(pendingOrgToUnlock.orgId);
        document.getElementById('modal-verify-worker')?.classList.remove('active');
        showToast(`Workspace unlocked for ${pendingOrgToUnlock.name}!`, 'success');
        openOrgWorkspacePartition(pendingOrgToUnlock);
      } else {
        showToast(res.error || 'Invalid worker password for organization', 'error');
      }
    } catch (err) {
      showToast(`Verification failed: ${err.message}`, 'error');
    }
  });

  // Create Organization Modal & Form
  document.getElementById('btn-open-create-org-modal')?.addEventListener('click', () => {
    document.getElementById('modal-create-org')?.classList.add('active');
  });

  document.getElementById('btn-save-new-org')?.addEventListener('click', async () => {
    const oid = document.getElementById('create-org-id')?.value.trim();
    const name = document.getElementById('create-org-name')?.value.trim();
    const sector = document.getElementById('create-org-sector')?.value;
    const clearance = document.getElementById('create-org-clearance')?.value;
    const desc = document.getElementById('create-org-desc')?.value.trim();
    const roles = document.getElementById('create-org-roles')?.value.split(',').map(s=>s.trim()).filter(Boolean);
    const membersRaw = document.getElementById('create-org-members')?.value.trim();
    const pwd = document.getElementById('create-org-pwd')?.value.trim();

    if (!oid || !name) {
      showToast('Organization ID and Name are required', 'warning');
      return;
    }

    let members = membersRaw ? membersRaw.split(',').map(s=>s.trim()).filter(Boolean) : [];
    if (!members.includes(state.activeUserId)) {
      members.unshift(state.activeUserId);
    }

    try {
      await api.post('/organizations', {
        orgId: oid,
        name,
        sector,
        description: desc,
        allowedRoles: roles,
        authorizedMembers: members,
        creator: state.activeUserId,
        workerPassword: pwd,
        requirePassword: Boolean(pwd),
        minClearance: clearance
      });
      showToast(`Created organization: ${name} with ${members.length} whitelisted members`, 'success');
      document.getElementById('modal-create-org')?.classList.remove('active');
      await loadOrganizations();
      state.activeOrgPageId = oid;
      renderOrgPortal();
    } catch (err) {
      showToast(`Failed to create organization: ${err.message}`, 'error');
    }
  });

  // Modal Generic Close Buttons
  document.querySelectorAll('[data-modal]').forEach(btn => {
    btn.addEventListener('click', () => {
      const mid = btn.getAttribute('data-modal');
      document.getElementById(mid)?.classList.remove('active');
    });
  });

  // Register User
  document.getElementById('btn-open-user-modal')?.addEventListener('click', () => {
    document.getElementById('modal-add-user')?.classList.add('active');
  });

  document.getElementById('btn-save-new-user')?.addEventListener('click', async () => {
    const uid = document.getElementById('new-user-id')?.value.trim();
    const name = document.getElementById('new-user-name')?.value.trim();
    const role = document.getElementById('new-user-role')?.value.trim();
    const dept = document.getElementById('new-user-dept')?.value.trim();
    const clearance = document.getElementById('new-user-clearance')?.value;
    const orgId = document.getElementById('new-user-org')?.value;
    const pwd = document.getElementById('new-user-pwd')?.value.trim();

    if (!uid || !name) {
      showToast('Unique User ID and Full Name are required', 'warning');
      return;
    }

    try {
      await api.post('/users', {
        userId: uid,
        name,
        role: role || 'Staff',
        department: dept || 'General',
        clearance: clearance || 'Level-3 Confidential',
        organizationId: orgId,
        workerPassword: pwd
      });
      showToast(`Registered unique identity: ${name} (${uid})`, 'success');
      document.getElementById('modal-add-user')?.classList.remove('active');
      state.activeUserId = uid;
      await loadUsers();
      renderUsersTable();
      updateActiveUserDisplay();
    } catch (err) {
      showToast(`Failed to create user: ${err.message}`, 'error');
    }
  });

  // Issue Attribute
  document.getElementById('btn-open-issue-attr-modal')?.addEventListener('click', () => {
    document.getElementById('modal-issue-attr')?.classList.add('active');
  });

  document.getElementById('btn-save-issue-attr')?.addEventListener('click', async () => {
    const userId = document.getElementById('issue-attr-user-select')?.value;
    const attr = document.getElementById('issue-attr-name')?.value.trim();

    if (!userId || !attr) {
      showToast('Select user and enter attribute name', 'warning');
      return;
    }

    try {
      await api.post('/users/issue-attribute', { userId, attribute: attr });
      showToast(`Issued '${attr}' to ${userId}`, 'success');
      document.getElementById('modal-issue-attr')?.classList.remove('active');
      document.getElementById('issue-attr-name').value = '';
      await loadUsers();
      renderUsersTable();
      updateActiveUserDisplay();
    } catch (err) {
      showToast(`Failed to issue attribute: ${err.message}`, 'error');
    }
  });

  // ZK-Proof from Modal (Fixed button!)
  document.getElementById('btn-generate-zk-from-modal')?.addEventListener('click', async () => {
    const uid = state.currentModalUserForVc || state.activeUserId;
    await generateZkProofForUser(uid);
  });

  // Merkle Proof Verify Button
  document.getElementById('btn-run-proof-verify')?.addEventListener('click', async () => {
    if (!state.targetProofData) return;
    try {
      const res = await api.post('/audit/verify-proof', {
        leafHashHex: state.targetProofData.leafHashHex,
        proofPath: state.targetProofData.proofPath,
        expectedRootHex: state.targetProofData.rootHex
      });

      const badgeEl = document.getElementById('proof-verification-badge');
      if (res.verified) {
        badgeEl.innerHTML = '<span class="badge badge-emerald" style="padding:8px 16px;">✓ MATHEMATICALLY VERIFIED IN ON-CHAIN MERKLE ROOT</span>';
        showToast('Proof verified with 100% cryptographic integrity!', 'success');
      } else {
        badgeEl.innerHTML = '<span class="badge badge-coral" style="padding:8px 16px;">✕ PROOF VERIFICATION FAILED</span>';
        showToast('Proof verification failed', 'error');
      }
    } catch (err) {
      showToast(`Verification error: ${err.message}`, 'error');
    }
  });

  // S3 Presigned URL Copy
  document.getElementById('btn-copy-s3-url')?.addEventListener('click', () => {
    const text = document.getElementById('modal-s3-url')?.textContent;
    if (text) {
      navigator.clipboard.writeText(text);
      showToast('AWS S3 Presigned URL copied to clipboard!', 'success');
    }
  });

  // Audit Filter and Export
  document.getElementById('audit-event-filter')?.addEventListener('change', loadAuditLogs);
  document.getElementById('audit-search-input')?.addEventListener('input', () => {
    clearTimeout(window._auditSearchDebounce);
    window._auditSearchDebounce = setTimeout(loadAuditLogs, 300);
  });

  document.getElementById('btn-export-audit-json')?.addEventListener('click', () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.auditLogs, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `omnivault_audit_ledger_${Date.now()}.json`);
    dlAnchor.click();
    showToast('Audit ledger exported to JSON', 'success');
  });

  // Live Benchmark Button
  document.getElementById('btn-run-live-benchmark')?.addEventListener('click', async () => {
    try {
      showToast('Running benchmark suite on EVM state-machine...', 'info');
      const b = await api.post('/benchmarks/run');
      renderBenchmarks(b);
      showToast('Benchmarks completed successfully!', 'success');
    } catch (err) {
      showToast(`Benchmark error: ${err.message}`, 'error');
    }
  });

  // Dashboard refresh
  document.getElementById('btn-refresh-dashboard')?.addEventListener('click', () => {
    loadDashboard();
    loadFiles();
    showToast('Dashboard data refreshed', 'info');
  });

  // Dedicated Organization Gatekeeper Login (Fix redirect bug & session preference!)
  const handleOrgGateLogin = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId) || state.organizations[0];
    if (!activeOrg) return;

    const workerId = document.getElementById('gate-worker-user-select')?.value;
    const pwd = document.getElementById('gate-worker-password-input')?.value.trim();
    const remember = document.getElementById('gate-remember-session')?.checked;

    if (!workerId) {
      showToast('Please select a worker identity', 'warning');
      return;
    }

    try {
      const res = await api.post('/organizations/verify-worker', {
        orgId: activeOrg.orgId,
        userId: workerId,
        password: pwd
      });

      if (res.verified) {
        if (remember) {
          state.authenticatedOrgs.add(activeOrg.orgId);
        } else {
          state.authenticatedOrgs.delete(activeOrg.orgId);
          state.tempAuthenticatedOrg = activeOrg.orgId;
        }
        state.activeUserId = workerId;
        showToast(`Verified worker access for ${activeOrg.name}!`, 'success');
        await loadUsers();
        updateActiveUserDisplay();
        renderOrgPortal();
      } else {
        showToast(res.error || 'Invalid worker password for this organization', 'error');
      }
    } catch (err) {
      showToast(`Authentication failed: ${err.message}`, 'error');
    }
  };

  document.getElementById('form-org-gate-login')?.addEventListener('submit', handleOrgGateLogin);
  document.getElementById('btn-submit-org-gate-login')?.addEventListener('click', handleOrgGateLogin);

  // Dedicated Lock & Sign Out Button
  document.getElementById('btn-org-portal-lock')?.addEventListener('click', () => {
    const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId) || state.organizations[0];
    if (activeOrg) {
      state.authenticatedOrgs.delete(activeOrg.orgId);
      state.tempAuthenticatedOrg = null;
      showToast(`Locked workspace for ${activeOrg.name}. Re-authentication required to re-enter.`, 'info');
      renderOrgPortal();
    }
  });

  // Add Worker to Organization Modal Controls
  document.getElementById('btn-org-add-worker')?.addEventListener('click', () => {
    const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId) || state.organizations[0];
    if (!activeOrg) return;
    const nameEl = document.getElementById('modal-org-add-member-org-name');
    if (nameEl) nameEl.textContent = activeOrg.name;

    const userSelect = document.getElementById('modal-org-add-member-user-select');
    if (userSelect) {
      const currentMembers = new Set(activeOrg.authorizedMembers || []);
      const candidates = state.users.filter(u => !currentMembers.has(u.userId));
      if (candidates.length === 0) {
        userSelect.innerHTML = `<option value="">(All registered users are already whitelisted)</option>`;
      } else {
        userSelect.innerHTML = `<option value="">-- Choose registered user or enter username below --</option>` +
          candidates.map(u => `<option value="${u.userId}">${escapeHtml(u.name)} (${escapeHtml(u.role)}) [${escapeHtml(u.userId)}]</option>`).join('');
      }
    }
    const customInput = document.getElementById('modal-org-add-member-custom-id');
    if (customInput) customInput.value = '';
    const roleInput = document.getElementById('modal-org-add-member-role');
    if (roleInput) roleInput.value = (activeOrg.allowedRoles && activeOrg.allowedRoles[0]) || 'Staff';

    document.getElementById('modal-org-add-member')?.classList.add('active');
  });

  document.getElementById('btn-save-org-add-member')?.addEventListener('click', async () => {
    const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId) || state.organizations[0];
    if (!activeOrg) return;
    const selUid = document.getElementById('modal-org-add-member-user-select')?.value;
    const customUid = document.getElementById('modal-org-add-member-custom-id')?.value.trim();
    const uid = customUid || selUid;
    const role = document.getElementById('modal-org-add-member-role')?.value.trim();
    const clearance = document.getElementById('modal-org-add-member-clearance')?.value;

    if (!uid) {
      showToast('Please select a user or enter a custom username to whitelist', 'warning');
      return;
    }

    try {
      const res = await api.post(`/organizations/${activeOrg.orgId}/members`, {
        userId: uid,
        role: role || undefined,
        clearance: clearance || undefined,
        caller: state.activeUserId
      });
      if (res.success) {
        const addedInfo = res.addedCount && res.addedCount > 1
          ? `${res.addedCount} workers (${res.userId})`
          : `'${res.userId || uid}'`;
        showToast(`Authorized and whitelisted ${addedInfo} for ${activeOrg.name}!`, 'success');
        document.getElementById('modal-org-add-member')?.classList.remove('active');
        await loadUsers();
        await loadOrganizations();
        await renderOrgPortal();
      }
    } catch(err) {
      showToast(`Failed to add member: ${err.message}`, 'error');
    }
  });

  // Multi-Role: Switch Active Role Listener
  document.getElementById('active-user-role-select')?.addEventListener('change', async (e) => {
    const newRole = e.target.value;
    try {
      await api.post(`/users/${state.activeUserId}/switch-role`, { role: newRole });
      window.resetDecryptedSession();
      showToast(`Switched active role to "${newRole}"`, 'success');
      await loadUsers();
      updateActiveUserDisplay();
      if (state.currentView === 'requester') renderRequesterFilesTable();
      if (state.currentView === 'users') renderUsersTable();
    } catch (err) {
      showToast(`Failed to switch role: ${err.message}`, 'error');
    }
  });

  document.getElementById('btn-open-add-role-modal')?.addEventListener('click', () => {
    window.openAddRoleModalFor(state.activeUserId);
  });

  // Multi-Role: Save New Role to Profile
  document.getElementById('btn-save-user-role')?.addEventListener('click', async () => {
    const uid = document.getElementById('modal-role-user-select')?.value;
    const role = document.getElementById('modal-role-input')?.value.trim();
    const dept = document.getElementById('modal-role-dept-input')?.value.trim();

    if (!uid || !role) {
      showToast('User identity and role name are required', 'warning');
      return;
    }

    try {
      await api.post(`/users/${uid}/roles`, { role, department: dept });
      showToast(`Role "${role}" added to user ${uid}!`, 'success');
      document.getElementById('modal-add-user-role')?.classList.remove('active');
      await loadUsers();
      updateActiveUserDisplay();
      renderUsersTable();
    } catch (err) {
      showToast(`Failed to add role: ${err.message}`, 'error');
    }
  });

  // Custom Data Classification Modal Controls
  document.getElementById('btn-open-custom-classification-modal')?.addEventListener('click', () => {
    document.getElementById('modal-custom-classification')?.classList.add('active');
  });

  document.querySelectorAll('#custom-class-color-picker .color-swatch').forEach(swatch => {
    swatch.addEventListener('click', () => {
      document.querySelectorAll('#custom-class-color-picker .color-swatch').forEach(s => s.classList.remove('selected'));
      swatch.classList.add('selected');
      const color = swatch.dataset.color;
      const hiddenInput = document.getElementById('custom-class-color');
      if (hiddenInput) hiddenInput.value = color;
      updateClassificationPreview();
    });
  });

  document.getElementById('custom-class-score')?.addEventListener('input', (e) => {
    const valEl = document.getElementById('custom-class-score-val');
    if (valEl) valEl.textContent = `${e.target.value}%`;
    updateClassificationPreview();
  });

  document.getElementById('custom-class-label')?.addEventListener('input', updateClassificationPreview);

  function updateClassificationPreview() {
    const label = document.getElementById('custom-class-label')?.value.trim() || 'Custom Classification';
    const score = document.getElementById('custom-class-score')?.value || '85';
    const color = document.getElementById('custom-class-color')?.value || '#ec4899';
    const preview = document.getElementById('custom-class-preview-badge');
    if (preview) {
      preview.innerHTML = `
        <span class="custom-classification-badge" style="background-color:${color}22; border-color:${color}; color:${color};">
          🏷️ ${escapeHtml(label)} (${score}%)
        </span>
      `;
    }
  }

  // Save Custom Classification
  document.getElementById('btn-save-custom-classification')?.addEventListener('click', async () => {
    const label = document.getElementById('custom-class-label')?.value.trim();
    const score = parseInt(document.getElementById('custom-class-score')?.value || '75', 10);
    const color = document.getElementById('custom-class-color')?.value || '#3b82f6';
    const desc = document.getElementById('custom-class-desc')?.value.trim();

    if (!label) {
      showToast('Classification label is required', 'warning');
      return;
    }

    try {
      await api.post('/classifications', {
        label,
        sensitivityScore: score,
        color,
        description: desc
      });
      showToast(`Custom classification "${label}" registered on-chain!`, 'success');
      document.getElementById('modal-custom-classification')?.classList.remove('active');
      document.getElementById('custom-class-label').value = '';
      document.getElementById('custom-class-desc').value = '';
      await loadClassifications();
      const select = document.getElementById('upload-importance');
      if (select) select.value = label;
      renderFilesTable();
    } catch (err) {
      showToast(`Failed to create classification: ${err.message}`, 'error');
    }
  });

  // ==========================================================================
  // FRONT-DOOR ZERO-TRUST AUTHENTICATION & SESSION MANAGEMENT
  // ==========================================================================
  const frontdoorOverlay = document.getElementById('frontdoor-auth-overlay');
  const appContainer = document.getElementById('app-container');

  window.showFrontdoorOverlay = function() {
    if (frontdoorOverlay) {
      frontdoorOverlay.classList.remove('hidden');
      frontdoorOverlay.style.display = 'flex';
    }
    if (appContainer) {
      appContainer.classList.remove('authenticated');
      appContainer.style.display = 'none';
    }
  };

  window.hideFrontdoorOverlay = function() {
    if (frontdoorOverlay) {
      frontdoorOverlay.classList.add('hidden');
      frontdoorOverlay.style.display = 'none';
    }
    if (appContainer) {
      appContainer.classList.add('authenticated');
      appContainer.style.display = 'flex';
    }
  };

  // --- Frontdoor Error Handling Helpers ---
  function clearFrontdoorErrors() {
    const errLogin = document.getElementById('frontdoor-login-error-banner');
    const errReg1 = document.getElementById('frontdoor-reg-error-step1');
    const errReg2 = document.getElementById('frontdoor-reg-error-step2');
    const errForgot = document.getElementById('frontdoor-forgot-error-banner');
    const okForgot = document.getElementById('frontdoor-forgot-success-banner');
    if (errLogin) errLogin.style.display = 'none';
    if (errReg1) errReg1.style.display = 'none';
    if (errReg2) errReg2.style.display = 'none';
    if (errForgot) errForgot.style.display = 'none';
    if (okForgot) okForgot.style.display = 'none';
    document.querySelectorAll('.input-error').forEach(el => el.classList.remove('input-error'));
  }

  function showLoginError(msg) {
    const banner = document.getElementById('frontdoor-login-error-banner');
    const txt = document.getElementById('frontdoor-login-error-text');
    if (banner && txt) {
      txt.textContent = msg;
      banner.style.display = 'flex';
      banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function showRegError(msg, step = 1) {
    const banner = document.getElementById(step === 1 ? 'frontdoor-reg-error-step1' : 'frontdoor-reg-error-step2');
    const txt = document.getElementById(step === 1 ? 'frontdoor-reg-error-text-step1' : 'frontdoor-reg-error-text-step2');
    if (banner && txt) {
      txt.textContent = msg;
      banner.style.display = 'flex';
      banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function showForgotError(msg) {
    const okBanner = document.getElementById('frontdoor-forgot-success-banner');
    if (okBanner) okBanner.style.display = 'none';
    const banner = document.getElementById('frontdoor-forgot-error-banner');
    const txt = document.getElementById('frontdoor-forgot-error-text');
    if (banner && txt) {
      txt.textContent = msg;
      banner.style.display = 'flex';
      banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function showForgotSuccess(msg) {
    const errBanner = document.getElementById('frontdoor-forgot-error-banner');
    if (errBanner) errBanner.style.display = 'none';
    const banner = document.getElementById('frontdoor-forgot-success-banner');
    const txt = document.getElementById('frontdoor-forgot-success-text');
    if (banner && txt) {
      txt.textContent = msg;
      banner.style.display = 'flex';
      banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function highlightInput(id) {
    const el = document.getElementById(id);
    if (el) {
      el.classList.add('input-error');
      el.focus();
    }
  }

  // Clear errors when user types in inputs
  [
    'frontdoor-login-user',
    'frontdoor-login-password',
    'frontdoor-reg-username',
    'frontdoor-reg-name',
    'frontdoor-reg-password',
    'frontdoor-reg-password-confirm',
    'frontdoor-reg-role',
    'frontdoor-forgot-username',
    'frontdoor-forgot-new-password',
    'frontdoor-forgot-confirm-password'
  ].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        el.classList.remove('input-error');
        const loginBanner = document.getElementById('frontdoor-login-error-banner');
        if (loginBanner && (id === 'frontdoor-login-user' || id === 'frontdoor-login-password')) {
          loginBanner.style.display = 'none';
        }
        const reg1 = document.getElementById('frontdoor-reg-error-step1');
        if (reg1 && (id.startsWith('frontdoor-reg-') && id !== 'frontdoor-reg-role')) {
          reg1.style.display = 'none';
        }
        const reg2 = document.getElementById('frontdoor-reg-error-step2');
        if (reg2) reg2.style.display = 'none';
        const forgotBanner = document.getElementById('frontdoor-forgot-error-banner');
        if (forgotBanner && id.startsWith('frontdoor-forgot-')) {
          forgotBanner.style.display = 'none';
        }
        if (id === 'frontdoor-forgot-username') {
          const verifiedCard = document.getElementById('forgot-user-verified-card');
          if (verifiedCard) verifiedCard.style.display = 'none';
        }
      });
    }
  });

  window.loginUser = async function(userId, password) {
    clearFrontdoorErrors();
    const uid = (userId || '').trim();
    const pwd = password || '';

    if (!uid || !pwd) {
      showLoginError('Please enter both your Username and Password.');
      if (!uid) highlightInput('frontdoor-login-user');
      if (!pwd) highlightInput('frontdoor-login-password');
      showToast('Please enter both username and password', 'warning');
      return;
    }

    try {
      const res = await api.post('/auth/login', { userId: uid, password: pwd });
      if (res.authenticated) {
        window.resetDecryptedSession(); // Close and reset any active decrypted session
        sessionStorage.setItem('bcs_auth_user', JSON.stringify(res.user));
        state.activeUserId = res.user.userId;
        clearFrontdoorErrors();
        showToast(`Authenticated as ${res.user.name}! Clearance: ${res.user.clearance}`, 'success');
        window.hideFrontdoorOverlay();
        await loadUsers();
        await loadFiles();
        updateActiveUserDisplay();
        if (state.currentView === 'requester') renderRequesterFilesTable();
        if (state.currentView === 'uploader') renderUploaderFilesTable();
        if (state.currentView === 'org-portal') renderOrgPortal();
        if (state.currentView === 'audit') loadAuditLogs();
        await loadDashboard();
        await refreshEmergencyConsole();
      } else {
        const errMsg = res.error || 'Authentication failed. Please verify username and password.';
        showLoginError(errMsg);
        highlightInput('frontdoor-login-password');
        showToast(errMsg, 'error');
      }
    } catch (err) {
      const errMsg = err.message || 'Authentication error';
      showLoginError(errMsg);
      if (errMsg.toLowerCase().includes('password')) {
        highlightInput('frontdoor-login-password');
      } else if (errMsg.toLowerCase().includes('username') || errMsg.toLowerCase().includes('account') || errMsg.toLowerCase().includes('not exist')) {
        highlightInput('frontdoor-login-user');
      } else {
        highlightInput('frontdoor-login-user');
        highlightInput('frontdoor-login-password');
      }
      showToast(errMsg, 'error');
    }
  };

  window.logoutUser = function() {
    window.resetDecryptedSession(); // Close and wipe decrypted inspection session!
    sessionStorage.removeItem('bcs_auth_user');
    clearFrontdoorErrors();
    showToast('Signed out of session. Front-door authentication required.', 'info');
    window.showFrontdoorOverlay();
    document.getElementById('tab-frontdoor-login')?.click();
  };

  window.registerUser = async function() {
    clearFrontdoorErrors();
    const username = document.getElementById('frontdoor-reg-username')?.value.trim();
    const name = document.getElementById('frontdoor-reg-name')?.value.trim();
    const password = document.getElementById('frontdoor-reg-password')?.value;
    const passwordConfirm = document.getElementById('frontdoor-reg-password-confirm')?.value;
    const orgId = document.getElementById('frontdoor-reg-org')?.value || 'org_general';
    const role = document.getElementById('frontdoor-reg-role')?.value.trim() || 'Worker';

    if (!username || !name || !password) {
      // Go back to Step 1 to show missing fields
      document.getElementById('btn-reg-step2-back')?.click();
      showRegError('Username, Full Name, and Password are all required.', 1);
      if (!username) highlightInput('frontdoor-reg-username');
      else if (!name) highlightInput('frontdoor-reg-name');
      else highlightInput('frontdoor-reg-password');
      showToast('Username, Full Name, and Password are required', 'warning');
      return;
    }
    if (password !== passwordConfirm) {
      document.getElementById('btn-reg-step2-back')?.click();
      showRegError('Passwords do not match. Please re-confirm password.', 1);
      highlightInput('frontdoor-reg-password-confirm');
      showToast('Passwords do not match', 'error');
      return;
    }

    try {
      const res = await api.post('/auth/register', {
        userId: username,
        password,
        name,
        organizationId: orgId,
        role
      });
      if (res.registered) {
        window.resetDecryptedSession(); // Clean reset for new user
        sessionStorage.setItem('bcs_auth_user', JSON.stringify(res.user));
        state.activeUserId = res.user.userId;
        clearFrontdoorErrors();
        showToast(`Account registered for ${res.user.organizationId}! Initial Clearance: ${res.user.clearance}`, 'success');
        window.hideFrontdoorOverlay();
        await loadOrganizations();
        await loadUsers();
        await loadFiles();
        updateActiveUserDisplay();
        if (state.currentView === 'requester') renderRequesterFilesTable();
        await loadDashboard();
        await refreshEmergencyConsole();
      } else {
        const errMsg = res.error || 'Registration failed. Please check your information.';
        showRegError(errMsg, 2);
        showToast(errMsg, 'error');
      }
    } catch (err) {
      const errMsg = err.message || 'Registration error';
      // If error is about username taken, switch back to Step 1
      if (errMsg.toLowerCase().includes('username') || errMsg.toLowerCase().includes('already taken')) {
        document.getElementById('btn-reg-step2-back')?.click();
        showRegError(errMsg, 1);
        highlightInput('frontdoor-reg-username');
      } else {
        showRegError(errMsg, 2);
      }
      showToast(errMsg, 'error');
    }
  };

  window.verifyForgotUser = async function() {
    clearFrontdoorErrors();
    const uid = document.getElementById('frontdoor-forgot-username')?.value.trim();
    const verifiedCard = document.getElementById('forgot-user-verified-card');
    if (verifiedCard) verifiedCard.style.display = 'none';

    if (!uid) {
      showForgotError('Please enter your registered Username / ID first.');
      highlightInput('frontdoor-forgot-username');
      showToast('Please enter your username to verify', 'warning');
      return;
    }

    try {
      const res = await api.post('/auth/verify-reset-user', { userId: uid });
      if (res.verified && res.user) {
        if (verifiedCard) {
          document.getElementById('forgot-verified-name').textContent = `${res.user.name} (${res.user.userId})`;
          document.getElementById('forgot-verified-org').textContent = `${res.user.role} • ${res.user.organizationName}`;
          document.getElementById('forgot-verified-did').textContent = `DID: ${res.user.did}`;
          verifiedCard.style.display = 'block';
        }
        showToast(`Account verified: ${res.user.name}. Please enter your new password.`, 'success');
        document.getElementById('frontdoor-forgot-new-password')?.focus();
      } else {
        const errMsg = res.error || `Account '${uid}' was not found.`;
        showForgotError(errMsg);
        highlightInput('frontdoor-forgot-username');
        showToast(errMsg, 'error');
      }
    } catch (err) {
      const errMsg = err.message || 'Account verification failed.';
      showForgotError(errMsg);
      highlightInput('frontdoor-forgot-username');
      showToast(errMsg, 'error');
    }
  };

  window.resetForgotPassword = async function() {
    clearFrontdoorErrors();
    const uid = document.getElementById('frontdoor-forgot-username')?.value.trim();
    const newPassword = document.getElementById('frontdoor-forgot-new-password')?.value || '';
    const confirmPassword = document.getElementById('frontdoor-forgot-confirm-password')?.value || '';

    if (!uid) {
      showForgotError('Please enter your registered Username / ID.');
      highlightInput('frontdoor-forgot-username');
      showToast('Username is required', 'warning');
      return;
    }
    if (!newPassword) {
      showForgotError('Please enter a new password.');
      highlightInput('frontdoor-forgot-new-password');
      showToast('New password is required', 'warning');
      return;
    }
    if (newPassword.length < 4) {
      showForgotError('New password must be at least 4 characters long.');
      highlightInput('frontdoor-forgot-new-password');
      showToast('Password must be at least 4 characters long', 'warning');
      return;
    }
    if (newPassword !== confirmPassword) {
      showForgotError('New password and confirmation password do not match.');
      highlightInput('frontdoor-forgot-confirm-password');
      showToast('Passwords do not match', 'error');
      return;
    }

    try {
      const res = await api.post('/auth/reset-password', {
        userId: uid,
        newPassword,
        confirmPassword
      });
      if (res.reset) {
        const msg = res.message || `Password for '${uid}' has been reset! You can now sign in with your new password.`;
        showForgotSuccess(msg);
        showToast(msg, 'success');
        // Pre-populate username in login form and clear password fields
        const loginUser = document.getElementById('frontdoor-login-user');
        const loginPass = document.getElementById('frontdoor-login-password');
        if (loginUser) loginUser.value = res.userId || uid;
        if (loginPass) loginPass.value = '';
        const newPassEl = document.getElementById('frontdoor-forgot-new-password');
        const confPassEl = document.getElementById('frontdoor-forgot-confirm-password');
        if (newPassEl) newPassEl.value = '';
        if (confPassEl) confPassEl.value = '';
      } else {
        const errMsg = res.error || 'Password reset failed.';
        showForgotError(errMsg);
        showToast(errMsg, 'error');
      }
    } catch (err) {
      const errMsg = err.message || 'Password reset failed.';
      showForgotError(errMsg);
      if (errMsg.toLowerCase().includes('account') || errMsg.toLowerCase().includes('username') || errMsg.toLowerCase().includes('not exist')) {
        highlightInput('frontdoor-forgot-username');
      } else if (errMsg.toLowerCase().includes('match')) {
        highlightInput('frontdoor-forgot-confirm-password');
      } else {
        highlightInput('frontdoor-forgot-new-password');
      }
      showToast(errMsg, 'error');
    }
  };

  function openForgotPasswordPane() {
    clearFrontdoorErrors();
    document.getElementById('tab-frontdoor-forgot')?.classList.add('active');
    document.getElementById('tab-frontdoor-login')?.classList.remove('active');
    document.getElementById('tab-frontdoor-register')?.classList.remove('active');
    const pLogin = document.getElementById('frontdoor-pane-login');
    const pReg = document.getElementById('frontdoor-pane-register');
    const pForgot = document.getElementById('frontdoor-pane-forgot');
    if (pLogin) pLogin.style.display = 'none';
    if (pReg) pReg.style.display = 'none';
    if (pForgot) pForgot.style.display = 'block';

    // Pre-fill username if already typed on the login pane
    const currentLoginUid = document.getElementById('frontdoor-login-user')?.value.trim();
    const forgotUidEl = document.getElementById('frontdoor-forgot-username');
    if (currentLoginUid && forgotUidEl && !forgotUidEl.value.trim()) {
      forgotUidEl.value = currentLoginUid;
    }
    forgotUidEl?.focus();
  }

  // Frontdoor Tabs
  document.getElementById('tab-frontdoor-login')?.addEventListener('click', () => {
    clearFrontdoorErrors();
    document.getElementById('tab-frontdoor-login')?.classList.add('active');
    document.getElementById('tab-frontdoor-register')?.classList.remove('active');
    document.getElementById('tab-frontdoor-forgot')?.classList.remove('active');
    const pLogin = document.getElementById('frontdoor-pane-login');
    const pReg = document.getElementById('frontdoor-pane-register');
    const pForgot = document.getElementById('frontdoor-pane-forgot');
    if (pLogin) pLogin.style.display = 'block';
    if (pReg) pReg.style.display = 'none';
    if (pForgot) pForgot.style.display = 'none';
  });

  document.getElementById('tab-frontdoor-register')?.addEventListener('click', () => {
    clearFrontdoorErrors();
    document.getElementById('tab-frontdoor-register')?.classList.add('active');
    document.getElementById('tab-frontdoor-login')?.classList.remove('active');
    document.getElementById('tab-frontdoor-forgot')?.classList.remove('active');
    const pLogin = document.getElementById('frontdoor-pane-login');
    const pReg = document.getElementById('frontdoor-pane-register');
    const pForgot = document.getElementById('frontdoor-pane-forgot');
    if (pReg) pReg.style.display = 'block';
    if (pLogin) pLogin.style.display = 'none';
    if (pForgot) pForgot.style.display = 'none';
    // Reset to step 1
    const s1 = document.getElementById('reg-step-1-container');
    const s2 = document.getElementById('reg-step-2-container');
    if (s1) s1.style.display = 'block';
    if (s2) s2.style.display = 'none';
    const b1 = document.getElementById('badge-step-1');
    const b2 = document.getElementById('badge-step-2');
    if (b1) b1.classList.add('active');
    if (b2) b2.classList.remove('active');
  });

  document.getElementById('tab-frontdoor-forgot')?.addEventListener('click', openForgotPasswordPane);
  document.getElementById('btn-open-forgot-password')?.addEventListener('click', openForgotPasswordPane);
  document.getElementById('btn-forgot-back-to-login')?.addEventListener('click', () => {
    document.getElementById('tab-frontdoor-login')?.click();
  });
  document.getElementById('btn-verify-forgot-user')?.addEventListener('click', () => {
    window.verifyForgotUser();
  });
  document.getElementById('btn-submit-forgot-password')?.addEventListener('click', () => {
    window.resetForgotPassword();
  });

  // Allow Enter key on Forgot Password fields
  document.getElementById('frontdoor-forgot-username')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      window.verifyForgotUser();
    }
  });
  ['frontdoor-forgot-new-password', 'frontdoor-forgot-confirm-password'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        window.resetForgotPassword();
      }
    });
  });

  // Step 1 -> Step 2 transition
  document.getElementById('btn-reg-step1-next')?.addEventListener('click', () => {
    clearFrontdoorErrors();
    const username = document.getElementById('frontdoor-reg-username')?.value.trim();
    const name = document.getElementById('frontdoor-reg-name')?.value.trim();
    const password = document.getElementById('frontdoor-reg-password')?.value;
    const passwordConfirm = document.getElementById('frontdoor-reg-password-confirm')?.value;

    if (!username) {
      showRegError('Please choose a unique Username / ID.', 1);
      highlightInput('frontdoor-reg-username');
      showToast('Username is required', 'warning');
      return;
    }
    if (!name) {
      showRegError('Please enter your Full Name.', 1);
      highlightInput('frontdoor-reg-name');
      showToast('Full Name is required', 'warning');
      return;
    }
    if (!password) {
      showRegError('Please set an account password.', 1);
      highlightInput('frontdoor-reg-password');
      showToast('Password is required', 'warning');
      return;
    }
    if (password.length < 4) {
      showRegError('Password must be at least 4 characters long.', 1);
      highlightInput('frontdoor-reg-password');
      showToast('Password must be at least 4 characters long', 'warning');
      return;
    }
    if (password !== passwordConfirm) {
      showRegError('Passwords do not match. Please re-enter confirm password.', 1);
      highlightInput('frontdoor-reg-password-confirm');
      showToast('Passwords do not match', 'error');
      return;
    }

    const s1 = document.getElementById('reg-step-1-container');
    const s2 = document.getElementById('reg-step-2-container');
    if (s1) s1.style.display = 'none';
    if (s2) s2.style.display = 'block';
    const b1 = document.getElementById('badge-step-1');
    const b2 = document.getElementById('badge-step-2');
    if (b1) b1.classList.remove('active');
    if (b2) b2.classList.add('active');

    // Ensure organizations dropdown is populated for Step 2
    populateOrgSelects();
    if (!state.organizations || state.organizations.length === 0) {
      loadOrganizations().catch(() => {});
    }
  });

  // Step 2 -> Step 1 back transition
  document.getElementById('btn-reg-step2-back')?.addEventListener('click', () => {
    clearFrontdoorErrors();
    const s1 = document.getElementById('reg-step-1-container');
    const s2 = document.getElementById('reg-step-2-container');
    if (s2) s2.style.display = 'none';
    if (s1) s1.style.display = 'block';
    const b1 = document.getElementById('badge-step-1');
    const b2 = document.getElementById('badge-step-2');
    if (b2) b2.classList.remove('active');
    if (b1) b1.classList.add('active');
  });

  // Demo Persona Pills
  document.querySelectorAll('.btn-demo-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      clearFrontdoorErrors();
      const uid = pill.dataset.uid;
      const pwd = pill.dataset.pwd;
      const userInput = document.getElementById('frontdoor-login-user');
      const passInput = document.getElementById('frontdoor-login-password');
      if (userInput) userInput.value = uid;
      if (passInput) passInput.value = pwd;
      window.loginUser(uid, pwd);
    });
  });

  document.getElementById('btn-submit-frontdoor-login')?.addEventListener('click', () => {
    const uid = document.getElementById('frontdoor-login-user')?.value.trim();
    const pwd = document.getElementById('frontdoor-login-password')?.value;
    window.loginUser(uid, pwd);
  });

  // Allow Enter key to trigger login
  ['frontdoor-login-user', 'frontdoor-login-password'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('btn-submit-frontdoor-login')?.click();
      }
    });
  });

  // Allow Enter key on Step 1 to trigger Next
  ['frontdoor-reg-username', 'frontdoor-reg-name', 'frontdoor-reg-password', 'frontdoor-reg-password-confirm'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('btn-reg-step1-next')?.click();
      }
    });
  });

  document.getElementById('btn-submit-frontdoor-register')?.addEventListener('click', () => {
    window.registerUser();
  });

  // ==========================================================================
  // CREATOR GOVERNANCE: EDIT WORKER ROLE & CLEARANCE
  // ==========================================================================
  window.openEditOrgMemberModal = function(orgId, userId, currentRole, currentClearance) {
    const orgInput = document.getElementById('modal-org-edit-org-id');
    const userInput = document.getElementById('modal-org-edit-user-id');
    const userDisplay = document.getElementById('modal-org-edit-user-display');
    const roleInput = document.getElementById('modal-org-edit-role');
    const selClearance = document.getElementById('modal-org-edit-clearance');

    if (orgInput) orgInput.value = orgId;
    if (userInput) userInput.value = userId;
    if (userDisplay) userDisplay.textContent = userId;
    if (roleInput) roleInput.value = currentRole || '';
    if (selClearance) {
      for (let opt of selClearance.options) {
        if (opt.value.includes(currentClearance) || currentClearance.includes(opt.value)) {
          selClearance.value = opt.value;
          break;
        }
      }
    }
    document.getElementById('modal-org-edit-member')?.classList.add('active');
  };

  document.getElementById('btn-save-org-edit-member')?.addEventListener('click', async () => {
    const orgId = document.getElementById('modal-org-edit-org-id')?.value;
    const userId = document.getElementById('modal-org-edit-user-id')?.value;
    const role = document.getElementById('modal-org-edit-role')?.value.trim();
    const clearance = document.getElementById('modal-org-edit-clearance')?.value;

    if (!role) {
      showToast('Assigned role cannot be empty', 'warning');
      return;
    }

    try {
      const res = await api.post(`/organizations/${orgId}/update-member`, {
        caller: state.activeUserId,
        userId,
        role,
        clearance
      });
      if (res.success) {
        showToast(`Updated role and clearance for ${userId}!`, 'success');
        document.getElementById('modal-org-edit-member')?.classList.remove('active');
        await loadUsers();
        await renderOrgPortal();
      }
    } catch (err) {
      showToast(`Failed to update member: ${err.message}`, 'error');
    }
  });

  // ==========================================================================
  // AUDIT LOG GOVERNANCE: MANAGE LOG VIEWERS
  // ==========================================================================
  window.openManageLogViewersModal = function() {
    const sel = document.getElementById('modal-log-viewers-file-select');
    if (sel) {
      sel.innerHTML = state.files.map(f => 
        `<option value="${f.fileId}">${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
      ).join('');
      if (state.files.length > 0) {
        loadAndRenderLogViewers(state.files[0].fileId);
      }
    }
    document.getElementById('modal-manage-log-viewers')?.classList.add('active');
  };

  async function loadAndRenderLogViewers(fileId) {
    const box = document.getElementById('modal-log-viewers-list');
    if (!box) return;
    try {
      const perms = await api.get('/audit/permissions', { fileId, caller: state.activeUserId });
      const viewers = perms.logViewers || [];
      if (viewers.length === 0) {
        box.innerHTML = `<span style="font-size:0.75rem; color:var(--text-dim);">(Only owner ${escapeHtml(perms.owner || '')} and org creator authorized)</span>`;
      } else {
        box.innerHTML = viewers.map(v => `
          <span class="whitelist-chip">
            👤 ${escapeHtml(v)}
            <span class="remove-btn" onclick="revokeLogViewer('${fileId}', '${v}')" title="Revoke view permission">&times;</span>
          </span>
        `).join('');
      }
    } catch (err) {
      box.innerHTML = `<span style="font-size:0.75rem; color:var(--coral-danger);">Failed to load permissions: ${escapeHtml(err.message)}</span>`;
    }
  }

  document.getElementById('modal-log-viewers-file-select')?.addEventListener('change', (e) => {
    loadAndRenderLogViewers(e.target.value);
  });

  document.getElementById('btn-open-manage-log-viewers')?.addEventListener('click', () => {
    window.openManageLogViewersModal();
  });

  document.getElementById('btn-grant-log-viewer')?.addEventListener('click', async () => {
    const fileId = document.getElementById('modal-log-viewers-file-select')?.value;
    const username = document.getElementById('modal-log-viewers-new-user')?.value.trim();
    if (!fileId || !username) {
      showToast('Please specify username or upload Excel to grant log view access', 'warning');
      return;
    }
    try {
      const res = await api.post('/audit/permissions/grant', {
        fileId,
        username,
        caller: state.activeUserId
      });
      if (res.success) {
        const countLabel = res.grantedCount && res.grantedCount > 1
          ? `${res.grantedCount} users (${res.grantedUsers.join(', ')})`
          : `'${(res.grantedUsers && res.grantedUsers[0]) || username}'`;
        showToast(`Granted log viewing access for ${countLabel}!`, 'success');
        document.getElementById('modal-log-viewers-new-user').value = '';
        await loadUsers();
        loadAndRenderLogViewers(fileId);
      }
    } catch (err) {
      showToast(`Grant error: ${err.message}`, 'error');
    }
  });

  window.revokeLogViewer = async function(fileId, username) {
    try {
      const res = await api.post('/audit/permissions/revoke', {
        fileId,
        username,
        caller: state.activeUserId
      });
      if (res.success) {
        showToast(`Revoked log access for '${username}'`, 'warning');
        loadAndRenderLogViewers(fileId);
      }
    } catch (err) {
      showToast(`Revoke error: ${err.message}`, 'error');
    }
  };

  // ==========================================================================
  // EMERGENCY GOVERNANCE: MANAGE RESPONDER WHITELIST (OWNER & CREATOR EXCLUSIVE)
  // ==========================================================================
  window.openManageEmergencyWhitelistModal = function() {
    const eligibleFiles = state.files.filter(f => {
      const isOwner = (f.owner === state.activeUserId);
      const fileOrg = state.organizations.find(o => o.orgId === f.organizationId);
      const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);
      return isOwner || isCreator;
    });

    const sel = document.getElementById('modal-emergency-whitelist-file-select');
    const warnEl = document.getElementById('modal-emergency-whitelist-perm-warning');
    const warnTxt = document.getElementById('modal-emergency-whitelist-perm-warning-text');
    const inputEl = document.getElementById('modal-emergency-whitelist-new-user');
    const addBtn = document.getElementById('btn-add-emergency-responder');

    if (eligibleFiles.length === 0) {
      if (sel) {
        sel.innerHTML = '<option value="">⛔ No files under your ownership or organization</option>';
        sel.disabled = true;
      }
      if (warnEl && warnTxt) {
        warnTxt.textContent = `Permission Denied: You are signed in as '${state.activeUserId}'. Only the file uploader or organization creator is permitted to whitelist emergency responders.`;
        warnEl.style.display = 'flex';
      }
      if (inputEl) inputEl.disabled = true;
      if (addBtn) addBtn.disabled = true;
      const box = document.getElementById('modal-emergency-whitelist-list');
      if (box) box.innerHTML = '<span style="font-size:0.75rem; color:var(--text-dim);">(Emergency whitelist management is restricted to file owners and organization creators)</span>';
    } else {
      if (sel) {
        sel.disabled = false;
        sel.innerHTML = eligibleFiles.map(f => 
          `<option value="${f.fileId}">${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
        ).join('');
      }
      if (warnEl) warnEl.style.display = 'none';
      if (inputEl) inputEl.disabled = false;
      if (addBtn) addBtn.disabled = false;
      loadAndRenderEmergencyResponders(eligibleFiles[0].fileId);
    }
    document.getElementById('modal-manage-emergency-whitelist')?.classList.add('active');
  };

  async function loadAndRenderEmergencyResponders(fileId) {
    const box = document.getElementById('modal-emergency-whitelist-list');
    const warnEl = document.getElementById('modal-emergency-whitelist-perm-warning');
    const warnTxt = document.getElementById('modal-emergency-whitelist-perm-warning-text');
    const inputEl = document.getElementById('modal-emergency-whitelist-new-user');
    const addBtn = document.getElementById('btn-add-emergency-responder');
    if (!box) return;

    try {
      const info = await api.get('/emergency/whitelist', { fileId });
      const responders = info.whitelistedResponders || [];
      const isOwner = (info.owner === state.activeUserId);
      const isCreator = (info.orgCreator === state.activeUserId);
      const canManage = isOwner || isCreator;

      if (!canManage) {
        if (warnEl && warnTxt) {
          warnTxt.textContent = `Permission Denied: Only file uploader (${info.owner}) or organization creator (${info.orgCreator || 'none'}) can manage emergency whitelisting for this asset.`;
          warnEl.style.display = 'flex';
        }
        if (inputEl) inputEl.disabled = true;
        if (addBtn) addBtn.disabled = true;
      } else {
        if (warnEl) warnEl.style.display = 'none';
        if (inputEl) inputEl.disabled = false;
        if (addBtn) addBtn.disabled = false;
      }

      if (responders.length === 0) {
        box.innerHTML = `<span style="font-size:0.75rem; color:var(--text-dim);">(Only owner ${escapeHtml(info.owner || '')} and org creator authorized)</span>`;
      } else {
        box.innerHTML = responders.map(r => `
          <span class="whitelist-chip" style="border-color:#ef4444;">
            🚨 ${escapeHtml(r)}
            ${canManage ? `<span class="remove-btn" onclick="removeEmergencyResponder('${fileId}', '${r}')" title="Remove emergency responder">&times;</span>` : ''}
          </span>
        `).join('');
      }
    } catch (err) {
      box.innerHTML = `<span style="font-size:0.75rem; color:var(--coral-danger);">Failed to load responders: ${escapeHtml(err.message)}</span>`;
    }
  }

  document.getElementById('modal-emergency-whitelist-file-select')?.addEventListener('change', (e) => {
    loadAndRenderEmergencyResponders(e.target.value);
  });

  document.getElementById('btn-open-manage-emergency-whitelist')?.addEventListener('click', () => {
    window.openManageEmergencyWhitelistModal();
  });

  document.getElementById('btn-add-emergency-responder')?.addEventListener('click', async () => {
    const fileId = document.getElementById('modal-emergency-whitelist-file-select')?.value;
    const username = document.getElementById('modal-emergency-whitelist-new-user')?.value.trim();
    if (!fileId || !username) {
      showToast('Please select a file and enter username(s) or upload Excel to whitelist for emergency break-glass', 'warning');
      return;
    }

    const f = state.files.find(item => item.fileId === fileId);
    const fileOrg = state.organizations.find(o => o.orgId === f?.organizationId);
    const isOwner = f && f.owner === state.activeUserId;
    const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);

    if (!isOwner && !isCreator) {
      showToast(`Permission Denied: Only file uploader (${f ? f.owner : 'owner'}) or organization creator can whitelist emergency responders.`, 'error');
      return;
    }

    try {
      const res = await api.post('/emergency/whitelist/add', {
        fileId,
        username,
        caller: state.activeUserId
      });
      if (res.success) {
        const countLabel = res.addedCount && res.addedCount > 1
          ? `${res.addedCount} emergency responders (${res.addedUsers.join(', ')})`
          : `'${(res.addedUsers && res.addedUsers[0]) || username}'`;
        showToast(`Whitelisted ${countLabel} for ${fileId}!`, 'success');
        const userInp = document.getElementById('modal-emergency-whitelist-new-user');
        if (userInp) userInp.value = '';
        await loadUsers();
        loadAndRenderEmergencyResponders(fileId);
        await loadFiles();
        if (state.currentView === 'requester') renderRequesterFilesTable();
      }
    } catch (err) {
      showToast(`Whitelist error: ${err.message}`, 'error');
    }
  });

  window.removeEmergencyResponder = async function(fileId, username) {
    const f = state.files.find(item => item.fileId === fileId);
    const fileOrg = state.organizations.find(o => o.orgId === f?.organizationId);
    const isOwner = f && f.owner === state.activeUserId;
    const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);

    if (!isOwner && !isCreator) {
      showToast(`Permission Denied: Only file uploader (${f ? f.owner : 'owner'}) or organization creator can remove emergency responders.`, 'error');
      return;
    }

    try {
      const res = await api.post('/emergency/whitelist/remove', {
        fileId,
        username,
        caller: state.activeUserId
      });
      if (res.success) {
        showToast(`Removed emergency responder '${username}'`, 'warning');
        loadAndRenderEmergencyResponders(fileId);
        await loadFiles();
        if (state.currentView === 'requester') renderRequesterFilesTable();
      }
    } catch (err) {
      showToast(`Remove error: ${err.message}`, 'error');
    }
  };

  window.openFileAccessModal = function(fileId) {
    const sel = document.getElementById('modal-file-access-file-select');
    if (sel) {
      sel.innerHTML = state.files.map(f => 
        `<option value="${f.fileId}" ${f.fileId === fileId ? 'selected' : ''}>${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
      ).join('');
      sel.value = fileId;
      loadAndRenderFileAuthorizedUsers(fileId);
    }
    document.getElementById('modal-manage-file-access')?.classList.add('active');
  };

  async function loadAndRenderFileAuthorizedUsers(fileId) {
    const listEl = document.getElementById('modal-file-access-list');
    if (!listEl) return;
    try {
      const data = await api.get(`/files/${fileId}/authorized-users`);
      const users = data.authorizedUsers || [];
      const owner = data.owner || '';
      if (users.length === 0) {
        listEl.innerHTML = '<span style="font-size:0.75rem; color:var(--text-dim);">No authorized users configured.</span>';
        return;
      }
      listEl.innerHTML = users.map(u => {
        const isFileOwner = (u === owner);
        return `
          <div style="display:flex; align-items:center; gap:6px; background:rgba(99, 102, 241, 0.15); border:1px solid rgba(99, 102, 241, 0.35); padding:4px 10px; border-radius:14px; font-size:0.78rem;">
            <span style="font-weight:700; color:var(--text-main); font-family:monospace;">${escapeHtml(u)}</span>
            ${isFileOwner 
              ? '<span class="badge badge-emerald" style="font-size:0.65rem; padding:1px 5px;">Owner</span>'
              : `<button type="button" onclick="revokeFileUserAccess('${fileId}', '${u}')" style="background:none; border:none; color:var(--coral-danger); cursor:pointer; font-weight:800; font-size:0.85rem; padding:0 2px;" title="Revoke access">&times;</button>`
            }
          </div>
        `;
      }).join('');
    } catch (err) {
      listEl.innerHTML = `<span style="color:var(--coral-danger); font-size:0.78rem;">Error loading users: ${err.message}</span>`;
    }
  }

  document.getElementById('modal-file-access-file-select')?.addEventListener('change', (e) => {
    loadAndRenderFileAuthorizedUsers(e.target.value);
  });

  document.getElementById('btn-grant-file-user-access')?.addEventListener('click', async () => {
    const fileId = document.getElementById('modal-file-access-file-select')?.value;
    const username = document.getElementById('modal-file-access-new-user')?.value.trim();
    if (!fileId || !username) {
      showToast('Please enter a username or upload an Excel file to grant file access', 'warning');
      return;
    }
    try {
      const res = await api.post(`/files/${fileId}/grant-user`, {
        fileId,
        userId: username,
        caller: state.activeUserId
      });
      if (res.success) {
        const countLabel = res.grantedCount && res.grantedCount > 1
          ? `${res.grantedCount} users (${res.grantedUsers.join(', ')})`
          : `'${(res.grantedUsers && res.grantedUsers[0]) || username}'`;
        showToast(`Granted direct file access to ${countLabel}!`, 'success');
        const inp = document.getElementById('modal-file-access-new-user');
        if (inp) inp.value = '';
        await loadUsers();
        await loadFiles();
        loadAndRenderFileAuthorizedUsers(fileId);
        if (state.currentView === 'requester') renderRequesterFilesTable();
        if (state.currentView === 'uploader') renderUploaderFilesTable();
      }
    } catch (err) {
      showToast(`Grant error: ${err.message}`, 'error');
    }
  });

  window.revokeFileUserAccess = async function(fileId, username) {
    try {
      const res = await api.post(`/files/${fileId}/revoke-user`, {
        fileId,
        userId: username,
        caller: state.activeUserId
      });
      if (res.success) {
        showToast(`Revoked file access from '${username}'`, 'warning');
        await loadFiles();
        loadAndRenderFileAuthorizedUsers(fileId);
        if (state.currentView === 'requester') renderRequesterFilesTable();
        if (state.currentView === 'uploader') renderUploaderFilesTable();
      }
    } catch (err) {
      showToast(`Revoke error: ${err.message}`, 'error');
    }
  };

  window.openFileLogViewersModal = function(fileId) {
    const sel = document.getElementById('modal-log-viewers-file-select');
    if (sel) {
      sel.innerHTML = state.files.map(f => 
        `<option value="${f.fileId}" ${f.fileId === fileId ? 'selected' : ''}>${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
      ).join('');
      sel.value = fileId;
      loadAndRenderLogViewers(fileId);
    }
    document.getElementById('modal-manage-log-viewers')?.classList.add('active');
  };

  window.openFileEmergencyWhitelistModal = function(fileId) {
    const eligibleFiles = state.files.filter(f => {
      const isOwner = (f.owner === state.activeUserId);
      const fileOrg = state.organizations.find(o => o.orgId === f.organizationId);
      const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);
      return isOwner || isCreator;
    });

    const targetFile = state.files.find(f => f.fileId === fileId);
    const targetOrg = targetFile ? state.organizations.find(o => o.orgId === targetFile.organizationId) : null;
    const isTargetOwner = Boolean(targetFile && targetFile.owner === state.activeUserId);
    const isTargetCreator = Boolean(targetOrg && targetOrg.creator === state.activeUserId);
    const canManageTarget = isTargetOwner || isTargetCreator;

    const sel = document.getElementById('modal-emergency-whitelist-file-select');
    const warnEl = document.getElementById('modal-emergency-whitelist-perm-warning');
    const warnTxt = document.getElementById('modal-emergency-whitelist-perm-warning-text');
    const inputEl = document.getElementById('modal-emergency-whitelist-new-user');
    const addBtn = document.getElementById('btn-add-emergency-responder');

    if (!canManageTarget) {
      if (sel) {
        sel.innerHTML = `<option value="${fileId}">${escapeHtml(targetFile?.fileName || fileId)} (${escapeHtml(fileId)})</option>`;
        sel.disabled = true;
      }
      if (warnEl && warnTxt) {
        warnTxt.textContent = `Permission Denied: You are signed in as '${state.activeUserId}'. Only the file uploader (${targetFile?.owner || 'owner'}) or organization creator is permitted to whitelist emergency responders.`;
        warnEl.style.display = 'flex';
      }
      if (inputEl) inputEl.disabled = true;
      if (addBtn) addBtn.disabled = true;
    } else {
      if (sel) {
        sel.disabled = false;
        sel.innerHTML = eligibleFiles.map(f => 
          `<option value="${f.fileId}" ${f.fileId === fileId ? 'selected' : ''}>${escapeHtml(f.fileName)} (${escapeHtml(f.fileId)})</option>`
        ).join('');
        sel.value = fileId;
      }
      if (warnEl) warnEl.style.display = 'none';
      if (inputEl) inputEl.disabled = false;
      if (addBtn) addBtn.disabled = false;
    }

    loadAndRenderEmergencyResponders(fileId);
    document.getElementById('modal-manage-emergency-whitelist')?.classList.add('active');
  };

  window.openRequesterBreakGlassModal = function(fileId) {
    const f = state.files.find(item => item.fileId === fileId);
    if (!f) return;

    const fnEl = document.getElementById('breakglass-modal-filename');
    const fidEl = document.getElementById('breakglass-modal-fileid');
    const incEl = document.getElementById('breakglass-modal-incident-id');
    const authEl = document.getElementById('breakglass-modal-auth-badge');
    const justEl = document.getElementById('breakglass-modal-justification');

    if (fnEl) fnEl.textContent = f.fileName;
    if (fidEl) fidEl.textContent = f.fileId;
    if (incEl) incEl.value = `INC-EMER-${Date.now().toString().slice(-6)}`;
    if (justEl) justEl.value = 'Critical emergency trauma patient / mission override required';

    const isOwner = (f.owner === state.activeUserId);
    const fileOrg = state.organizations.find(o => o.orgId === f.organizationId);
    const isCreator = Boolean(fileOrg && fileOrg.creator === state.activeUserId);
    const isWhitelisted = (f.emergencyWhitelistedUsers || []).includes(state.activeUserId) || isOwner || isCreator;

    if (authEl) {
      if (isWhitelisted) {
        authEl.innerHTML = `
          <span class="badge badge-emerald" style="font-size:0.75rem; padding:4px 10px;">
            ✓ Authorized Emergency Responder (Whitelisted by Owner/Creator)
          </span>
        `;
      } else {
        authEl.innerHTML = `
          <span class="badge badge-coral" style="font-size:0.75rem; padding:4px 10px;">
            ⛔ Not Authorized on Emergency Whitelist for this File
          </span>
        `;
      }
    }

    const submitBtn = document.getElementById('btn-submit-requester-breakglass');
    if (submitBtn) {
      submitBtn.dataset.fileId = fileId;
      submitBtn.disabled = !isWhitelisted;
      if (!isWhitelisted) {
        submitBtn.style.opacity = '0.5';
        submitBtn.title = 'You must be whitelisted by the file uploader or organization creator to trigger break-glass.';
      } else {
        submitBtn.style.opacity = '1';
        submitBtn.title = 'Execute Emergency Break-Glass Override';
      }
    }

    document.getElementById('modal-requester-emergency-breakglass')?.classList.add('active');
  };

  document.getElementById('btn-submit-requester-breakglass')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-submit-requester-breakglass');
    const fileId = btn?.dataset.fileId;
    const justification = document.getElementById('breakglass-modal-justification')?.value.trim();
    const incidentId = document.getElementById('breakglass-modal-incident-id')?.value;

    if (!fileId) return;
    if (!justification) {
      showToast('Please provide an emergency justification for on-chain audit', 'warning');
      return;
    }

    try {
      const res = await api.post('/emergency/break-glass', {
        fileId,
        requester: state.activeUserId,
        incidentId: incidentId || `INC-EMER-${Date.now().toString().slice(-6)}`,
        justification
      });

      if (res.success) {
        showToast(`🚨 Emergency Break-Glass override verified on-chain! Decrypting...`, 'success');
        document.getElementById('modal-requester-emergency-breakglass')?.classList.remove('active');
        await loadFiles();
        renderRequesterFilesTable();
        await quickDecrypt(fileId);
      } else {
        showToast(`Emergency override failed: ${res.error || 'Access denied'}`, 'error');
      }
    } catch (err) {
      showToast(`Emergency Break-Glass Denied: ${err.message}`, 'error');
    }
  });

  // ==========================================================================
  // EXCEL (.XLSX / .XLS / .CSV) BULK NAMES IMPORT FOR WHITELISTING & ACCESS
  // ==========================================================================
  let pendingExcelTargetInputId = null;
  let pendingExcelAutoClickBtnId = null;

  window.triggerExcelImportForInput = function(targetInputId, autoClickButtonId = null) {
    const fileInput = document.getElementById('global-excel-whitelist-input');
    if (!fileInput) {
      showToast('Excel upload input element not found', 'error');
      return;
    }
    pendingExcelTargetInputId = targetInputId;
    pendingExcelAutoClickBtnId = autoClickButtonId;
    fileInput.value = '';
    fileInput.click();
  };

  document.getElementById('global-excel-whitelist-input')?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file || !pendingExcelTargetInputId) return;

    const targetId = pendingExcelTargetInputId;
    const autoBtnId = pendingExcelAutoClickBtnId;
    const reader = new FileReader();

    reader.onload = async (evt) => {
      try {
        const dataUrl = evt.target.result || '';
        const base64Content = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
        const activeOrg = state.organizations.find(o => o.orgId === state.activeOrgPageId);
        const defaultOrg = activeOrg ? activeOrg.name : 'General Commons';

        const res = await api.post('/utils/parse-excel-usernames', {
          filename: file.name,
          contentBase64: base64Content,
          defaultOrg
        });

        if (res.success && Array.isArray(res.usernames) && res.usernames.length > 0) {
          const targetEl = document.getElementById(targetId);
          if (targetEl) {
            const existing = targetEl.value
              ? targetEl.value.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean)
              : [];
            const merged = Array.from(new Set([...existing, ...res.usernames]));
            targetEl.value = merged.join(', ');
          }
          await loadUsers();
          showToast(
            `📊 Imported ${res.count} name(s) from '${file.name}': ${res.usernames.join(', ')}`,
            'success'
          );

          if (autoBtnId) {
            const actionBtn = document.getElementById(autoBtnId);
            if (actionBtn && !actionBtn.disabled) {
              actionBtn.click();
            }
          }
        }
      } catch (err) {
        showToast(`Excel import failed: ${err.message}`, 'error');
      } finally {
        pendingExcelTargetInputId = null;
        pendingExcelAutoClickBtnId = null;
      }
    };

    reader.readAsDataURL(file);
  });

  window.downloadSampleWhitelistExcel = async function() {
    try {
      const res = await api.get('/utils/sample-whitelist-excel');
      if (res.success && res.contentBase64) {
        const binaryStr = atob(res.contentBase64);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          bytes[i] = binaryStr.charCodeAt(i);
        }
        const blob = new Blob([bytes], {
          type: res.mimeType || 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.filename || 'whitelisted_usernames_sample.xlsx';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`📥 Downloaded sample Excel '${res.filename || 'whitelisted_usernames_sample.xlsx'}' (contains names alone)`, 'info');
      }
    } catch (err) {
      showToast(`Failed to download sample Excel: ${err.message}`, 'error');
    }
  };

  // Scope Segment Buttons listener
  document.querySelectorAll('.scope-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.scope-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.requesterScope = btn.dataset.scope || 'all';
      renderRequesterFilesTable();
    });
  });

  // Initial Metadata Pre-Fetch for Frontdoor Registration Dropdowns
  try {
    await loadOrganizations();
    await loadClassifications();
  } catch (err) {
    console.warn('Initial metadata pre-fetch:', err);
  }

  // Strict Zero-Trust Entry Gate:
  // The application is always gated behind the frontdoor authentication gate upon opening.
  // App container remains completely hidden until cryptographic credentials are authenticated.
  window.showFrontdoorOverlay();
});
