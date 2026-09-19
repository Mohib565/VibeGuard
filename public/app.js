document.addEventListener('DOMContentLoaded', () => {
    const auditForm = document.getElementById('auditForm');
    const repoUrl = document.getElementById('repoUrl');
    const btnScan = document.getElementById('btnScan');
    const btnRefresh = document.getElementById('btnRefresh');
    const testRepoBtn = document.getElementById('testRepoBtn');
    const toggleOptional = document.getElementById('toggleOptional');
    const optionalBox = document.getElementById('optionalBox');
    const toggleArrow = document.getElementById('toggleArrow');
    const customFileName = document.getElementById('customFileName');
    const customSourceCode = document.getElementById('customSourceCode');
    const terminalContainer = document.getElementById('terminalContainer');
    const terminalFeed = document.getElementById('terminalFeed');
    const streamStatusBadge = document.getElementById('streamStatusBadge');
    const reportsFeed = document.getElementById('reportsFeed');
    const dbState = document.getElementById('dbState');
    const themeToggle = document.getElementById('themeToggle');
    const themeEmoji = document.getElementById('themeEmoji');
    const themeTitle = document.getElementById('themeTitle');

    // Theme Switcher
    function applyTheme(mode) {
        document.documentElement.setAttribute('data-theme', mode);
        localStorage.setItem('vibeguard_user_theme', mode);
        if (mode === 'dark') {
            themeEmoji.textContent = '☀️';
            themeTitle.textContent = 'Light Mode';
        } else {
            themeEmoji.textContent = '🌙';
            themeTitle.textContent = 'Dark Mode';
        }
    }
    applyTheme(localStorage.getItem('vibeguard_user_theme') || 'light');

    themeToggle.addEventListener('click', () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        applyTheme(isDark ? 'light' : 'dark');
    });

    // Toggle Optional Section
    toggleOptional.addEventListener('click', () => {
        optionalBox.classList.toggle('open');
        toggleArrow.textContent = optionalBox.classList.contains('open') ? '▲' : '▼';
    });

    // Quick Test Repo
    testRepoBtn.addEventListener('click', () => {
        repoUrl.value = 'https://github.com/Mohib565/Cyber-Guard';
    });

    // Supabase Health Check
    async function checkHealth() {
        try {
            const res = await fetch('/api/health');
            const data = await res.json();
            if (data.success) {
                dbState.textContent = 'Connected';
            }
        } catch {
            dbState.textContent = 'Offline';
        }
    }

    function appendTerminalLog(message, type = 'info') {
        const time = new Date().toLocaleTimeString();
        const row = document.createElement('div');
        row.className = 'log-entry';
        row.innerHTML = `
            <span class="log-time">[${time}]</span>
            <span class="log-${type}">${message}</span>
        `;
        terminalFeed.appendChild(row);
        terminalFeed.scrollTop = terminalFeed.scrollHeight;
    }

    // Load Audits from Database
    async function loadReports() {
        try {
            const res = await fetch('/api/repos');
            const result = await res.json();

            if (!result.success || !result.data || result.data.length === 0) {
                reportsFeed.innerHTML = `
                    <div class="empty-box">
                        No repositories audited yet. Paste a link above to see real findings and actionable suggestions.
                    </div>`;
                return;
            }

            reportsFeed.innerHTML = result.data.map(repo => {
                let scoreClass = 'score-safe';
                if (repo.health_score < 80) scoreClass = 'score-warn';
                if (repo.health_score < 50) scoreClass = 'score-danger';

                const findingsHtml = (repo.findings || []).map(f => `
                    <div class="finding-card-item">
                        <div class="finding-row">
                            <div class="finding-left">
                                <span class="sev-tag sev-${f.severity}">${f.severity}</span>
                                <span><strong>${f.secret_type}</strong></span>
                                <span style="color: var(--text-muted);">(${f.file_path}:${f.line_number})</span>
                                <span class="code-leak">${f.masked_payload}</span>
                            </div>
                            <div>
                                <button class="btn-toggle-fix" onclick="updateStatus('${f.id}', '${f.status === 'ACTIVE' ? 'MITIGATED' : 'ACTIVE'}')">
                                    ${f.status === 'ACTIVE' ? 'Mark Resolved ✅' : 'Reopen ⚠️'}
                                </button>
                            </div>
                        </div>
                        ${f.suggestion ? `
                            <div class="suggestion-box">
                                <span class="sugg-icon">💡</span>
                                <div>
                                    <span class="sugg-label">Code Hardening Suggestion:</span>
                                    <p class="sugg-text">${f.suggestion}</p>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                `).join('');

                return `
                    <div class="repo-card">
                        <div class="repo-card-head">
                            <div>
                                <div class="repo-title">${repo.repo_name}</div>
                                <a href="${repo.repo_url}" target="_blank" class="repo-link">${repo.repo_url} ↗</a>
                            </div>
                            <div class="card-tags">
                                <span class="score-pill ${scoreClass}">Security Score: ${repo.health_score}%</span>
                                <button class="btn-del" onclick="deleteAudit('${repo.id}')">Delete</button>
                            </div>
                        </div>
                        <div class="findings-box">
                            ${(repo.findings && repo.findings.length > 0) 
                                ? findingsHtml 
                                : '<div class="all-clean">✅ Exceptional Security: Zero exposures or code hardening flaws located.</div>'}
                        </div>
                    </div>
                `;
            }).join('');
        } catch (err) {
            console.error('Database load error:', err);
        }
    }

    // Submit SSE Scan Stream
    auditForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const url = repoUrl.value.trim();
        const fileName = customFileName.value.trim();
        const sourceCode = customSourceCode.value.trim();

        btnScan.disabled = true;
        terminalContainer.classList.remove('hidden');
        terminalFeed.innerHTML = '';
        streamStatusBadge.textContent = 'SCANNING IN PROGRESS';
        streamStatusBadge.style.background = 'rgba(56, 189, 248, 0.2)';
        streamStatusBadge.style.color = '#38bdf8';

        appendTerminalLog(`Initiating inspection stream for: ${url}`, 'info');

        const params = new URLSearchParams({
            repoUrl: url,
            customFileName: fileName,
            customSourceCode: sourceCode
        });

        const eventSource = new EventSource(`/api/scan-stream?${params.toString()}`);

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.step === 'COMPLETE') {
                eventSource.close();
                btnScan.disabled = false;
                streamStatusBadge.textContent = 'COMPLETED';
                streamStatusBadge.style.background = 'rgba(16, 185, 129, 0.2)';
                streamStatusBadge.style.color = '#10b981';
                loadReports();
                return;
            }

            appendTerminalLog(data.message, data.type || 'info');
        };

        eventSource.onerror = () => {
            eventSource.close();
            btnScan.disabled = false;
            streamStatusBadge.textContent = 'FAILED';
            streamStatusBadge.style.background = 'rgba(239, 68, 68, 0.2)';
            streamStatusBadge.style.color = '#ef4444';
            appendTerminalLog('Stream closed unexpectedly or rate limit reached.', 'error');
        };
    });

    window.updateStatus = async (id, status) => {
        await fetch(`/api/findings/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        loadReports();
    };

    window.deleteAudit = async (id) => {
        if (confirm('Delete this audit report from Supabase?')) {
            await fetch(`/api/repos/${id}`, { method: 'DELETE' });
            loadReports();
        }
    };

    btnRefresh.addEventListener('click', loadReports);

    checkHealth();
    loadReports();
});