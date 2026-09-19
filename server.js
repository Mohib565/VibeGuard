require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('[CRITICAL] Missing Supabase configuration inside .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Telemetry Logger
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const delta = Date.now() - start;
        console.log(`[PULSE] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${delta}ms)`);
    });
    next();
});

// Comprehensive Multi-Tier Rules with Actionable Suggestions
const AUDIT_RULES = [
    // --- TIER 1: HARD EXPOSURES ---
    {
        ruleId: 'SEC-001',
        type: 'OpenAI Secret API Key Leaked',
        severity: 'CRITICAL',
        regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{24,}/g,
        suggestion: 'Never hardcode AI keys. Move this key to a .env file and access via process.env.OPENAI_API_KEY.'
    },
    {
        ruleId: 'SEC-002',
        type: 'Supabase / JWT Secret Hardcoded',
        severity: 'HIGH',
        regex: /eyJh[a-zA-Z0-9-_]+\.eyJh[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/g,
        suggestion: 'Exposing service_role or JWT keys bypasses Row Level Security. Keep this secret strictly on the server.'
    },
    {
        ruleId: 'SEC-003',
        type: 'AWS Access Key ID Detected',
        severity: 'CRITICAL',
        regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
        suggestion: 'Revoke this AWS Key ID immediately from the AWS IAM console and use IAM Roles or environment variables.'
    },
    {
        ruleId: 'SEC-004',
        type: 'Database Connection String with Plain Credentials',
        severity: 'CRITICAL',
        regex: /(postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s"']+@[^\s"']+/gi,
        suggestion: 'Exposing plain text database credentials enables unauthorized database dumps. Use parameterized connection pools from .env.'
    },
    {
        ruleId: 'SEC-005',
        type: 'Vulnerable Dynamic SQL Concatenation (SQLi Risk)',
        severity: 'HIGH',
        regex: /(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[\w\.]+/gi,
        suggestion: 'Do not concatenate query strings with variables. Use parameterized queries ($1, $2) or an ORM/query builder.'
    },
    {
        ruleId: 'SEC-006',
        type: 'GitHub Personal Access Token (PAT)',
        severity: 'CRITICAL',
        regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
        suggestion: 'Active GitHub tokens allow full repository takeover. Invalidate this token from GitHub Developer Settings.'
    },

    // --- TIER 2: ARCHITECTURAL CODE HARDENING & JAVASCRIPT/NODE FLAWS ---
    {
        ruleId: 'HARDEN-001',
        type: 'Permissive Wildcard CORS Detected',
        severity: 'LOW',
        regex: /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/gi,         suggestion: 'Avoid origin: "*". Whitelist specific allowed frontend domains: cors({ origin: ["https://yourdomain.com"] }).'     },     {         ruleId: 'HARDEN-002',         type: 'Unsafe Dynamic Code Execution (eval)',         severity: 'MEDIUM',         regex: /\beval\s*\([^\)]+\)/gi,
        suggestion: 'eval() allows arbitrary remote code execution. Parse structured data using JSON.parse() instead.'
    },
    {
        ruleId: 'HARDEN-003',
        type: 'Direct innerHTML Injection Vector (XSS Hazard)',
        severity: 'LOW',
        regex: /\.innerHTML\s*=/gi,
        suggestion: 'Direct innerHTML assignment causes DOM-based XSS. Use textContent, innerText, or DOMPurify.sanitize().'
    },
    {
        ruleId: 'HARDEN-004',
        type: 'Debug Trace Exposure (console.log)',
        severity: 'LOW',
        regex: /console\.log\s*\(\s*.*(err|error|exception|user|req\.body|pass)/gi,
        suggestion: 'Avoid logging internal error objects or request bodies in production. Use a structured logger (Pino or Winston) with redaction.'
    },
    {
        ruleId: 'HARDEN-005',
        type: 'Hardcoded Port Fallback',
        severity: 'LOW',
        regex: /listen\s*\(\s*(3000|5000|8080)\b/gi,
        suggestion: 'Make sure your listener falls back gracefully to system environment: app.listen(process.env.PORT || 5000).'
    }
];

function maskSecret(val) {
    if (val.length <= 8) return '****';
    return val.substring(0, 4) + '...' + val.substring(val.length - 4);
}

function parseGitHubUrl(repoUrl) {
    try {
        const clean = repoUrl.trim().replace(/\/$/, '');
        const match = clean.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/);
        if (!match) return null;
        return { owner: match[1], repo: match[2].replace('.git', '') };
    } catch {
        return null;
    }
}

// Health Probe
app.get('/api/health', async (req, res) => {
    const { count, error } = await supabase.from('repositories').select('*', { count: 'exact', head: true });
    if (error) return res.status(500).json({ success: false, status: 'OFFLINE', error: error.message });
    return res.status(200).json({ success: true, status: 'CONNECTED', trackedRepos: count || 0 });
});

// Read All Audits (CRUD: READ)
app.get('/api/repos', async (req, res) => {
    const { data, error } = await supabase
        .from('repositories')
        .select(`*, findings (*)`)
        .order('scanned_at', { ascending: false });

    if (error) return res.status(500).json({ success: false, error: error.message });
    return res.status(200).json({ success: true, data });
});

// SSE Streaming Scanner with Dynamic Recommendations
app.get('/api/scan-stream', async (req, res) => {
    const { repoUrl, customFileName, customSourceCode } = req.query;

    if (!repoUrl) return res.status(400).send('Repository URL is required.');

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const sendEvent = (data) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    };

    const detectedFindings = [];
    let repoDisplayName = '';
    let filesAuditedCount = 0;
    let hasGitignore = false;

    try {
        // CASE A: Custom Snippet
        if (customSourceCode && customSourceCode.trim().length > 0) {
            sendEvent({ step: 'INFO', message: 'Analyzing raw code buffer...', type: 'info' });
            const filePath = customFileName ? customFileName.trim() : 'custom_file.js';
            repoDisplayName = repoUrl.replace('https://github.com/', '') || 'Code Snippet';

            sendEvent({ step: 'SCAN', message: `Executing deep heuristic pass on ${filePath}`, type: 'active' });
            const lines = customSourceCode.split('\n');
            filesAuditedCount = 1;

            lines.forEach((lineText, idx) => {
                const lineNum = idx + 1;
                AUDIT_RULES.forEach(rule => {
                    const matches = lineText.match(rule.regex);
                    if (matches) {
                        matches.forEach(m => {
                            detectedFindings.push({
                                rule_id: rule.ruleId,
                                secret_type: rule.type,
                                file_path: filePath,
                                line_number: lineNum,
                                masked_payload: maskSecret(m.trim()),
                                severity: rule.severity,
                                suggestion: rule.suggestion,
                                status: 'ACTIVE'
                            });
                            sendEvent({ step: 'ALERT', message: `[${rule.severity}] ${rule.type} at line ${lineNum}`, type: 'warn' });
                        });
                    }
                });
            });
        }
        // CASE B: GitHub Live Crawl
        else {
            const repoInfo = parseGitHubUrl(repoUrl);
            if (!repoInfo) {
                sendEvent({ step: 'ERROR', message: 'Invalid URL format.', type: 'error' });
                return res.end();
            }

            const { owner, repo } = repoInfo;
            repoDisplayName = `${owner}/${repo}`;
            sendEvent({ step: 'INFO', message: `Querying GitHub API for [${owner}/${repo}]...`, type: 'info' });

            const metaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
                headers: { 'User-Agent': 'VibeGuard-Production-Scanner' }
            });

            if (!metaRes.ok) {
                sendEvent({ step: 'ERROR', message: `Repository inaccessible (HTTP ${metaRes.status}). Verify it is public.`, type: 'error' });
                return res.end();
            }

            const metaData = await metaRes.json();
            const defaultBranch = metaData.default_branch || 'main';
            sendEvent({ step: 'INFO', message: `Default branch resolved: [${defaultBranch}]`, type: 'info' });

            const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`, {
                headers: { 'User-Agent': 'VibeGuard-Production-Scanner' }
            });

            if (!treeRes.ok) {
                sendEvent({ step: 'ERROR', message: 'Failed to extract git directory tree.', type: 'error' });
                return res.end();
            }

            const treeData = await treeRes.json();
            const scannableExts = ['.js', '.jsx', '.ts', '.tsx', '.py', '.env', '.json', '.html', '.php', '.sql', '.yaml', '.yml'];

            const rawTree = treeData.tree || [];
            hasGitignore = rawTree.some(item => item.path === '.gitignore');

            const filesToScan = rawTree.filter(item => {
                if (item.type !== 'blob') return false;
                const pathLower = item.path.toLowerCase();
                const isIgnored = pathLower.includes('node_modules/') || 
                                  pathLower.includes('.git/') || 
                                  pathLower.includes('dist/') || 
                                  pathLower.includes('build/') || 
                                  pathLower.includes('package-lock.json') ||
                                  pathLower.includes('.min.');
                const hasExt = scannableExts.some(ext => pathLower.endsWith(ext));
                return !isIgnored && hasExt;
            }).slice(0, 25);

            sendEvent({ step: 'INFO', message: `Tree analyzed. Crawling ${filesToScan.length} source files for vulnerability & architectural checks...`, type: 'info' });

            for (let i = 0; i < filesToScan.length; i++) {
                const file = filesToScan[i];
                sendEvent({ step: 'SCAN', message: `[${i + 1}/${filesToScan.length}] Inspecting: ${file.path}`, type: 'active' });

                try {
                    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${file.path}`;
                    const fileRes = await fetch(rawUrl);
                    if (!fileRes.ok) continue;

                    const fileContent = await fileRes.text();
                    const lines = fileContent.split('\n');

                    lines.forEach((lineText, idx) => {
                        const lineNum = idx + 1;
                        AUDIT_RULES.forEach(rule => {
                            const matches = lineText.match(rule.regex);
                            if (matches) {
                                matches.forEach(m => {
                                    detectedFindings.push({
                                        rule_id: rule.ruleId,
                                        secret_type: rule.type,
                                        file_path: file.path,
                                        line_number: lineNum,
                                        masked_payload: maskSecret(m.trim()),
                                        severity: rule.severity,
                                        suggestion: rule.suggestion,
                                        status: 'ACTIVE'
                                    });
                                    sendEvent({ step: 'ALERT', message: `⚠️ [${rule.severity}] Found: ${rule.type} in ${file.path}:${lineNum}`, type: 'warn' });
                                });
                            }
                        });
                    });
                } catch (e) {
                    console.error('File stream error:', e);
                }

                filesAuditedCount++;
                await new Promise(r => setTimeout(r, 45));
            }

            // Fallback Perimeter Check: Agar .gitignore missing ho toh suggestion add karein
            if (!hasGitignore) {
                detectedFindings.push({
                    rule_id: 'PERIM-001',
                    secret_type: 'Missing Root .gitignore Configuration',
                    file_path: '.gitignore',
                    line_number: 1,
                    masked_payload: 'FILE_ABSENT',
                    severity: 'MEDIUM',
                    suggestion: 'Create a .gitignore in your root directory immediately to prevent accidental commits of .env, node_modules, and keys.',
                    status: 'ACTIVE'
                });
                sendEvent({ step: 'ALERT', message: '⚠️ Perimeter Warning: Root .gitignore file not found.', type: 'warn' });
            }
        }

        // Penalty and Realistic Scoring (Har finding ka wazeh asar score par hoga)
        const criticals = detectedFindings.filter(f => f.severity === 'CRITICAL').length;
        const highs = detectedFindings.filter(f => f.severity === 'HIGH').length;
        const mediums = detectedFindings.filter(f => f.severity === 'MEDIUM').length;
        const lows = detectedFindings.filter(f => f.severity === 'LOW').length;

        let penalty = (criticals * 30) + (highs * 15) + (mediums * 8) + (lows * 3);
        const healthScore = Math.max(12, 100 - penalty);

        sendEvent({ step: 'PERSIST', message: 'Saving findings and security suggestions to Supabase...', type: 'info' });

        const cleanRepoUrl = `https://github.com/${repoDisplayName}`;
        const { data: repoRecord, error: repoError } = await supabase
            .from('repositories')
            .upsert({
                repo_url: cleanRepoUrl,
                repo_name: repoDisplayName,
                health_score: healthScore,
                total_findings: detectedFindings.length,
                scanned_at: new Date().toISOString()
            }, { onConflict: 'repo_url' })
            .select()
            .single();

        if (repoError) throw repoError;

        await supabase.from('findings').delete().eq('repo_id', repoRecord.id);

        if (detectedFindings.length > 0) {
            const mapped = detectedFindings.map(f => ({ ...f, repo_id: repoRecord.id }));
            const { error: findErr } = await supabase.from('findings').insert(mapped);
            if (findErr) throw findErr;
        }

        sendEvent({ step: 'COMPLETE', message: `Audit finalized. Found ${detectedFindings.length} issue(s) / recommendations. Security Score: ${healthScore}%.`, type: 'success' });
        res.end();

    } catch (err) {
        console.error('[STREAM FATAL]', err);
        sendEvent({ step: 'ERROR', message: `Audit aborted: ${err.message}`, type: 'error' });
        res.end();
    }
});

// Update status
app.patch('/api/findings/:id', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    const { data, error } = await supabase
        .from('findings')
        .update({ status, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select()
        .single();

    if (error || !data) return res.status(404).json({ success: false, error: 'Finding not found.' });
    return res.status(200).json({ success: true, data });
});

// Delete
app.delete('/api/repos/:id', async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('repositories').delete().eq('id', id);
    if (error) return res.status(500).json({ success: false, error: error.message });
    return res.status(204).send();
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`[VIBEGUARD INTELLIGENCE ENGINE] Running on http://localhost:${PORT}`);
});