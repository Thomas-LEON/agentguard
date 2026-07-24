document.addEventListener('DOMContentLoaded', () => {
    const editor = document.getElementById('code-editor');
    const lineNumbers = document.getElementById('line-numbers');
    const runBtn = document.getElementById('run-btn');
    const logsContainer = document.getElementById('logs-container');
    const overallStatus = document.getElementById('overall-status');
    const statusText = document.querySelector('.status-text');
    const logsPanel = document.querySelector('.logs-panel');

    // Sync line numbers with textarea content
    function updateLineNumbers() {
        const lines = editor.value.split('\n').length;
        lineNumbers.innerHTML = Array(lines).fill(0).map((_, i) => i + 1).join('<br>');
    }

    editor.addEventListener('input', updateLineNumbers);
    updateLineNumbers();

    // Add a log entry to the dashboard
    function addLog(type, layer, message) {
        const div = document.createElement('div');
        div.className = `log-entry ${type}`;
        
        const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false, hour: "numeric", minute: "numeric", second: "numeric", fractionalSecondDigits: 3 });
        
        div.innerHTML = `
            <span class="timestamp">[${layer}]</span>
            <span class="message">${message}</span>
        `;
        
        logsContainer.appendChild(div);
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    // Set the overall status indicator
    function setStatus(status, text) {
        overallStatus.className = 'status-indicator ' + status;
        statusText.textContent = text;
        
        if (status === 'blocked') {
            logsPanel.classList.remove('flash-red', 'flash-green');
            void logsPanel.offsetWidth; // trigger reflow
            logsPanel.classList.add('flash-red');
        } else if (status === 'allowed') {
            logsPanel.classList.remove('flash-red', 'flash-green');
            void logsPanel.offsetWidth;
            logsPanel.classList.add('flash-green');
        }
    }

    // Execute code via the FastAPI backend
    async function runCode() {
        const code = editor.value;
        if (!code.trim()) return;

        // Reset UI
        runBtn.disabled = true;
        runBtn.innerHTML = '<svg class="spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg> Scanning...';
        
        addLog('info', 'AGENT', 'Submitting code for execution...');
        setStatus('scanning', 'Analyzing AST...');

        try {
            const response = await fetch('/api/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            // Step 1: AST Validator
            addLog('system', 'PIPELINE', '⏳ Running AST Static Analysis...');
            await new Promise(r => setTimeout(r, 500));
            
            if (data.status === 'blocked' && data.layer === 'AST Validator') {
                setStatus('blocked', 'BLOCKED');
                addLog('error', 'AST Validator', `🚨 Blocked: ${data.message}`);
                runBtn.disabled = false;
                runBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Run Code';
                return;
            }
            addLog('success', 'AST Validator', '✅ Passed');

            // Step 2: Network Filter
            addLog('system', 'PIPELINE', '⏳ Running Network Filter...');
            await new Promise(r => setTimeout(r, 500));
            
            if (data.status === 'blocked' && data.layer === 'Network Filter') {
                setStatus('blocked', 'BLOCKED');
                addLog('error', 'Network Filter', `🚨 Blocked: ${data.message}`);
                runBtn.disabled = false;
                runBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Run Code';
                return;
            }
            addLog('success', 'Network Filter', '✅ Passed');

            // Step 3: Semantic Judge
            addLog('system', 'PIPELINE', '⏳ Running Semantic Judge...');
            await new Promise(r => setTimeout(r, 500));
            
            if (data.status === 'blocked' && (data.layer === 'Semantic Judge' || data.layer.includes('Semantic Judge'))) {
                setStatus('blocked', 'BLOCKED');
                addLog('error', 'Semantic Judge', `🚨 Blocked: ${data.message}`);
                runBtn.disabled = false;
                runBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Run Code';
                return;
            }
            addLog('success', 'Semantic Judge', '✅ Passed');

            // Execution
            if (data.status === 'allowed') {
                addLog('system', 'PIPELINE', '⚙️ Executing safely sandboxed code...');
                await new Promise(r => setTimeout(r, 500));
                
                setStatus('allowed', 'SAFE');
                addLog('success', 'AGENTGUARD', 'Code executed successfully.');
                
                if (data.output) {
                    addLog('info', 'STDOUT', `<pre>${data.output}</pre>`);
                }
            } else {
                setStatus('blocked', 'ERROR');
                addLog('error', 'SYSTEM', `Execution Error: ${data.message}`);
            }
            
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Run Code';

        } catch (err) {
            setStatus('blocked', 'CONNECTION ERROR');
            addLog('error', 'SYSTEM', 'Failed to connect to AgentGuard backend.');
            
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9V3z"/></svg> Run Code';
        }
    }

    runBtn.addEventListener('click', runCode);

    // Optional: Typewriter effect for recording the GIF
    window.simulateTyping = async function(text, delay = 50) {
        editor.value = '';
        updateLineNumbers();
        
        for (let i = 0; i < text.length; i++) {
            editor.value += text.charAt(i);
            updateLineNumbers();
            await new Promise(r => setTimeout(r, delay));
        }
        
        setTimeout(runCode, 500);
    };
});
