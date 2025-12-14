async function collectAndTrack(linkId, targetUrl) {
    // Race fingerprint collection against a 2s timeout
    const fingerprintData = await Promise.race([
        getAdvancedFingerprint(),
        new Promise(resolve => setTimeout(() => resolve({ error: "timeout" }), 2000))
    ]);

    const fingerprintHash = await sha256(JSON.stringify(fingerprintData));

    const data = {
        link_id: linkId,
        screen_width: window.screen.width,
        screen_height: window.screen.height,
        device_pixel_ratio: window.devicePixelRatio,
        language: navigator.language,
        platform: navigator.platform,
        fingerprint: fingerprintHash,
        fingerprint_details: JSON.stringify(fingerprintData, null, 2)
    };

    // Solve Hash Cash
    data.hash_cash = await solveHashCash(data.fingerprint);

    try {
        await fetch('/track', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
    } catch (e) {
        console.error("Tracking failed", e);
    }

    window.location.href = targetUrl;
}

async function getAdvancedFingerprint() {
    return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        screenResolution: `${window.screen.width}x${window.screen.height}`,
        colorDepth: window.screen.colorDepth,
        timezoneOffset: new Date().getTimezoneOffset(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        canvas: await getCanvasFingerprint(),
        webgl: getWebGLFingerprint(),
        audio: await getAudioFingerprint(),
        fonts: await getFontsFingerprint()
    };
}

async function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("Zenir", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("Zenir", 4, 17);
    return await sha256(canvas.toDataURL());
}

function getWebGLFingerprint() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return null;
    return {
        vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
        renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
    };
}

async function getAudioFingerprint() {
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return null;
        const context = new AudioContext();
        const oscillator = context.createOscillator();
        const analyser = context.createAnalyser();
        const gain = context.createGain();
        const scriptProcessor = context.createScriptProcessor(4096, 1, 1);

        gain.gain.value = 0;
        oscillator.type = 'triangle';
        oscillator.connect(analyser);
        analyser.connect(scriptProcessor);
        scriptProcessor.connect(context.destination);

        oscillator.start(0);

        return new Promise(resolve => {
            const timeout = setTimeout(() => {
                oscillator.stop();
                scriptProcessor.disconnect();
                context.close();
                resolve("timeout");
            }, 500); // 500ms timeout

            scriptProcessor.onaudioprocess = (bins) => {
                clearTimeout(timeout);
                oscillator.stop();
                scriptProcessor.disconnect();
                context.close();

                const array = new Float32Array(analyser.frequencyBinCount);
                analyser.getFloatFrequencyData(array);
                // Simple hash of the frequency data
                resolve(array.slice(0, 10).join(','));
            };
        });
    } catch (e) {
        return null;
    }
}

async function getFontsFingerprint() {
    // Simple font detection
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const fontList = [
        'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia',
        'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Arial Black', 'Impact'
    ];

    const testString = "mmmmmmmmmmlli";
    const testSize = "72px";
    const h = document.getElementsByTagName("body")[0];
    const baseWidths = {};

    // Create spans for base fonts
    for (const base of baseFonts) {
        const s = document.createElement("span");
        s.style.fontSize = testSize;
        s.style.fontFamily = base;
        s.innerHTML = testString;
        h.appendChild(s);
        baseWidths[base] = s.offsetWidth;
        h.removeChild(s);
    }

    const detected = [];
    for (const font of fontList) {
        let match = false;
        for (const base of baseFonts) {
            const s = document.createElement("span");
            s.style.fontSize = testSize;
            s.style.fontFamily = `'${font}', ${base}`;
            s.innerHTML = testString;
            h.appendChild(s);
            if (s.offsetWidth !== baseWidths[base]) {
                match = true;
            }
            h.removeChild(s);
            if (match) break;
        }
        if (match) detected.push(font);
    }
    return detected;
}

async function solveHashCash(fingerprint) {
    let nonce = 0;
    while (true) {
        const str = fingerprint + nonce;
        const hash = await sha256(str);
        if (hash.startsWith("0000")) {
            return nonce.toString();
        }
        nonce++;
    }
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
