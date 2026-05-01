import os
import yara
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Compile the YARA rules when the server starts
try:
    rules = yara.compile(filepath='rules.yar')
except yara.SyntaxError as e:
    print(f"Error compiling YARA rules: {e}")
    rules = None

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YARA Threat Intelligence</title>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #050505;
            --panel-bg: rgba(10, 15, 20, 0.85);
            --neon-blue: #00f3ff;
            --neon-green: #39ff14;
            --neon-red: #ff003c;
            --grid-color: rgba(0, 243, 255, 0.05);
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Share Tech Mono', monospace;
            background-color: var(--bg-base);
            color: #fff;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            overflow: hidden;
            /* Animated Grid Background */
            background-image: 
                linear-gradient(var(--grid-color) 1px, transparent 1px),
                linear-gradient(90deg, var(--grid-color) 1px, transparent 1px);
            background-size: 30px 30px;
            animation: gridMove 20s linear infinite;
        }

        @keyframes gridMove {
            0% { background-position: 0 0; }
            100% { background-position: 30px 30px; }
        }

        .dashboard {
            width: 100%;
            max-width: 650px;
            padding: 20px;
            position: relative;
            z-index: 10;
        }

        .scanner-card {
            background: var(--panel-bg);
            border: 1px solid rgba(0, 243, 255, 0.2);
            border-radius: 4px;
            padding: 40px;
            box-shadow: 0 0 30px rgba(0, 243, 255, 0.05),
                        inset 0 0 20px rgba(0, 243, 255, 0.05);
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }

        /* Top decorative bar */
        .scanner-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: var(--neon-blue);
            box-shadow: 0 0 15px var(--neon-blue);
        }

        h2 {
            margin: 0 0 5px 0;
            font-size: 28px;
            color: var(--neon-blue);
            text-shadow: 0 0 10px rgba(0, 243, 255, 0.5);
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        p.sys-status {
            color: #888;
            font-size: 14px;
            margin-bottom: 35px;
            border-bottom: 1px dashed #333;
            padding-bottom: 15px;
        }

        /* Drop Zone */
        .upload-zone {
            position: relative;
            border: 2px dashed rgba(0, 243, 255, 0.3);
            background: rgba(0, 0, 0, 0.5);
            padding: 50px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            margin-bottom: 25px;
            overflow: hidden;
        }

        .upload-zone:hover {
            border-color: var(--neon-blue);
            box-shadow: inset 0 0 20px rgba(0, 243, 255, 0.1);
        }

        .upload-zone input[type="file"] {
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            opacity: 0;
            cursor: pointer;
            z-index: 5;
        }

        .icon {
            font-size: 40px;
            display: block;
            margin-bottom: 10px;
            text-shadow: 0 0 10px rgba(255,255,255,0.3);
        }

        .file-status {
            color: var(--neon-blue);
            font-size: 16px;
            display: block;
        }

        /* The Laser Animation */
        .laser {
            position: absolute;
            top: -10px;
            left: 0;
            width: 100%;
            height: 2px;
            background: var(--neon-blue);
            box-shadow: 0 0 15px 5px rgba(0, 243, 255, 0.4);
            opacity: 0;
            pointer-events: none;
        }

        .laser.active {
            animation: scan 2s ease-in-out infinite alternate;
            opacity: 1;
        }

        @keyframes scan {
            0% { top: 0; }
            100% { top: 100%; }
        }

        /* Button */
        .btn-scan {
            width: 100%;
            background: transparent;
            color: var(--neon-blue);
            border: 1px solid var(--neon-blue);
            padding: 16px;
            font-family: inherit;
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 3px;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
        }

        .btn-scan:hover {
            background: var(--neon-blue);
            color: #000;
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.6);
        }

        /* Loader Overlay */
        .overlay {
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(5, 5, 5, 0.95);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 20;
            display: none;
        }

        .spinner {
            width: 50px; height: 50px;
            border: 3px solid transparent;
            border-top-color: var(--neon-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 20px;
        }

        @keyframes spin { 100% { transform: rotate(360deg); } }

        /* Results Display */
        .result-box {
            margin-top: 30px;
            padding: 25px;
            border-left: 4px solid;
            background: rgba(0,0,0,0.6);
            animation: glitchIn 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94) both;
        }

        .clean {
            border-color: var(--neon-green);
            box-shadow: 0 0 15px rgba(57, 255, 20, 0.1);
        }
        .clean h3 { color: var(--neon-green); text-shadow: 0 0 10px rgba(57, 255, 20, 0.5); }

        .infected {
            border-color: var(--neon-red);
            box-shadow: 0 0 15px rgba(255, 0, 60, 0.1);
        }
        .infected h3 { color: var(--neon-red); text-shadow: 0 0 10px rgba(255, 0, 60, 0.5); margin-top: 0;}

        ul.matches {
            list-style: none; padding: 0; margin: 15px 0 0 0;
            background: rgba(255, 0, 60, 0.05);
            border: 1px solid rgba(255, 0, 60, 0.2);
            padding: 15px;
        }

        ul.matches li {
            color: #ffb3c1;
            margin-bottom: 8px;
        }
        ul.matches li::before { content: "[CRITICAL] "; color: var(--neon-red); }

        @keyframes glitchIn {
            0% { transform: translate(-20px, 20px); opacity: 0; }
            20% { transform: translate(20px, -10px); opacity: 0.5; }
            40% { transform: translate(-10px, 10px); opacity: 0.8; }
            60% { transform: translate(10px, -5px); opacity: 1; }
            80% { transform: translate(-5px, 5px); }
            100% { transform: translate(0, 0); }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="scanner-card">
            
            <div class="overlay" id="loadingOverlay">
                <div class="spinner"></div>
                <div style="color: var(--neon-blue); letter-spacing: 2px;">ANALYZING PAYLOAD...</div>
                <div style="color: #666; font-size: 12px; margin-top: 10px;" id="loadingText">Extracting bytes...</div>
            </div>

            <h2>YARA_ENGINE v2.0</h2>
            <p class="sys-status">STATUS: ONLINE | AWAITING BINARY INPUT</p>
            
            <form method="POST" enctype="multipart/form-data" id="scanForm">
                <div class="upload-zone" id="dropZone">
                    <div class="laser" id="laser"></div>
                    <span class="icon">▤</span>
                    <input type="file" name="file" id="fileInput" required>
                    <span class="file-status" id="fileNameDisplay">SELECT TARGET FILE</span>
                </div>
                <button type="button" class="btn-scan" id="scanBtn">INITIATE SCAN</button>
            </form>

            {% if result is defined %}
                {% if matches %}
                    <div class="result-box infected">
                        <h3>[!] MALWARE SIGNATURE DETECTED</h3>
                        <p style="color: #ccc; font-size: 14px;">The engine identified known threat patterns:</p>
                        <ul class="matches">
                            {% for match in matches %}
                                <li>{{ match }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                {% else %}
                    <div class="result-box clean">
                        <h3>[✓] PAYLOAD SECURE</h3>
                        <p style="color: #ccc; font-size: 14px;">Zero malicious signatures triggered. File appears benign.</p>
                    </div>
                {% endif %}
            {% endif %}
        </div>
    </div>

    <script>
        const fileInput = document.getElementById('fileInput');
        const fileNameDisplay = document.getElementById('fileNameDisplay');
        const scanBtn = document.getElementById('scanBtn');
        const scanForm = document.getElementById('scanForm');
        const laser = document.getElementById('laser');
        const overlay = document.getElementById('loadingOverlay');
        const loadingText = document.getElementById('loadingText');

        // Trigger laser and text change on file select
        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                fileNameDisplay.textContent = "TARGET ACQUIRED: " + e.target.files[0].name;
                fileNameDisplay.style.color = "var(--neon-green)";
                laser.classList.add('active'); // Turn on the scanning laser
            } else {
                fileNameDisplay.textContent = 'SELECT TARGET FILE';
                fileNameDisplay.style.color = 'var(--neon-blue)';
                laser.classList.remove('active');
            }
        });

        // Intercept button click for cool fake loading sequence
        scanBtn.addEventListener('click', function(e) {
            if(fileInput.files.length === 0) {
                alert("SYSTEM ERROR: No payload selected.");
                return;
            }

            // Show processing overlay
            overlay.style.display = 'flex';
            
            // Fake terminal output logic
            setTimeout(() => loadingText.textContent = "Checking entropy...", 400);
            setTimeout(() => loadingText.textContent = "Comparing YARA signatures...", 800);
            setTimeout(() => loadingText.textContent = "Finalizing report...", 1200);

            // Actually submit the form after 1.5 seconds
            setTimeout(() => {
                scanForm.submit();
            }, 1500);
        });
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if rules is None:
            return "YARA rules failed to load on the server.", 500

        if 'file' not in request.files:
            return "No file part", 400
            
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file", 400

        file_data = file.read()
        matches = rules.match(data=file_data)
        
        match_names = [match.rule for match in matches]

        return render_template_string(HTML_TEMPLATE, result=True, matches=match_names)

    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    # Run locally on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)