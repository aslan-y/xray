<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <h1>Xray - Your Network Toolkit</h1>
        <img src="https://via.placeholder.com/800x200.png?text=Xray+-+Your+Network+Toolkit" alt="Xray Banner">
    </header>
    <main>
        <section id="overview">
            <h2>Overview</h2>
            <p>Xray is a comprehensive network toolkit designed to provide various network utilities such as port scanning, traceroute, HTTP header grabbing, ping, whois lookup, nslookup, and subnet calculation. This tool is built with Python and leverages several libraries to offer a robust and user-friendly experience.</p>
        </section>
        <section id="features">
            <h2>Features</h2>
            <ul>
                <li><strong>Port Scanner</strong>: Scan common ports on a target IP or domain.</li>
                <li><strong>Traceroute</strong>: Trace the route packets take to a network host.</li>
                <li><strong>HTTP Header Grabber</strong>: Retrieve HTTP headers from a target IP.</li>
                <li><strong>Ping</strong>: Check the reachability of a host.</li>
                <li><strong>Whois Lookup</strong>: Get detailed information about a domain or IP.</li>
                <li><strong>Nslookup</strong>: Query DNS records for a domain.</li>
                <li><strong>Subnet Calculator</strong>: Calculate network details from an IP and subnet mask.</li>
            </ul>
        </section>
        <section id="installation">
            <h2>Installation</h2>
            <h3>Prerequisites</h3>
            <p>Ensure you have Python 3.7+ installed on your system. You can download it from <a href="https://www.python.org/downloads/">python.org</a>.</p>
            <h3>Clone the Repository</h3>
            <pre><code>git clone https://github.com/CyberGameX/xray-network-toolkit.git
cd xray-network-toolkit</code></pre>
            <h3>Install Dependencies</h3>
            <pre><code>pip install -r requirements.txt</code></pre>
            <h3>Set Environment Variables</h3>
            <p>Set the <code>IPINFO_ACCESS_TOKEN</code> environment variable with your Ipinfo access token:</p>
            <h4>Windows (CMD)</h4>
            <pre><code>setx IPINFO_ACCESS_TOKEN "your_ipinfo_access_token"</code></pre>
            <h4>Windows (PowerShell)</h4>
            <pre><code>$env:IPINFO_ACCESS_TOKEN="your_ipinfo_access_token"</code></pre>
        </section>
        <section id="usage">
            <h2>Usage</h2>
            <p>Run the main script to start the toolkit:</p>
            <pre><code>python main.py</code></pre>
            <p>Follow the on-screen instructions to navigate through the menu and use the various network utilities.</p>
        </section>
        <section id="screenshots">
            <h2>Screenshots</h2>
            <img src="https://github.com/CyberGameX/xray-network-toolkit/blob/main/xray_main_menu.png?raw=true?" alt="Main Menu">
            <img src="https://github.com/CyberGameX/xray-network-toolkit/blob/main/portscanner.png?raw=true?" alt="Port Scanner">
        </section>
        <section id="contributing">
            <h2>Contributing</h2>
            <p>We welcome contributions! Please read our <a href="CONTRIBUTING.md">Contributing Guidelines</a> for more details.</p>
        </section>
        <section id="license">
            <h2>License</h2>
            <p>This project is licensed under the GPL License. See the <a href="LICENSE">LICENSE</a> file for details.</p>
        </section>
        <section id="disclaimer">
            <h2>Disclaimer</h2>
            <p>This program is intended for educational purposes only. Do not use it for illegal activities. The creator of this program is not responsible for any misuse of information provided by this program.</p>
        </section>
    </main>
    <footer>
        <p>Developed with ❤️ by <a href="https://github.com/CyberGameX">CyberSeC</a></p>
    </footer>
</body>
</html>
