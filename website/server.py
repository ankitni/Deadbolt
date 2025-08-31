#!/usr/bin/env python3
"""
Simple HTTP server for Deadbolt website
Serves the static website files locally
"""

import http.server
import socketserver
import os
import webbrowser
import sys
from pathlib import Path

def start_server(port=8080):
    """Start the web server for the Deadbolt website"""
    
    # Change to website directory
    website_dir = Path(__file__).parent
    os.chdir(website_dir)
    
    # Create server
    handler = http.server.SimpleHTTPRequestHandler
    
    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            print("=" * 60)
            print("🛡️  DEADBOLT 5 - CYBERSECURITY WEBSITE")
            print("=" * 60)
            print(f"🚀 Server starting on port {port}")
            print(f"🌐 Website URL: http://localhost:{port}")
            print(f"📂 Serving files from: {website_dir}")
            print("=" * 60)
            print()
            print("🔥 Features:")
            print("   ✅ 3D Interactive Shield Animation")
            print("   ✅ Cyberpunk Particle System")
            print("   ✅ Live Ransomware Simulation Demo")
            print("   ✅ Real-time Security Dashboard")
            print("   ✅ Responsive Mobile Design")
            print()
            print("🎯 Navigation:")
            print("   • Home - Hero section with 3D animations")
            print("   • Features - Advanced defense capabilities")
            print("   • Demo - Interactive threat simulation")
            print("   • Stats - Real-time security dashboard")
            print("   • Download - Get Deadbolt 5")
            print()
            print("💡 Press Ctrl+C to stop the server")
            print("=" * 60)
            
            # Try to open browser automatically
            try:
                webbrowser.open(f'http://localhost:{port}')
                print("🌐 Opening website in your default browser...")
            except:
                print("📌 Manually open: http://localhost:{port} in your browser")
            
            print()
            print("🛡️  Server is running... Protect the web!")
            
            # Start server
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        print("✅ Deadbolt website server shut down successfully")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ Port {port} is already in use!")
            print(f"💡 Try a different port: python server.py --port 8081")
        else:
            print(f"❌ Server error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    """Main function with command line argument parsing"""
    port = 8080
    
    # Simple command line argument parsing
    if len(sys.argv) > 1:
        if "--port" in sys.argv:
            try:
                port_index = sys.argv.index("--port") + 1
                if port_index < len(sys.argv):
                    port = int(sys.argv[port_index])
            except (ValueError, IndexError):
                print("❌ Invalid port number. Using default port 8080.")
        elif "--help" in sys.argv or "-h" in sys.argv:
            print("Deadbolt 5 Website Server")
            print("Usage: python server.py [--port PORT]")
            print("       python server.py --help")
            print()
            print("Options:")
            print("  --port PORT    Set server port (default: 8080)")
            print("  --help, -h     Show this help message")
            return
    
    start_server(port)

if __name__ == "__main__":
    main()