# Real Security Scanning Integration Guide

## 🎯 **Integration Complete!**

Your Attack Surface Discovery application now includes **real security scanning** using industry-standard tools:
- **Subfinder** - Subdomain discovery
- **Naabu** - Port scanning  
- **Nuclei** - Vulnerability scanning

## 🔧 **What Was Added**

### **1. Security Tools Integration**
- `tools/base_scanner.py` - Base scanner class with common functionality
- `tools/subfinder.py` - Subfinder integration for subdomain discovery
- `tools/naabu.py` - Naabu integration for port scanning
- `tools/nuclei.py` - Nuclei integration for vulnerability scanning
- `tools/scanner_manager.py` - Orchestrates all three tools

### **2. Real Scanning Service**
- `services/real_scanning_service.py` - Processes scan results and stores in database
- Automatically creates assets, vulnerabilities, and alerts from scan results
- Maps tool outputs to your application's data models

### **3. API Endpoints**
- `routes/real_scanning.py` - New API endpoints for real scanning
- `/api/scan/status` - Check tool availability
- `/api/scan/test-tools` - Test all tools
- `/api/scan/quick` - Quick scan (1-3 minutes)
- `/api/scan/deep` - Deep scan (10-30 minutes)
- `/api/scan/subdomain` - Subfinder only
- `/api/scan/ports` - Naabu only
- `/api/scan/vulnerabilities` - Nuclei only

### **4. Frontend Interface**
- `templates/real_scanning.html` - Modern scanning interface
- `static/js/real_scanning.js` - Interactive JavaScript functionality
- Integrated with existing dashboard design
- Real-time progress tracking

### **5. Docker Integration**
- Updated `Dockerfile` to install Go and security tools
- Automatic Nuclei template updates on container start
- Tools available in container PATH

## 🚀 **Deployment**

### **Option 1: Simple Deployment (Recommended)**
```bash
# Deploy with real scanning tools
./deploy-simple.sh
```

### **Option 2: Manual Deployment**
```bash
# Stop existing containers
docker-compose down

# Rebuild with security tools
docker-compose build --no-cache

# Deploy
docker-compose up -d
```

## 🌐 **Access Real Scanning**

After deployment, access the new scanning interface:

1. **Login** to your application: http://localhost:8090
2. **Navigate** to "Real Scanning" in the sidebar (marked with "NEW" badge)
3. **Check tool status** to verify all tools are working
4. **Start scanning** your domains!

## 🔍 **Scanning Options**

### **Quick Scan (1-3 minutes)**
- Subdomain discovery (1 minute timeout)
- Top 100 ports
- Critical & High severity vulnerabilities only
- Perfect for regular monitoring

### **Deep Scan (10-30 minutes)**
- Recursive subdomain discovery (5 minutes)
- Top 10,000 ports
- All vulnerability templates
- Comprehensive security assessment

### **Individual Tool Scans**
- **Subfinder**: Domain → Subdomains
- **Naabu**: Hosts → Open ports
- **Nuclei**: URLs → Vulnerabilities

## 📊 **Scan Results**

All scan results are automatically:
- ✅ **Stored in database** as assets, vulnerabilities, and alerts
- ✅ **Displayed in dashboard** with existing data
- ✅ **Categorized by severity** (Critical, High, Medium, Low, Info)
- ✅ **Linked to assets** for easy tracking
- ✅ **Timestamped** for historical analysis

## 🛠️ **Tool Configuration**

### **Subfinder Configuration**
```json
{
  "max_time": 180,        // Scan timeout in seconds
  "recursive": false,     // Enable recursive discovery
  "sources": ["all"]      // Data sources to use
}
```

### **Naabu Configuration**
```json
{
  "top_ports": 1000,      // Number of top ports to scan
  "rate": 1000,           // Packets per second
  "timeout": 5,           // Connection timeout
  "retries": 3            // Number of retries
}
```

### **Nuclei Configuration**
```json
{
  "severity": ["critical", "high"],  // Severity levels
  "rate_limit": 150,                 // Requests per second
  "concurrency": 25,                 // Concurrent requests
  "templates": ["cves/", "vulns/"]   // Template categories
}
```

## 🔧 **Troubleshooting**

### **Tools Not Available**
```bash
# Check if tools are installed
docker-compose exec web which subfinder
docker-compose exec web which naabu
docker-compose exec web which nuclei

# Check tool versions
docker-compose exec web subfinder -version
docker-compose exec web naabu -version
docker-compose exec web nuclei -version
```

### **Scan Failures**
```bash
# Check web container logs
docker-compose logs web

# Test tools manually
docker-compose exec web subfinder -d example.com -silent
docker-compose exec web naabu -host example.com -top-ports 10 -silent
docker-compose exec web nuclei -u http://example.com -t cves/ -silent
```

### **Permission Issues**
```bash
# Check container permissions
docker-compose exec web ls -la /go/bin/

# Rebuild container if needed
docker-compose build --no-cache web
```

## 📈 **Performance Optimization**

### **Quick Scans**
- Use for regular monitoring
- Limit to top 100 ports
- Focus on critical/high vulnerabilities
- Set shorter timeouts

### **Deep Scans**
- Use for comprehensive assessments
- Schedule during off-peak hours
- Monitor resource usage
- Consider rate limiting

### **Resource Management**
```bash
# Monitor container resources
docker stats

# Adjust scan parameters for your server
# Edit scan configurations in the UI
```

## 🔐 **Security Considerations**

### **Network Security**
- Tools make external network requests
- Consider firewall rules for outbound traffic
- Monitor scan targets for compliance

### **Rate Limiting**
- Default rate limits are conservative
- Adjust based on your network capacity
- Respect target server resources

### **Data Privacy**
- Scan results contain sensitive information
- Ensure proper access controls
- Consider data retention policies

## 🎯 **Next Steps**

1. **Test the integration**:
   - Run tool status check
   - Perform a quick scan on a test domain
   - Verify results appear in dashboard

2. **Configure scanning**:
   - Set up regular scanning schedules
   - Customize scan parameters
   - Define alerting rules

3. **Monitor and optimize**:
   - Track scan performance
   - Adjust resource limits
   - Fine-tune scan configurations

## 🆕 **New Features Available**

- ✅ **Real subdomain discovery** with Subfinder
- ✅ **Actual port scanning** with Naabu  
- ✅ **Live vulnerability detection** with Nuclei
- ✅ **Automated asset discovery** and cataloging
- ✅ **Real-time security alerts** based on findings
- ✅ **Integration with existing dashboard** and workflows

## 📞 **Support**

If you encounter issues:

1. **Check logs**: `docker-compose logs web`
2. **Verify tools**: Use the "Test All Tools" button
3. **Review configuration**: Check scan parameters
4. **Monitor resources**: Ensure adequate CPU/memory

---

**🎉 Congratulations!** Your Attack Surface Discovery application now performs **real security scanning** with industry-standard tools. Start discovering your actual attack surface today!
