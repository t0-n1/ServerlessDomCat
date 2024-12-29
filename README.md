# ServerlessDomCat

## Description

**Serverless Domain Categorization** is a tool that identifies websites with misconfigured `default_server` settings (using nginx terminology). This misconfiguration can be exploited to enable domain categorization by simply pointing your domain to the IP addresses of these websites through a web proxy like Cloudflare CDN, eliminating the need to host, manage, or develop any web server.

## How It Works

1. The tool scans for websites with incorrect `default_server` configurations.
2. By pointing your domain to the IP address of one of these websites through a web proxy, category providers may mistakenly categorize your domain as the original site.  
3. This process allows for passive domain categorization without actively running or managing any infrastructure.  

## Why Use This Tool?  

- **Serverless Approach** – No need to deploy or manage web servers.
- **Cost-Effective** – No hosting fees, maintenance, or operational overhead.
- **Automated Categorization** – Leverage existing domain categorizations from misconfigured servers.
- **Time-Saving** – Point and wait, with minimal manual intervention required.

## Installation  

```bash
git clone https://github.com/t0-n1/ServerlessDomCat.git
cd ServerlessDomCat

sudo docker build -t serverlessdomcat .

xhost +local:docker
IPQS='Your IPQS API Key'
SHODAN='Your Shodan API Key'
sudo docker run -e DISPLAY=$DISPLAY -e IPQS=$IPQS -e SHODAN=$SHODAN -v /tmp/.X11-unix:/tmp/.X11-unix -v ./results:/app/results -it --rm serverlessdomcat

google-chrome results/candidates.html
jq 'del(.. | .screenshot?)' results/candidates.json
```

## Verifying Results  

You can double-check the domain categorization tool's results using the following services:
- [APIVoid URL Reputation Check](https://www.apivoid.com/tools/url-reputation-check/)  
- [Bluecoat Site Review](https://sitereview.bluecoat.com/#/lookup-result/)  
- [Cloudflare Radar](https://radar.cloudflare.com/domains/)  
- [FortiGuard Web Filter](https://www.fortiguard.com/webfilter)  
- [Norton SafeWeb](https://safeweb.norton.com/)  
- [Palo Alto Networks URL Filtering](https://urlfiltering.paloaltonetworks.com/query/)  
- [Talos Intelligence](https://www.talosintelligence.com/reputation_center/)  
