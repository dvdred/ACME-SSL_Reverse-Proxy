# ACME-SSL Reverse-Proxy  
Docker Compose stack → automatic SSL (ZeroSSL) + nginx HTTPS reverse-proxy

## 1. What it is
Two containers:  
- **acme-server** – gets and renews ZeroSSL certificates, serves HTTP-01 challenges on :80  
- **reverse-proxy** – nginx terminating TLS on :443 and forwarding traffic to your backend

## 2. Requirements
- Host with docker & docker-compose  
- Domain (or IP!) pointing to the docker host on :80 / :443  
- ZeroSSL API key (free at https://app.zerossl.com/developer)

> ⚠️ **ZeroSSL FREE TIER LIMIT**  
A ZeroSSL “Free” account allows **3 active certificates at the same time**.  
Before the very first run, log in to [https://app.zerossl.com/developer](https://app.zerossl.com/developer) and make sure you have **at least one free slot**; otherwise issuance will fail.

> ⚠️ **Quick host-reachability test**
Port 80 must be open to the Internet before you start the stack, open the firewall and then try:

```bash
# one-liner Python 3 temporary server, on docker host
sudo python3 -m http.server 80 --directory /tmp --bind 0.0.0.0
```

Leave it running, then from outside:

```bash
curl http://<YOUR_PUBLIC_IP>/   # should return a directory listing
```

Stop the server (Ctrl-C) only after you get the response; afterwards start the containers with `docker-compose up -d`.

If the curl test fails, adjust your firewall, NAT/port-forward or cloud security group so that port 80 is reachable; otherwise ZeroSSL will not be able to perform the HTTP-01 challenge and issuance will fail.

## 3. First run
```bash
git clone <repo>
cd <repo>
cp env-sample .env               # edit values
```
Minimal `.env`:
```
PUBLIC_IP=12.13.14.15            # or your domain
ZEROSSL_API_KEY=xxxxxxxxxx
BACKEND1_HOST=192.168.1.100      # where your service lives
BACKEND1_PORT=8580
AUTO_CLEANUP_CERTS=true
```

## 4. Start
```bash
docker compose up -d
```
- http://`<PUBLIC_IP>`/health → OK (challenge server)  
- https://`<PUBLIC_IP>`/health → OK (reverse proxy)

## 5. How it works
1. acme-server creates ZeroSSL account, requests certificate  
2. HTTP-01 challenge served at `/.well-known/acme-challenge/`  
3. certs saved in shared volume `certs/<PUBLIC_IP>/{fullchain,privkey}.pem`  
4. reverse-proxy waits for cert files, then listens on :443 with HTTP/2  
5. cron jobs:  
   – 03:00 daily → attempt cert renewal  
   – 04:00 daily → nginx reload if cert changed

## 6. Updates / rebuild
```bash
docker compose pull
docker compose up -d --build
```
No cert loss (persistent `certs` volume).

## 7. Logs & debug
```bash
docker logs acme-server
docker logs reverse-proxy
docker exec acme-server python3 /scripts/manage-certs.py list
```

## 8. Backup
Copy the `certs` volume or local `./certs` folder.

## 9. Security
- Port 80 used only for challenges; real service is HTTPS only  
- HSTS, CSP, X-Frame-Options headers already set

## 10. Move to another host
1. keep same `PUBLIC_IP` / domain in `.env`  
2. restore `certs` folder  
3. `docker compose up -d`

🙏 Done: zero-touch HTTPS reverse-proxy with auto-renewed SSL certificates.

## Credits

- **Made with ❤️ for the community by** dvdred@gmail.com  
- **License**: GPL3