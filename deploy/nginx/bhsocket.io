server {
    server_name bhsocket.io www.bhsocket.io;
    root /opt/bhsocket/www;
    index index.html;
    access_log /var/log/nginx/bhsocket.access.log;
    error_log /var/log/nginx/bhsocket.error.log;

    location = /admin {
        return 301 /admin/;
    }

    location = /panel {
        return 301 /panel/;
    }

    location /panel/ {
        proxy_pass http://127.0.0.1:8730;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    location /admin/ {
        proxy_pass http://127.0.0.1:8730/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
        proxy_read_timeout 60s;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8730/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
        proxy_read_timeout 60s;
    }

    location / {
        try_files $uri $uri/ =404;
    }

    listen 127.0.0.1:9443 ssl;
    http2 on;
    ssl_certificate /etc/letsencrypt/live/bhsocket.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/bhsocket.io/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    listen 80;
    listen [::]:80;
    server_name bhsocket.io www.bhsocket.io;
    return 301 https://$host$request_uri;
}
