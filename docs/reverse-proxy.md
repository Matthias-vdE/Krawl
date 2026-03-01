# Example Usage Behind Reverse Proxy

You can configure a reverse proxy so all web requests land on the Krawl page by default, and hide your real content behind a secret hidden url. For example:

```bash
location / {
    proxy_pass https://your-krawl-instance;
    proxy_pass_header Server;
}

location /my-hidden-service {
    proxy_pass https://my-hidden-service;
    proxy_pass_header Server;
}
```

Alternatively, you can create a bunch of different "interesting" looking domains. For example:

- admin.example.com
- portal.example.com
- sso.example.com
- login.example.com
- ...

Additionally, you may configure your reverse proxy to forward all non-existing subdomains (e.g. nonexistent.example.com) to one of these domains so that any crawlers that are guessing domains at random will automatically end up at your Krawl instance.
