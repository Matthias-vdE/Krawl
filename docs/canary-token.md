# Customizing the Canary Token

To create a custom canary token, visit https://canarytokens.org

and generate a "Web bug" canary token.

This optional token is triggered when a crawler fully traverses the webpage until it reaches 0. At that point, a URL is returned. When this URL is requested, it sends an alert to the user via email, including the visitor's IP address and user agent.


To enable this feature, set the canary token URL [using the environment variable](../README.md#configuration-via-enviromental-variables) `KRAWL_CANARY_TOKEN_URL`.
