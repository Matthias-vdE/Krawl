# Customizing the Wordlist

Edit `wordlists.json` to customize fake data for your use case

```json
{
  "usernames": {
    "prefixes": ["admin", "root", "user"],
    "suffixes": ["_prod", "_dev", "123"]
  },
  "passwords": {
    "prefixes": ["P@ssw0rd", "Admin"],
    "simple": ["test", "password"]
  },
  "directory_listing": {
    "files": ["credentials.txt", "backup.sql"],
    "directories": ["admin/", "backup/"]
  }
}
```

or **values.yaml** in the case of helm chart installation
