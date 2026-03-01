# Enable Database Dump Job for Backups

To enable the database dump job, set the following variables (*config file example*)

```yaml
backups:
    path: "backups" # where backup will be saved
    cron: "*/30 * * * *" # frequency of the cronjob
    enabled: true
```
