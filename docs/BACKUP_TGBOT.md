# Backups and Telegram bot (v0.20.1)

```
echo 'a long passphrase' > /etc/khaymali/backup.pass && chmod 600 /etc/khaymali/backup.pass
khaymali backup run --pass-file /etc/khaymali/backup.pass --keep 14      # default sources: /etc/khaymali, /var/lib/khaymali
khaymali backup list
khaymali backup verify FILE --pass-file ...
khaymali backup restore FILE --to /root/restore --pass-file ...          # review, then copy files into place yourself

khaymali tgbot --token BOT_TOKEN --admin 123456789
```
Keep the passphrase somewhere else too: without it a backup cannot be opened.
