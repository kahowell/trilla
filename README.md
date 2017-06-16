# trilla
Sync Trello cards from Bugzilla bugs!

* [Requirements](https://github.com/vritant/trilla/blob/master/docs/requirements.md)
* [Implementation Design](https://github.com/vritant/trilla/blob/master/docs/Implementation_design.md)
* [Rules Design](https://github.com/vritant/trilla/blob/master/docs/Rules_design.md)

# Example config

```yaml
---
default_profile: work

profiles:
  work:
    github:
      token: [REDACTED]
    trello:
      api_key: [REDACTED]
      oauth_token: [REDACTED]
      oauth_token_secret: [REDACTED]
    bugzilla:
    target_board: [REDACTED BOARD ID]
    email_trello_user_map:
      [REDACTED EMAIL]: [REDACTED TRELLO USERNAME]
```
