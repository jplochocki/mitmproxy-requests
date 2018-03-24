# mitmproxy-requests

MitmProxy 3.x addon for Requests parameters generation


## Requirements

**mitmproxy**, pyperclip, jinja2


## Usage

Use in mitmproxy:

```sh
mitmproxy -s requestsaddon.py ...
```

Save current flow to file:

```sh
: request.file @focus test.py
```

Copy current flow to clipboard:

```sh
: request.clip @focus
```
