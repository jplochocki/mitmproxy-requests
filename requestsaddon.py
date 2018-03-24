from mitmproxy import ctx, command, flow, types
from mitmproxy.utils.strutils import always_str
import typing
import pyperclip
from jinja2 import Environment
import re
from urllib.parse import urlparse, urlunparse, parse_qsl
import base64


REQUESTS_TEMPLATE = '''import requests

{%- if using_base64 -%}{{ '\n' }}import base64{%- endif -%}

{{ '\n\n\n' }}


{%- if params -%}
    params = {{- ' {\n' -}}
        {%- for k, v in params -%}
            {%- set suffix = ',' -%}
            {%- if loop.last -%}{%- set suffix = '' -%}{%- endif -%}

            {{ write_kv_line(k, v, '    ', suffix) }}
        {%- endfor -%}
    {{- '}\n\n' -}}
{%- endif -%}


{%- if headers -%}
    headers = {{- ' {\n' -}}
        {%- for k, v in headers -%}
            {%- set suffix = ',' -%}
            {%- if loop.last -%}{%- set suffix = '' -%}{%- endif -%}

            {{ write_kv_line(k|prepare_header_name, v, '    ', suffix) }}
        {%- endfor -%}
    {{- '}\n\n' -}}
{%- endif -%}


{%- if cookies -%}
    cookies = {{- ' {\n' -}}
        {%- for k, v in cookies -%}
            {%- set suffix = ',' -%}
            {%- if loop.last -%}{%- set suffix = '' -%}{%- endif -%}

            {{ write_kv_line(k, v, '    ', suffix) }}
        {%- endfor -%}
    {{- '}\n\n' -}}
{%- endif -%}


{%- if data -%}
    data = {{- ' {\n' -}}
        {%- for k, v in data -%}
            {%- set suffix = ',' -%}
            {%- if loop.last -%}
                {%- set suffix = '' -%}
            {%- endif -%}

            {%- set base64_ = False -%}
            {%- if isinstance(v, bytes) -%}
                {%- set base64_ = True -%}
                {%- set v = v.decode() -%}
            {%- endif -%}

            {{ write_kv_line(k, v, '    ', suffix, base64_=base64_) }}
        {%- endfor -%}
    {{- '}\n\n' -}}
{%- endif -%}


requests.{{ method|lower }}(
    '{{ url }}'
    {%-if params -%}{{ ',\n    ' }}params=params{%- endif -%}
    {%- if data -%}{{ ',\n    ' }}data=data{%- endif -%}
    {%- if headers -%}{{ ',\n    ' }}headers=headers{%- endif -%}
    {%- if cookies -%}{{ ',\n    ' }}cookies=cookies{%- endif -%})
'''


def _prepare_header_name(name):
    r = ''
    for s in re.split(r'(\W+)', name):
        if len(s):
            r += s[0].upper() + s[1:]
    return r


def write_kv_line(k, v, prefix='    ', suffix=',', line_max=80, base64_=False):
    k = re.sub(r'\'', '\\\'', k)
    v = re.sub(r'\'', '\\\'', v)

    base64_ = 'base64.b64decode(' if base64_ else ''
    suffix = ')' + suffix if base64_ else suffix

    r = "{}'{}': {}'{}'{}\n".format(prefix, k, base64_, v, suffix)

    if line_max and len(r) > line_max:
        max_len = line_max - len(prefix) - 3

        r = "{}'{}': {}'{}'\n".format(
            prefix, k, base64_,
            v[:max_len - len(prefix) - len(k) - len(base64_)])
        v = v[max_len - len(prefix) - len(k) - len(base64_):]

        while True:
            if len(v) < max_len:
                r += "{}'{}'{}\n".format(prefix, v, suffix)
                break
            r += "{}'{}'\n".format(prefix, v[:max_len])
            v = v[max_len:]
        return r

    return r


class RequestsAddon:

    """
    Copy commands for requests parameters.
    """

    def _prepare_flow_data(self, flow):
        headers = [(k, v) for k,  v in flow.request.headers.items() if
                   not k.startswith(':') and k != 'cookie']
        cookies = flow.request.cookies.items()

        url = urlparse(flow.request.url)
        params = parse_qsl(url.query)
        url = urlunparse((url[0], url[1], url[2], url[3], '', url[5]))

        using_base64 = False
        data = [(always_str(k), always_str(v))
                for k, v in flow.request.urlencoded_form.items()]

        for k, v in flow.request.multipart_form.items():
            try:
                data.append((always_str(k), always_str(v)))
            except:
                using_base64 = True
                data.append((always_str(k), base64.b64encode(v)))

        env = Environment()
        env.filters['prepare_header_name'] = _prepare_header_name
        env.globals.update({
            'isinstance': isinstance,
            'bytes': bytes,
            'write_kv_line': write_kv_line
        })
        tp = env.from_string(REQUESTS_TEMPLATE)

        return tp.render({
            'method': flow.request.method,
            'url': url,
            'params': params,
            'data': data,
            'using_base64': using_base64,
            'headers': headers,
            'cookies': cookies
        })

    @command.command('requests.clip')
    def req_clip(
            self,
            flows: typing.Sequence[flow.Flow]) -> None:  # noqa
        """
        Copy requests parameters to clipboard.
        """
        r = ''
        for f in flows:
            r += self._prepare_flow_data(f)
        pyperclip.copy(r)
        ctx.log.alert('{} bytes copied to clipboard'.format(len(r)))

    @command.command('requests.file')
    def req_file(
            self,
            flows: typing.Sequence[flow.Flow],
            fl: types.Path) -> None:  # noqa
        """
        Copy requests parameters to clipboard.
        """
        r = ''
        for f in flows:
            r += self._prepare_flow_data(f)
        with open(fl, 'a') as f:
            f.write(r)

        ctx.log.alert('{} bytes saved to file'.format(len(r)))


addons = [
    RequestsAddon()
]
