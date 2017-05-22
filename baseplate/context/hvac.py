from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from . import ContextFactory

import hvac
import requests


class HvacContextFactory(ContextFactory):
    def __init__(self, vault_url, secrets_store, timeout=1):
        self.url = vault_url
        self.secrets = secrets_store
        self.timeout = timeout
        self.session = requests.Session()

    def make_object_for_context(self, name, server_span):
        vault_token = self.secrets.get_vault_token()

        return InstrumentedHvacClient(
            url=self.url,
            token=vault_token,
            timeout=self.timeout,
            session=self.session,
            context_name=name,
            server_span=server_span,
        )


class InstrumentedHvacClient(hvac.Client):
    def __init__(self, url, token, timeout, session, context_name, server_span):
        self.context_name = context_name
        self.server_span = server_span

        super(InstrumentedHvacClient, self).__init__(
            url=url, token=token, timeout=timeout, session=session)

    def _get(self, url, **kwargs):
        return self.__request('get', url, **kwargs)

    def _post(self, url, **kwargs):
        return self.__request('post', url, **kwargs)

    def _put(self, url, **kwargs):
        return self.__request('put', url, **kwargs)

    def _delete(self, url, **kwargs):
        return self.__request('delete', url, **kwargs)

    def __request(self, method, url, **kwargs):
        span_name = "{}.request".format(self.context_name)
        with self.server_span.make_child(span_name) as span:
            span.set_tag("http.method", method)
            span.set_tag("http.url", url)

            response = self._Client__request(
                method=method, url=url, **kwargs)

            # this means we can't get the status code from error responses.
            # that's unfortunate, but hvac doesn't make it easy.
            span.set_tag("http.status_code", response.status_code)
        return response
