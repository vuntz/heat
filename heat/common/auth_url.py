#
# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from keystoneclient import discover as ks_discover
from keystoneclient import session
from oslo_config import cfg
from oslo_utils import importutils
from webob import exc

from heat.common.i18n import _
from heat.common import wsgi


class AuthUrlFilter(wsgi.Middleware):

    def __init__(self, app, conf):
        super(AuthUrlFilter, self).__init__(app)
        self.conf = conf
        self.session = session.Session.construct(self._ssl_options())
        self.auth_url = self._get_auth_url()

    def _get_auth_url(self):
        if 'auth_uri' in self.conf:
            return self.conf['auth_uri']
        else:
            # Look for the keystone auth_uri in the configuration. First we
            # check the [clients_keystone] section, and if it is not set we
            # look in [keystone_authtoken]
            if cfg.CONF.clients_keystone.auth_uri:
                discover = ks_discover.Discover(
                    self.session,
                    auth_url=cfg.CONF.clients_keystone.auth_uri)
                return discover.url_for('3.0')
            else:
                # Import auth_token to have keystone_authtoken settings setup.
                auth_token_module = 'keystonemiddleware.auth_token'
                importutils.import_module(auth_token_module)
                return cfg.CONF.keystone_authtoken.auth_uri

    def _validate_auth_url(self, auth_url):
        """Validate auth_url to ensure it can be used."""
        if not auth_url:
            raise exc.HTTPBadRequest(_('Request missing required header '
                                       'X-Auth-Url'))
        allowed = cfg.CONF.auth_password.allowed_auth_uris
        if auth_url not in allowed:
            raise exc.HTTPUnauthorized(_('Header X-Auth-Url "%s" not '
                                         'an allowed endpoint') % auth_url)
        return True

    def process_request(self, req):
        auth_url = self.auth_url
        if cfg.CONF.auth_password.multi_cloud:
            auth_url = req.headers.get('X-Auth-Url')
            self._validate_auth_url(auth_url)

        req.headers['X-Auth-Url'] = auth_url
        return None

    def _ssl_options(self):
        opts = {'cacert': self._get_client_option('ca_file'),
                'insecure': self._get_client_option('insecure'),
                'cert': self._get_client_option('cert_file'),
                'key': self._get_client_option('key_file')}
        return opts

    def _get_client_option(self, option):
        # look for the option in the [clients_keystone] section
        # unknown options raise cfg.NoSuchOptError
        cfg.CONF.import_opt(option, 'heat.common.config',
                            group='clients_keystone')
        v = getattr(cfg.CONF.clients_keystone, option)
        if v is not None:
            return v
        # look for the option in the generic [clients] section
        cfg.CONF.import_opt(option, 'heat.common.config', group='clients')
        return getattr(cfg.CONF.clients, option)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_url_filter(app):
        return AuthUrlFilter(app, conf)
    return auth_url_filter
