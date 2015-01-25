# Copyright 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo.utils import strutils
import six.moves.urllib.parse as urlparse
import webob
import httplib
import sys
import json
from nova import db
from nova.api.openstack.compute.schemas.v3 import quota_sets
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api import validation
import nova.context
from nova import exception
from nova.i18n import _
from nova import objects
from nova import quota
#import keystoneclient.middleware.auth_token as auth_token
#from keystoneclient.middleware import auth_token
#KEYSTONE_CONF = auth_token.CONF
ALIAS = "os-quota-sets"
QUOTAS = quota.QUOTAS
authorize_root_update = extensions.extension_authorizer('compute',
                                                   'v3:%s:root:update' % ALIAS)
authorize_update = extensions.extension_authorizer('compute',
                                                   'v3:%s:update' % ALIAS)
authorize_show = extensions.extension_authorizer('compute',
                                                 'v3:%s:show' % ALIAS)
authorize_root_delete = extensions.extension_authorizer('compute',
                                                   'v3:%s:root:delete' % ALIAS)
authorize_delete = extensions.extension_authorizer('compute',
                                                   'v3:%s:delete' % ALIAS)
authorize_detail = extensions.extension_authorizer('compute',
                                                   'v3:%s:detail' % ALIAS)


class QuotaSetsController(wsgi.Controller):

    def _format_quota_set(self, project_id, quota_set):
        """Convert the quota object to a result dict."""
        quota_set.update(id=str(project_id))
        return dict(quota_set=quota_set)

    def _validate_quota_limit(self, resource, limit, minimum, maximum):
        # NOTE: -1 is a flag value for unlimited
       
        if limit < -1:
            msg = (_("Quota limit %(limit)s for %(resource)s "
                     "must be -1 or greater.") %
                   {'limit': limit, 'resource': resource})
            raise webob.exc.HTTPBadRequest(explanation=msg)

        def conv_inf(value):
            return float("inf") if value == -1 else value

        if conv_inf(limit) < conv_inf(minimum):
            msg = (_("Quota limit %(limit)s for %(resource)s must "
                     "be greater than or equal to already used and "
                     "reserved %(minimum)s.") %
                   {'limit': limit, 'resource': resource, 'minimum': minimum})
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if conv_inf(limit) > conv_inf(maximum):
            msg = (_("Quota limit %(limit)s for %(resource)s must be "
                     "less than or equal to %(maximum)s.") %
                   {'limit': limit, 'resource': resource, 'maximum': maximum})
            raise webob.exc.HTTPBadRequest(explanation=msg)

    def _get_quotas(self, context, id, user_id=None, usages=False):
        if user_id:
            values = QUOTAS.get_user_quotas(context, id, user_id,
                                            usages=usages)
        else:
            values = QUOTAS.get_project_quotas(context, id, usages=usages)
        if usages:
            return values
        else:
            return dict((k, v['limit']) for k, v in values.items())

    def _get_parent_id(self,headers,project_id):
        params = {}
        auth_url = '/%s/%s/%s' % ("v3","projects",project_id)
        #auth_host = KEYSTONE_CONF.keystone_authtoken.auth_host
        #auth_port = int(KEYSTONE_CONF.keystone_authtoken.auth_port)
        auth_host = "127.0.0.1"
        auth_port = "35357"
        auth_server = '%s:%s' % (auth_host,auth_port)

        """ The keytsone output for the following url is used for
        checking whether the given project is a root project or not """

        auth_url = '/%s/%s/%s' % ("v3","projects",project_id)
        conn = httplib.HTTPConnection(auth_server)
        conn.request("GET", auth_url, json.dumps(params), headers=headers)
        response = conn.getresponse()
        data = response.read()
        data = json.loads(data)
        conn.close()
        parent_id = None
        if not "project" in data:
            raise webob.exc.HTTPForbidden()
        try:
            parent_id = data["project"]["parent_id"]
        except:
            pass
        return parent_id
    
    def _get_immediate_child_list(self,headers,parent_id):
        params = {}
        child_list = []
        #auth_host = KEYSTONE_CONF.keystone_authtoken.auth_host
        #auth_port = int(KEYSTONE_CONF.keystone_authtoken.auth_port)
        auth_host = "127.0.0.1"
        auth_port = "35357"
        auth_server = '%s:%s' % (auth_host,auth_port)

        """ The keytsone output for the following url is used for
        finding the subtree under the project """

        auth_url = '/%s/%s/%s?%s' % ("v3","projects",parent_id,"subtree")
        conn = httplib.HTTPConnection(auth_server)
        conn.request("GET", auth_url, json.dumps(params), headers=headers)
        response = conn.getresponse()
        data = response.read()
        data = json.loads(data)
        conn.close()
        subtree = []
        try:
            subtree = data["project"]["subtree"]
        except:
            pass
        for item in subtree:
            project_info = item["project"]
            try:
                if project_info["parent_id"] == parent_id:
                    child_list.append(project_info["id"])
            except:
                pass
        return child_list

    def _delete_project_quota(self, req, id,body):
        context = req.environ['nova.context']
        # id is made equivalent to project_id for better readability
        project_id = id
        child_list = []
        parent_id = None
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                headers = {"X-Auth-Token": token,
                           "Content-type": "application/json",
                           "Accept": "text/json"}

                parent_id = self._get_parent_id ( headers , project_id )
                target = {"project_id":parent_id}
                try:
                    if parent_id:
                        authorize_delete(context,target = target)
                        nova.context.authorize_root_or_parent_project_context(context,parent_id)
                    else:
                        authorize_root_delete(context)
                        nova.context.authorize_root_or_parent_project_context(context,project_id)
                except exception.Forbidden:
                    raise webob.exc.HTTPForbidden()
                
                if parent_id :
                    child_list = self._get_immediate_child_list( headers , parent_id )
                else:
                    child_list = self._get_immediate_child_list( headers , project_id )

        if parent_id is not None:
            if id not in child_list:
                raise exception.InvalidParent(parent_id=parent_id,project_id=project_id)
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]

        quota_set = body['quota_set']
        force_update = strutils.bool_from_string(quota_set.get('force',
                                                               'False'))

        try:
            settable_quotas = QUOTAS.get_settable_quotas(context, project_id,
                                                         parent_id,user_id=user_id)
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()

        p = body['quota_set']
        for key, value in body['quota_set'].iteritems():
            if key == 'force' or (not value and value != 0):
                continue
            # validate whether already used and reserved exceeds the new
            # quota, this check will be ignored if admin want to force
            # update
            value = int(value)
            if not force_update:
                minimum = settable_quotas[key]['minimum']
                maximum = settable_quotas[key]['maximum']
                self._validate_quota_limit(key, value, minimum, maximum)
            try:
                objects.Quotas.create_limit(context, project_id,
                                            key, value, user_id=user_id)
            except exception.QuotaExists:
                objects.Quotas.update_limit(context, project_id,
                                            key, value, user_id=user_id)
            except exception.AdminRequired:
                raise webob.exc.HTTPForbidden()

            if parent_id:
                db.quota_allocated_update(context, parent_id,child_list)

    @extensions.expected_errors(403)
    def show(self, req, id):
        context = req.environ['nova.context']
        """ id is made equivalent to project_id for better readability"""
        project_id=id
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        parent_id=None
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                headers = {"X-Auth-Token": token,
                           "Content-type": "application/json",
                           "Accept": "text/json"}
                parent_id = self._get_parent_id(headers,project_id)
        try:
            if user_id:
                authorize_show(context)
                nova.context.authorize_project_context(context, id )
            else:
                if parent_id:
                    if context.project_id ==parent_id:
                        target = {"project_id":parent_id}
                        authorize_show(context,target)
                        nova.context.authorize_project_context(context,parent_id)
                    else:
                        target = {"project_id":project_id}
                        authorize_show(context,target)
                        nova.context.authorize_project_context(context,project_id)
                else:
                    nova.context.authorize_project_context(context,project_id)
            return self._format_quota_set(id,
                    self._get_quotas(context, id, user_id=user_id))
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()

    @extensions.expected_errors(403)
    def detail(self, req, id):
        context = req.environ['nova.context']
        authorize_detail(context)
        user_id = req.GET.get('user_id', None)
        try:
            nova.context.authorize_project_context(context, id)
            return self._format_quota_set(id, self._get_quotas(context, id,
                                                               user_id=user_id,
                                                               usages=True))
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()

    @extensions.expected_errors((400, 403))
    @validation.schema(quota_sets.update)
    def update(self, req, id, body):
        context = req.environ['nova.context']
        # id is made equivalent to project_id for better readability
        project_id = id
        child_list = []
        parent_id = None
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                headers = {"X-Auth-Token": token,
                           "Content-type": "application/json",
                           "Accept": "text/json"}
                parent_id = self._get_parent_id(headers,project_id)                
                target = {"project_id":parent_id}
                try:
                    if user_id:
                        authorize_update(context)
                        nova.context.authorize_project_context(context, id )
                    else:
                        if parent_id:
                            authorize_update(context,target = target)
                            nova.context.authorize_root_or_parent_project_context(context,parent_id)
                        else:
                            authorize_root_update(context)
                            nova.context.authorize_root_or_parent_project_context(context,project_id)
                except exception.Forbidden:
                    raise webob.exc.HTTPForbidden()
                
                if parent_id :
                    child_list = self._get_immediate_child_list( headers , parent_id )
                else:
                    child_list = self._get_immediate_child_list( headers , project_id )

        if parent_id is not None:
            if id not in child_list:
                raise exception.InvalidParent(parent_id=parent_id,project_id=project_id)

        ################
        quota_set = body['quota_set']
        force_update = strutils.bool_from_string(quota_set.get('force',
                                                               'False'))

        try:
            settable_quotas = QUOTAS.get_settable_quotas(context, project_id,
                                                         parent_id,user_id=user_id)
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()
        for key, value in body['quota_set'].iteritems():
            if key == 'force' or (not value and value != 0):
                continue
            # validate whether already used and reserved exceeds the new
            # quota, this check will be ignored if admin want to force
            # update
            value = int(value)
            if not force_update:
                minimum = settable_quotas[key]['minimum']
                maximum = settable_quotas[key]['maximum']
                self._validate_quota_limit(key, value, minimum, maximum)
            try:
                objects.Quotas.create_limit(context, project_id,
                                      key, value,user_id=user_id)
            except exception.QuotaExists:
                objects.Quotas.update_limit(context, project_id,
                                      key, value, user_id=user_id)
            if parent_id:
                db.quota_allocated_update(context, parent_id,child_list)
        return self._format_quota_set(id, self._get_quotas(context, id,
                                                           user_id=user_id))

    @extensions.expected_errors(())
    def defaults(self, req, id):
        context = req.environ['nova.context']
        authorize_show(context)
        values = QUOTAS.get_defaults(context)
        return self._format_quota_set(id, values)

    # TODO(oomichi): Here should be 204(No Content) instead of 202 by v2.1
    # +microversions because the resource quota-set has been deleted completely
    # when returning a response.
    @extensions.expected_errors(403)
    @wsgi.response(202)
    def delete(self, req, id):
        context = req.environ['nova.context']
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        body={"quota_set":{"instances":"0",
                              "cores":"0",
                              "ram":"0", 
                              "floating_ips":"0", 
                              "fixed_ips":"0", 
                              "metadata_items":"0", 
                              "injected_files":"0", 
                              "injected_file_content_bytes":"0",
                              "injected_file_path_bytes":"0", 
                              "security_groups":"0", 
                              "security_group_rules":"0", 
                              "server_groups":"0",
                              "server_group_members":"0",
                              "key_pairs":"0" }}
        try:
            if user_id:
                authorize_delete(context)
                nova.context.authorize_project_context(context, id )
                QUOTAS.destroy_all_by_project_and_user(context,
                                                       id, user_id)
            else:
                self._delete_project_quota(req,id,body)

        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()


class QuotaSets(extensions.V3APIExtensionBase):
    """Quotas management support."""

    name = "Quotas"
    alias = ALIAS
    version = 1

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension(ALIAS,
                                            QuotaSetsController(),
                                            member_actions={'defaults': 'GET',
                                                            'detail': 'GET'})
        resources.append(res)

        return resources

    def get_controller_extensions(self):
        return []
