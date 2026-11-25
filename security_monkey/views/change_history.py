#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.views.change_history
    :platform: Unix
    :synopsis: REST endpoints for querying the configuration change history
    (diffs, before/after state and operator attribution) of tracked resources.

.. version:: $$VERSION$$
"""
from security_monkey.views import AuthenticatedService
from security_monkey.views import CHANGE_RECORD_FIELDS
from security_monkey.views import ITEM_FIELDS
from security_monkey.datastore import Datastore, Item
from security_monkey import rbac

from flask_restful import marshal, reqparse


class ItemChangeHistory(AuthenticatedService):
    decorators = [
        rbac.allow(["View"], ["GET"])
    ]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ItemChangeHistory, self).__init__()

    def get(self, item_id):
        """
            .. http:get:: /api/1/items/<int:item_id>/changehistory

            Get the time-ordered configuration change history for one
            resource. Each entry contains the structured diff, the full
            before/after configuration snapshots, and the operator the
            change is attributed to.

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/items/144/changehistory?days=90 HTTP/1.1
                Host: example.com
                Accept: application/json

            **Example Response**:

            .. sourcecode:: http

                HTTP/1.1 200 OK
                Vary: Accept
                Content-Type: application/json

                {
                    "auth": {"authenticated": true, "user": "user@example.com"},
                    "item": {"id": 144, "name": "Example", "region": "us-east-1"},
                    "count": 1,
                    "items": [
                        {
                            "id": 12,
                            "item_id": 144,
                            "revision_id": 223757,
                            "previous_revision_id": 223700,
                            "change_type": "updated",
                            "diff": {"added": {}, "removed": {},
                                     "changed": {"policy": {"old": {}, "new": {}}}},
                            "old_config": {},
                            "new_config": {},
                            "actor": "arn:aws:iam::012345678910:user/alice",
                            "actor_source": "cloudtrail",
                            "date_created": "2014-06-19 20:54:12.962951"
                        }
                    ]
                }

            :statuscode 200: no error
            :statuscode 404: item not found
            :statuscode 401: Authentication Error. Please Login.
        """
        self.reqparse.add_argument('days', type=int, default=None, location='args')
        args = self.reqparse.parse_args()

        item = Item.query.filter(Item.id == item_id).first()
        if not item:
            return {'message': 'Item with id {} not found.'.format(item_id)}, 404

        datastore = Datastore()
        records = datastore.get_change_history(item_id=item_id, days=args.get('days'))

        result = {
            'auth': self.auth_dict,
            'item': marshal(item.__dict__, ITEM_FIELDS),
            'count': len(records),
            'items': [marshal(record, CHANGE_RECORD_FIELDS) for record in records]
        }
        return result, 200


class ChangeHistoryList(AuthenticatedService):
    decorators = [
        rbac.allow(["View"], ["GET"])
    ]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ChangeHistoryList, self).__init__()

    def get(self):
        """
            .. http:get:: /api/1/changehistory

            Query configuration change records across resources, filtered by
            technology, account, region and/or name. Defaults to the
            configured retention window (90 days).

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/changehistory?technology=s3&account=prod&days=90 HTTP/1.1
                Host: example.com
                Accept: application/json

            :statuscode 200: no error
            :statuscode 401: Authentication Error. Please Login.
        """
        self.reqparse.add_argument('technology', type=str, default=None, location='args')
        self.reqparse.add_argument('account', type=str, default=None, location='args')
        self.reqparse.add_argument('region', type=str, default=None, location='args')
        self.reqparse.add_argument('name', type=str, default=None, location='args')
        self.reqparse.add_argument('days', type=int, default=None, location='args')
        args = self.reqparse.parse_args()

        datastore = Datastore()
        records = datastore.get_change_history(
            ctype=args.get('technology'),
            account=args.get('account'),
            region=args.get('region'),
            name=args.get('name'),
            days=args.get('days'))

        items_marshaled = []
        for record in records:
            record_marshaled = marshal(record, CHANGE_RECORD_FIELDS)
            record_marshaled = dict(
                list(record_marshaled.items()) +
                list({'technology': record.item.technology.name}.items()) +
                list({'account': record.item.account.name}.items()) +
                list({'region': record.item.region}.items()) +
                list({'name': record.item.name}.items()))
            items_marshaled.append(record_marshaled)

        return {
            'auth': self.auth_dict,
            'count': len(items_marshaled),
            'items': items_marshaled
        }, 200
