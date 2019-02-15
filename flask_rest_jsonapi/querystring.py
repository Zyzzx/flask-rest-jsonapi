# -*- coding: utf-8 -*-

"""Helper to deal with querystring parameters according to jsonapi specification"""

import json
import re

from flask import current_app

from flask_rest_jsonapi.exceptions import BadRequest, InvalidFilters, InvalidSort, InvalidField, InvalidInclude
from flask_rest_jsonapi.schema import get_model_field, get_relationships, get_schema_from_type

import fiql_parser

from urllib.parse import quote as uriquote

class QueryStringManager(object):
    """Querystring parser according to jsonapi reference"""

    MANAGED_KEYS = (
        'filter',
        'xfilter',
        'page',
        'page_number',
        'page_size',
        'fields',
        'sort',
        'include',
        'q'
    )

    def __init__(self, querystring, schema):
        """Initialization instance

        :param dict querystring: query string dict from request.args
        """
        if not isinstance(querystring, dict):
            raise ValueError('QueryStringManager require a dict-like object querystring parameter')

        self.qs = querystring
        self.schema = schema

    def _get_key_values(self, name):
        """Return a dict containing key / values items for a given key, used for items like filters, page, etc.

        :param str name: name of the querystring parameter
        :return dict: a dict of key / values items
        """
        results = {}

        for key, value in self.qs.items():
            try:
                if not key.startswith(name):
                    continue

                key_start = key.index('[') + 1
                key_end = key.index(']')
                item_key = key[key_start:key_end]

                if ',' in value:
                    item_value = value.split(',')
                else:
                    item_value = value
                results.update({item_key: item_value})
            except Exception:
                raise BadRequest("Parse error", source={'parameter': key})

        return results

    @property
    def querystring(self):
        """Return original querystring but containing only managed keys

        :return dict: dict of managed querystring parameter
        """
        return {key: value for (key, value) in self.qs.items() if key.startswith(self.MANAGED_KEYS)}

    @property
    def filters(self):
        """Return filters from query string.
           TODO: Make plugable
        :return list: filter information
        """
        filters = self.qs.get('filter')
        xfilter = self.qs.get('xfilter')
        try:
            if filters is not None:
                decoded = decode_fiql_query(filters)
                filters = transform_fiql_query(decoded.to_python(),self.schema.Meta.type_)
            elif xfilter is not None:
                filters = json.loads(xfilter)
        except (ValueError, TypeError) as e:
            raise InvalidFilters("Parse error", str(e))

        return filters

    @property
    def pagination(self):
        """Return all page parameters as a dict.

        :return dict: a dict of pagination information

        To allow multiples strategies, all parameters starting with `page` will be included. e.g::

            {
                "number": '25',
                "size": '150',
            }

        Example with number strategy::

            >>> query_string = {'page[number]': '25', 'page[size]': '10'}
            >>> parsed_query.pagination
            {'number': '25', 'size': '10'}
        """
        # check values type
        result = {}
        page_number = self.qs.get('page_number')
        page_size = self.qs.get('page_size')
        try:
            if page_size is not None:
                result['size'] = int(page_size)
            if page_number is not None:
                result['number'] = int(page_number)
        except ValueError:
            raise BadRequest("Parse error", source={'parameter': 'page_size/page_number'})
        if result:
            return result

        result = self._get_key_values('page')
        for key, value in result.items():
            if key not in ('number', 'size'):
                raise BadRequest("{} is not a valid parameter of pagination".format(key), source={'parameter': 'page'})
            try:
                int(value)
            except ValueError:
                raise BadRequest("Parse error", source={'parameter': 'page[{}]'.format(key)})

        if current_app.config.get('ALLOW_DISABLE_PAGINATION', True) is False and int(result.get('size', 1)) == 0:
            raise BadRequest("You are not allowed to disable pagination", source={'parameter': 'page[size]'})

        if current_app.config.get('MAX_PAGE_SIZE') is not None and 'size' in result:
            if int(result['size']) > current_app.config['MAX_PAGE_SIZE']:
                raise BadRequest("Maximum page size is {}".format(current_app.config['MAX_PAGE_SIZE']),
                                 source={'parameter': 'page[size]'})

        return result

    @property
    def fields(self):
        """Return fields wanted by client.

        :return dict: a dict of sparse fieldsets information

        Return value will be a dict containing all fields by resource, for example::

            {
                "user": ['name', 'email'],
            }

        """
        result = self._get_key_values('fields')
        for key, value in result.items():
            if not isinstance(value, list):
                result[key] = [value]

        for key, value in result.items():
            schema = get_schema_from_type(key)
            for obj in value:
                if obj not in schema._declared_fields:
                    raise InvalidField("{} has no attribute {}".format(schema.__name__, obj))

        return result

    @property
    def sorting(self):
        """Return fields to sort by including sort name for SQLAlchemy and row
        sort parameter for other ORMs

        :return list: a list of sorting information

        Example of return value::

            [
                {'field': 'created_at', 'order': 'desc'},
            ]

        """
        if self.qs.get('sort'):
            type_ = self.schema.Meta.type_
            sorting_results = []
            for sort_field in self.qs['sort'].split(','):
                field = sort_field.replace('-', '')
                if field.startswith(type_ + '.'):
                    # Remove redundant type on the sort field if it is there
                    field = re.sub('^' + type_ + r'\.','',field)
                if field not in self.schema._declared_fields:
                    raise InvalidSort("{} has no attribute {}".format(self.schema.__name__, field))
                if field in get_relationships(self.schema):
                    raise InvalidSort("You can't sort on {} because it is a relationship field".format(field))
                field = get_model_field(self.schema, field)
                order = 'desc' if sort_field.startswith('-') else 'asc'
                sorting_results.append({'field': field, 'order': order})
            return sorting_results

        return []

    @property
    def include(self):
        """Return fields to include

        :return list: a list of include information
        """
        include_param = self.qs.get('include', [])

        if current_app.config.get('MAX_INCLUDE_DEPTH') is not None:
            for include_path in include_param:
                if len(include_path.split('.')) > current_app.config['MAX_INCLUDE_DEPTH']:
                    raise InvalidInclude("You can't use include through more than {} relationships"
                                         .format(current_app.config['MAX_INCLUDE_DEPTH']))

        return include_param.split(',') if include_param else []


def decode_fiql_query(query_str):
    """
            Decode a FIQL query
            :param query_str:
    """
    try:
        decoded = fiql_parser.parse_str_to_expression(query_str)
        return decoded
    except fiql_parser.exceptions.FiqlException as error:
        raise InvalidFilters('Invalid query: {}'.format(error))
    except AttributeError as error:
        raise InvalidField('Attribute {} is not valid for querying'.format(error))

def transform_fiql_query(q,type_):
    this_op = q
    last_op = []
    newq = []

    op_map = { '>': 'gt',
               '<': 'lt',
               '==': 'eq',
               '<=': 'le',
               '>=': 'ge',
               '!=': 'ne',
               'like': 'like'
    }
    def _procq(cur,l,operator=None, depth=0):
        if depth>6:
            raise InvalidFilters("Filter depth exceeded")
        nl = None
        if isinstance(cur,list) and isinstance(cur[0],str):
            operator = cur.pop(0).lower()
            nl = []
            nls = {operator: nl}
            l.append(nls)
        else:
            nl = l
        lists = []
        for cond in cur:
            if isinstance(cond,tuple):
                _names,_cond,_val = cond
                names = _names.split('.')
                _names,_cond,_val = cond
                name = None
                if len(names) > 1 and names[0] == type_:
                    names.pop(0)
                if _val.startswith('*'):
                    raise InvalidFilters("partial substring matches not supported")
                elif _val.endswith('*'):
                    op = 'like'
                    _cond = op
                    _val = _val.replace('*','%')
                else:
                    op = 'eq'
                if len(names) == 2:
                    op = 'has'
                    val  = { "name": names[1], "op" : op_map.get(_cond), "val" : _val  }
                    name = names[0]
                elif len(names) == 1:
                    val = _val
                    op = op_map.get(_cond)
                    name = names[0]
                if not name:
                    raise InvalidFilters("query filter parameters not valid")
                d = {'name': name, 'op': op, 'val': val }
                nl.append(d)
            elif isinstance(cond,list):
                lists.append(cond)
        if lists:
            for lst in lists:
                _procq(lst,nl,operator,depth+1)
    if not isinstance(q,list):
        q = [q]
    _procq(q,newq,None,1)
    return newq
