#!/usr/bin/env python3

import sys
import os
from configparser import ConfigParser, ExtendedInterpolation, ParsingError, DuplicateSectionError, DuplicateOptionError
from flask import Flask, abort, render_template, jsonify, request, send_from_directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # Need this for the next import
from watchtower import Watchtower, Db, Helpers

app = Flask(__name__)
app.config.update({'JSON_SORT_KEYS': False})
in_development_mode = app.config.get('ENV').lower() == 'development'

watchtower = Watchtower()
config_file = f'{os.path.dirname(os.path.realpath(__file__))}{os.sep}web.conf'

if not os.path.exists(config_file):
    message = f'Configuration file {config_file} does not exist.\n' if in_development_mode else None
    abort(500, message)
try:
    config = ConfigParser(interpolation=ExtendedInterpolation(), default_section='default', allow_no_value=True)
    config.read(config_file)
except ParsingError as pe:
    lines = str(pe).split('\n')
    errors = '\n'.join(map(str, lines[1:]))
    message = f'Configuration file {config_file} could not be loaded due to parsing errors:\n\n{errors}\n' if in_development_mode else None
    abort(500, message)
except (DuplicateSectionError, DuplicateOptionError) as de:
    message = f'Configuration file {config_file} could not be loaded due to parsing errors:\n\n{de}\n' if in_development_mode else None
    abort(500, message)


class DataTables:
    """
    Class used to handles actions related to a DataTable.
    """
    def __init__(self):
        self.length = 10
        self.start = 0
        self.draw = int(request.values.get('draw', 1))
        self.order_col_index = int(request.values.get('order[0][column]', 0)) + 1
        self.direction = 'DESC' if request.values.get('order[0][dir]', 'ASC') == 'desc' else 'ASC'

    @staticmethod
    def get_table_config(database, tables=None):
        """
        Compiles a dict of tables mapped to their normalized columns.

        If the configuration file contains key-value pairs for a given database, then these values will be used to
        determine table and column visibility.

        :param database: Database to use.
        :param tables: List of tables to use (if None, then all tables will be retrieved).
        :return: Dict of table name strings mapped to their comma-separated column name strings
        """
        section_key = f"{Helpers.strip_filename(database.db_path)}"

        if not config.has_section(section_key):
            return dict(map(lambda t: (t, ','.join(database.get_table_columns(t))), database.get_tables() if not tables else tables))

        tableconfig = config[section_key]

        normalized_tables = {}

        for table, columnstring in tableconfig.items():
            columnstring = ','.join([col.strip() for col in columnstring.split(',')]) if columnstring.strip() else ','.join(database.get_table_columns(table))
            if not tables or table in tables:
                normalized_tables[table] = columnstring

        return normalized_tables

    def get_response(self, total_count, filtered_count, rows, error=None):
        """
        Returns a response for a DataTable AJAX query.

        :param rows: List of rows where each row is a dict in the form of {"column_name": value}.
        :param total_count: Total number of rows in the table.
        :param filtered_count: Total number of rows in the table after filtering.
        :param error: Error message to display (do not set if there's no error).
        :return: JSON object DataTables response.
        """
        return jsonify({
            'draw': self.draw,
            'recordsTotal': total_count,
            'recordsFiltered': filtered_count,
            'data': rows
        }) if not error else jsonify({
            'draw': self.draw,
            'recordsTotal': 0,
            'recordsFiltered': 0,
            'data': [],
            'error': error
        })


@app.route('/')
def global_search_page():
    """
    Global search page.  Accepts GET requests and both GET/POST parameters.

    :return: Rendered Jinja HTML template.
    """
    db_param = Helpers.empty_to_none(request.values.get('database', None))
    all_dbs = watchtower.get_all_database_files()
    db_filepath = watchtower.get_database_filepath(db_param) if db_param else Helpers.sort_files_by_ostime(all_dbs)[-1] if all_dbs else None

    db = Db(db_filepath)
    query = request.values.get('query', None)
    tables = DataTables.get_table_config(db)

    return render_custom_template('global_search.html', global_search_api='/api/v1/global-search/search', query=query, tables=tables)


@app.route('/api/<version>/<method>/<action>', methods=['GET', 'POST'])
def api(version, method, action):
    """
    API entry point.  Accepts both GET and POST requests/parameters.

    :param version: Version being requested.
    :param method: Method being requested.
    :param action: Action being requested.
    :return: JSON object API response.
    """
    if version == 'v1' and method == 'global-search' and action == 'search':
        return global_search()
    if version == 'v1' and method == 'database' and action == 'download':
        return database_download()

    return jsonify({'error': 'Invalid request.'})


def render_custom_template(template, **kwargs):
    """
    Custom template renderer.  Ensures the base.html template has all its required arguments.

    :return: Rendered Jinja HTML template.
    """
    db_param = Helpers.empty_to_none(request.values.get('database', None))
    all_dbs = watchtower.get_all_database_files()
    db_filepath = watchtower.get_database_filepath(db_param) if db_param else Helpers.sort_files_by_ostime(all_dbs)[-1] if all_dbs else None

    if not db_filepath or db_filepath not in all_dbs:
        if db_param:
            abort(500, f'Database "{db_param}" not found.')
        else:
            abort(500, f'No databases found.')

    databases = [Helpers.strip_filename(db) for db in watchtower.get_all_database_files()]
    databases.insert(0, databases.pop(databases.index(Helpers.strip_filename(db_filepath))))  # Put chosen database at front of list

    kwargs.update(database_download_api='/api/v1/database/download')
    kwargs.update(databases=databases)

    return render_template(template, **kwargs)


def global_search():
    """
    API handler for DataTables JSON responses to global search requests.

    Request parameters:
        database: Database to use (required).
        table: Table to search (required).
        query: Query keyword to search for (default: None).
        order: Column index number by which to order the results (default: 1).
        direction: Direction to order the results (default: ASC).
        length: Maximum number of results to return (default: 10).
        start: Number by which to offset the results (default: 0).

    :return: JSON object DataTables response.
    """
    dt = DataTables()

    db_param = Helpers.empty_to_none(request.values.get('database', None))
    all_dbs = watchtower.get_all_database_files()
    db_filepath = watchtower.get_database_filepath(db_param) if db_param else None

    if not db_filepath or db_filepath not in all_dbs:
        if db_param:
            return dt.get_response(0, 0, [], f'Database "{db_param}" not found.')
        else:
            return dt.get_response(0, 0, [], f'Must specify a database parameter.')

    db = Db(db_filepath)
    table = Helpers.empty_to_none(request.values.get('table', None))

    if not table:
        return dt.get_response(0, 0, [], f'No table specified.')
    if not db.table_exists(table):
        return dt.get_response(0, 0, [], f"Table <b>{table}</b> does not exist.")

    columns = DataTables.get_table_config(db, [table])[table].split(',')
    query = Helpers.empty_to_none(request.values.get('query', None))
    order = Helpers.empty_to_none(request.values.get('order', None))
    order = int(order) if order else dt.order_col_index
    direction = Helpers.empty_to_none(request.values.get('direction', None))
    direction = int(direction) if direction else dt.direction
    limit = Helpers.empty_to_none(request.values.get('length', None))
    limit = int(limit) if limit else dt.length
    offset = Helpers.empty_to_none(request.values.get('start', None))
    offset = int(offset) if offset else dt.start

    try:
        total_count, filtered_count, rows = db.search_table(table, columns, query, order, direction, limit, offset)
        return dt.get_response(total_count, filtered_count, rows)
    except Exception:
        return dt.get_response(0, 0, [], f"Error attempting to fetch data: Check your web.conf file or your API request for references to tables or columns that don't exist.")


def database_download():
    """
    API handler for database download requests.

    Request parameters:
        database: Database to download (required).

    :return: Database file as an HTTP response attachment.
    """
    db_param = request.values.get('database', None)

    if not db_param:
        return jsonify({'error': 'No database specified.'})

    if watchtower.get_database_filepath(db_param):
        return send_from_directory(directory=watchtower.get_database_directory(), filename=os.path.basename(watchtower.get_database_filepath(db_param)), as_attachment=True)
    else:
        return jsonify({'error': f'Database "{db_param}" not found.'})
