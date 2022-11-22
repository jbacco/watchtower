#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import inspect
import json
import locale
import os
import psutil
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from colored import fg, attr
from configparser import ConfigParser, ExtendedInterpolation, ParsingError, DuplicateSectionError, DuplicateOptionError
from dateutil.parser import parse
from filelock import Timeout, FileLock
from importlib import import_module
from inspect import getmembers, isclass
from interface import implements, interface, Interface, InvalidImplementation
from pathlib import Path
from sqlite3 import connect, Row, IntegrityError
from sqlite_utils import Database, db, suggest_column_types
from tabulate import tabulate


class Regex:
    """
    Class which provides constants for Regex checks.
    """
    CONFIG_KEY_VALUE_PAIR = '^.*(:|=).*$'
    ARG_NAME = '^[a-z0-9_]*$'
    EMAIL = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    IPv4 = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    PORT = '^\d{1,5}$'
    PROTOCOL = '^(tcp|udp)$'
    FTS_TABLE = '^.*(_fts|_fts_config|_fts_data|_fts_docsize|_fts_idx)$'
    MULTIPLE_COMMAS = '[,]{2,}'
    ONLY_COMMAS = '^[,]*$'
    DATETIME_FULL_ISO = '^[+-]?\d{4}(-[01]\d(-[0-3]\d(T[0-2]\d:[0-5]\d:?([0-5]\d(\.\d+)?)?([+-][0-2]\d:[0-5]\d)?Z?)?)?)?$'
    DATETIME_ISO = '^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$'
    DATE_ISO = '^(\d{4})-(\d{2})-(\d{2})$'


class Colors:
    """
    Class which provides constants for colors.
    """
    APP = fg('deep_sky_blue_2')
    COMMAND = fg('deep_sky_blue_3a')
    ARGS = fg('deep_sky_blue_2')
    INFO = fg('deep_sky_blue_2')
    WARN = fg('yellow')
    SUCCESS = fg('green')
    FAIL = fg('magenta')
    RESET = attr('reset')


class Tags:
    """
    Class which provides constants for colorful, verbose output.
    """
    INFO = f"{Colors.INFO}[*]{Colors.RESET}"
    WARN = f"{Colors.WARN}[!]{Colors.RESET}"
    SUCCESS = f"{Colors.SUCCESS}[+]{Colors.RESET}"
    FAIL = f"{Colors.FAIL}[-]{Colors.RESET}"


class DateTime:
    """
    Class which provides constants for datetime parsing.
    """
    DATETIME_FULL_HUMAN_ISO_FORMAT = '%a, %b %d, %Y %I:%M %p %Z'
    DATETIME_ISO_FORMAT = '%Y-%M-%d %I:%M:%S'
    DATE_ISO_FORMAT = '%Y-%M-%d'


class Helpers:
    """
    Class which provides helper functions in the form of static methods.
    """
    @staticmethod
    def json_serializer(obj):
        """
        JSON serializer for objects that can't be serialized by default.

        :param obj: Object to serialize.
        :return: Serialized JSON string.
        """
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        raise TypeError(f'Type {type(obj)} not JSON serializable.')

    @staticmethod
    def json_deserializer(obj):
        """
        JSON deserializer for objects that can't be deserialized by default.

        :param obj: Object to deserialize.
        :return: Deserialized JSON object.
        """
        for k, v in obj.items():
            if isinstance(v, str):
                try:
                    if re.match(Regex.DATE_ISO, v):
                        obj[k] = datetime.date.fromisoformat(v)
                    elif re.match(Regex.DATETIME_FULL_ISO, v):
                        obj[k] = datetime.datetime.fromisoformat(v)
                    elif re.match(Regex.DATETIME_ISO, v):
                        obj[k] = datetime.datetime.strptime(v, DateTime.DATETIME_ISO_FORMAT)
                    else:
                        pass
                except:
                    pass
        return obj

    @staticmethod
    def empty_to_none(str):
        """
        Converts an empty string to None.

        :param str: A string.
        :return: None or a string.
        """
        return None if not str else str

    @staticmethod
    def remove_duplicates(lst):
        """
        Removes duplicate values from a list.

        :param lst: A list.
        :return: A de-duplicated list.
        """
        return list(dict.fromkeys(lst))

    @staticmethod
    def create_directories(dirs):
        """
        Creates target directories if they don't already exist.

        :param dirs: List of directories to create.
        :return: None.
        """
        [Path(d).mkdir(parents=True, exist_ok=True) for d in dirs if not os.path.exists(d)]

    @staticmethod
    def list_visible_files(path):
        """
        Removes all files from os.listdir() which begin with a period.

        :param path: Path on which to run os.listdir().
        :return: List of file paths.
        """
        for f in os.listdir(path):
            if not f.startswith('.'):
                yield f

    @staticmethod
    def generate_utc_datetime():
        """
        Generates a UTC datetime object.

        :return: Datetime object.
        """
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def convert_string_to_datetime(str):
        """
        Generates a UTC datetime object from a string.

        :param str: A string in datetime form.
        :return: Datetime object.
        """
        return parse(str).astimezone(datetime.timezone.utc)

    @staticmethod
    def generate_timestamp_filename(directory, name, ext):
        """
        Generates a timestamp filename.

        :param directory: Directory location of the file.
        :param name: Name of the file.
        :param ext: Extension of the file.
        :return: Datetime object.
        """
        return f"{directory}{os.sep}{name}_{time.time()}{os.extsep}{ext}"

    @staticmethod
    def get_module_name_from_file(name):
        """
        Retrieves a module name from a filename.

        :param name: Name of the file.
        :return: Module name string.
        """
        return '_'.join(Helpers.strip_filename(name).split('_')[:-1])

    @staticmethod
    def get_timestamp_from_file(name):
        """
        Retrieves a timestamp from a filename.

        :param name: Name of the file.
        :return: Timestamp string.
        """
        return Helpers.strip_filename(name).split('_')[-1]

    @staticmethod
    def sort_files_by_timestamp_name(files):
        """
        Sorts a list of files by the timestamps indicated in their filenames.

        :param files: List of filenames which follow the timestamp naming convention (e.g. [watchtower_1590173358.8195605.db]).
        :return: List of files.
        """
        files.sort(key=lambda f: Helpers.get_timestamp_from_file(f))
        return files

    @staticmethod
    def sort_files_by_ostime(files):
        """
        Sorts a list of files by the last modified timestamps indicated by the operating system.

        :param files: List of filenames (must include full or relative directory path).
        :return: List of files or None.
        """
        if files and isinstance(files, list): files.sort(key=lambda f: os.path.getmtime(f))
        return files

    @staticmethod
    def timestamp_to_human_datetime(timestamp):
        """
        Converts a timestamp to a local human datetime object.

        :param timestamp: An epoch timestamp, usually generated by time.time().
        :return: Datetime object.
        """
        return datetime.datetime.fromtimestamp(float(timestamp)).astimezone().strftime(DateTime.DATETIME_FULL_HUMAN_ISO_FORMAT)

    @staticmethod
    def datetime_iso_to_human(str):
        """
        Converts a datetime iso string to human form.

        :param str: A datetime iso string, usually generated by datetime.datetime.isoformat().
        :return: Datetime object.
        """
        return datetime.datetime.fromisoformat(str).astimezone().strftime(DateTime.DATETIME_FULL_HUMAN_ISO_FORMAT)

    @staticmethod
    def human_string_to_datetime(str):
        """
        Converts a human datetime string to a datetime object.

        :param str: A human datetime string, usually generated by datetime.datetime.strftime().
        :return: Datetime object.
        """
        return datetime.datetime.strptime(str, DateTime.DATETIME_FULL_HUMAN_ISO_FORMAT)

    @staticmethod
    def strip_filename(filename):
        """
        Removes the path and extension from a filename.

        :param filename: Filename or path to strip.
        :return: Filename string without path or extension.
        """
        return os.path.splitext(os.path.basename(filename))[0]

    @staticmethod
    def replace_slashes_by_os(str):
        """
        Ensures all slashes in a string are backward for Windows and forward for everything else.

        :param str: String to fix.
        :return: String with slashes replaced.
        """
        return str.replace('/', '\\') if os.name == 'nt' else str.replace('\\', '/')

    @staticmethod
    def log(str):
        """
        Logs a given string to the app_log file.

        :param str: String to log.
        :return: None.
        """
        watchtower = Watchtower()
        log_file = f"{watchtower.config.get('default', 'app_log')}"

        with open(log_file, 'a') as app_log:
            app_log.write(f'{str}\n')

    @staticmethod
    def print_and_log(str):
        """
        Prints a given string to the screen and writes it to the app_log file.

        :param str: String to print and log.
        :return: None.
        """
        print(str)
        Helpers.log(str)


class Db:
    """
    Class used to handle actions related to a Database.
    """
    def __init__(self, filepath):
        assert filepath, f'No database specified.'
        assert os.path.exists(filepath), f'Database {filepath} not found.'
        self.db_path = filepath
        self.db = Database(connect(self.db_path))

    @staticmethod
    def not_fts_table(table):
        """
        Filter for removing FTS tables from a list.

        :param table: Name of table.
        :return: True if table is an FTS table, False otherwise.
        """
        return False if re.match(Regex.FTS_TABLE, table) else True

    @staticmethod
    def normalize_fts_query(query):
        """
        Prepares a query string for use with SQLite3 FTS.

        :param query: Query string to normalize.
        :return: String.
        """
        phrases = list(map(lambda p: p.replace('"', ''), re.findall('"[^"]*"', query)))

        for p in phrases:
            query = query.replace(p, '')

        keywords = list(map(lambda k: k
                            .replace('"', '')
                            .replace('\'', '')
                            .replace(' ', '')
                            .replace('\n', '')
                            .replace('\r', '')
                            .replace(',', '')
                            , list(filter(None, map(lambda w: w, re.findall('\\b[^\\s]*\\b', query))))))

        query = '" OR "'.join(phrases + keywords) if phrases.count or keywords.count else None
        return f'"{query}"' if query else None

    def get_tables(self, filter_fts=True):
        """
        Retrieves the table names from the database.  Can filter out FTS tables (default) or include them.

        :param filter_fts: If True, filters FTS tables out of the list.
        :return: List of table name strings.
        """
        return list(filter(Db.not_fts_table, self.db.table_names())) if filter_fts else self.db.table_names()

    def get_table_count(self, table):
        """
        Returns the total number of rows in a table.

        :param table: Table to count.
        :return: Numeric string.
        """
        return self.db[table].count

    def get_table_columns(self, table):
        """
        Retrieves the column names for a table.

        :param table: Table to use.
        :return: List of column name strings.
        """
        return [name for name in self.db[table].columns_dict.keys()]

    def table_exists(self, table):
        """
        Checks if a table name exists in the database.

        :param table: Table to find.
        :return: True if the table name exists, False otherwise.
        """
        return self.db[table].exists()

    def column_exists(self, table, column):
        """
        Checks if a column name exists in a table.

        :param table: Table to use.
        :param column: Column to find.
        :return: True if the column name exists in the table, False otherwise.
        """
        if not self.db[table].exists():
            return False
        for c in self.db[table].columns_dict.keys():
            if column == c:
                return True
        return False

    def search_table(self, table, columns, query, order=1, direction='ASC', limit=0, offset=0):
        """
        Performs a full text search on a list of columns in a table.

        :param table: Table to search.
        :param columns: Columns to search.
        :param query: String to match.
        :param order: Column index number by which to sort the rows.
        :param direction: Direction to sort the rows.
        :param limit: Maximum number of rows to respond with.
        :param offset: Number of rows to skip.
        :return:    Numeric string: Total number rows in the table.
                    Numeric string: Filtered number of rows in the table.
                    List: Rows in dict form.
        """
        assert self.table_exists(table), f'Table {table} not found.'

        if columns:
            for column in columns:
                assert self.column_exists(table, column), f'Column {column} not found.'
        else:
            columns = self.get_table_columns(table)

        order = int(order)
        direction = 'DESC' if direction.lower() in ['desc', 'descending'] else 'ASC'
        limit = int(limit)
        limit_sql = f' LIMIT {limit}' if limit else ''
        offset = int(offset)
        offset_sql = f' OFFSET {offset}' if offset else ''

        self.db.conn.row_factory = Row
        total_count = self.db.table(table).count
        query = Db.normalize_fts_query(query) if query else None
        match = '{' + ' '.join(columns) + '}: ' + f'{query}' if query else None

        c = self.db.conn.execute(f"SELECT COUNT(*) AS filtered_count FROM {table} WHERE rowid IN (SELECT rowid FROM {table}_fts WHERE {table}_fts MATCH ?)", (match,)) if match else None
        filtered_count = c.fetchone()['filtered_count'] if match else total_count
        c = self.db.conn.execute(f"SELECT {','.join(columns)} FROM {table} WHERE rowid IN (SELECT rowid FROM {table}_fts WHERE {table}_fts MATCH ?) ORDER BY {order} {direction}{limit_sql}{offset_sql}", (match,)) if match else self.db.conn.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY {order} {direction}{limit_sql}{offset_sql}")
        return total_count, filtered_count, [dict(row) for row in c.fetchall()]


class BaseInterface(Interface):
    pass


class WatchtowerModuleInterface(BaseInterface):
    @interface.default
    def get_config_value(self, key):
        """
        Module helper method for retrieving configuration key values.

        :param key: Configuration key to fetch.
        :return: Value of the key if set, None otherwise.
        """
        config_file = Watchtower.get_config_filepath()
        module_name = Helpers.strip_filename(inspect.getmodule(inspect.stack()[1][0]).__file__)
        return parse_config(config_file).get(module_name, key, fallback=None)

    def run(self, args):
        """
        Module method which is dynamically called by `watchtower run`.  Must be implemented.

        :param args: List of arguments specified in the command line with `-a`.
        :return: Module Response.
        """
        pass


class Watchtower:
    """
    Class used to handle all Watchtower functionality.
    """
    def __init__(self):
        db.COLUMN_TYPE_MAPPING.update({bool: 'BOOLEAN', datetime: 'DATETIME', datetime.datetime: 'DATETIME', datetime.date: 'DATE'})
        locale.setlocale(locale.LC_ALL, '')
        self.config_file = Watchtower.get_config_filepath()

        try:
            self.config = self._initialize_config_file(self.config_file)
        except Exception as e:
            exit(e)

        Helpers.create_directories([
            self.config.get('default', 'cache_dir'),
            self.config.get('default', 'database_dir'),
            self.config.get('default', 'module_dir'),
            self.config.get('default', 'web_dir')
        ])
        self.lock_timeout = 60

    @staticmethod
    def get_config_filepath():
        """
        Retrieves the Watchtower configuration filepath.

        :return: Filepath string.
        """
        return f'{os.path.dirname(os.path.realpath(__file__))}{os.sep}watchtower.conf'
        
    @staticmethod
    def validate_module_response(data):
        """
        Ensures a module's response data is valid.  Throws an AssertionError if the data is invalid.

        :param data: Data that the module intends to return from its run() method.
        :return: None.
        """
        assert data, "Response data is empty."
        assert type(data) is dict, "Response data is not a dict."
        assert data.get('tables'), "data.get('tables') does not exist."
        assert type(data.get('tables')) is dict, "data.get('tables') is not a dict."

        for table in data.get('tables'):
            assert table != 'imports', f"data.get('tables').get('imports') is not allowed."
            assert not re.match(Regex.FTS_TABLE,
                                table), f"data.get('tables').get('{table}') is not allowed because it conflicts with FTS tables."
            if data.get('tables').get(table).get('pk'): assert type(data.get('tables').get(table).get(
                'pk')) is str, f"data.get('tables').get('{table}').get('pk') is not a string."
            assert type(data.get('tables').get(table)) is dict, f"data.get('tables').get('{table}') is not a dict."
            assert data.get('tables').get(table).get(
                'rows'), f"data.get('tables').get('{table}').get('rows') is empty or does not exist."
            assert type(data.get('tables').get(table).get(
                'rows')) is list, f"data.get('tables').get('{table}').get('rows') is not a list."

            for row in data.get('tables').get(table).get('rows'):
                assert type(
                    row) is dict, f"data.get('tables').get('{table}').get('rows') contains an item that is not a dict: {row}"

    def get_all_database_files(self):
        """
        Retrieves all database files from the database directory.

        :return: List of database file strings.
        """
        return list(map(lambda d: f"{self.config.get('default', 'database_dir')}{os.sep}{d}", Helpers.list_visible_files(self.config.get('default', 'database_dir'))))

    def get_most_recent_database(self):
        """
        Retrieves the most recently modified database file from the database directory.

        :return: A database file string.
        """
        return Helpers.sort_files_by_ostime(self.get_all_database_files())[-1]

    def get_database_directory(self):
        """
        Returns the database directory.

        :return: Directory path string.
        """
        return f"{self.config.get('default', 'database_dir')}{os.sep}"

    def get_database_filepath(self, filename):
        """
        Generates an absolute filepath for a given database filename.

        :return: Database file string.
        """
        return f"{self.config.get('default', 'database_dir')}{os.sep}{Helpers.strip_filename(filename)}{os.extsep}{self.config.get('default', 'database_ext')}"

    def _initialize_config_file(self, config_file):
        """
        Initializes a configuration file (with sensitivity to the OS) and returns the new config.

        :param config_file: Configuration filepath.
        :return: ConfigParser object.
        """
        config = parse_config(config_file)

        config.set('default', 'app_dir', f'{os.path.dirname(os.path.realpath(__file__))}')
        [config.set('default', k, Helpers.replace_slashes_by_os(v)) for k, v in config.items('default', raw=True) if k in
         ['app_dir', 'app_script', 'app_log', 'cache_dir', 'database_dir', 'module_dir', 'web_dir', 'web_script', 'web_log', 'cache_ext', 'database_ext', 'module_ext']]

        with open(config_file, 'w') as configfile:
            config.write(configfile)
        return config

    def _validate_and_normalize_args(self, args):
        """
        Ensures all arguments match their respective restrictions and attempts to normalize them to predictable values.

        :param args: Namespace object from the argparse package.  If a dict is provided, it will be converted.
        :return: Namespace object of args.
        """
        if not isinstance(args, argparse.Namespace):
            try:
                args = argparse.Namespace(**args)
                [args.__setattr__(arg, None) for arg in ['name', 'database', 'modules', 'files', 'force'] if not args.__contains__(arg)]
            except TypeError:
                exit(f'{Tags.FAIL} Args passed to execute_command() must either be an argparse.Namespace object or a dict.')
        if args.name:
            if not re.match(Regex.ARG_NAME, args.name):
                exit(f'{Tags.FAIL} Names specified with -n can only use lowercase letters, numbers, and underscores.')
        if args.database:
            args.database = self.get_database_filepath(args.database)
            if not os.path.exists(args.database):
                exit(f'{Tags.FAIL} Database file {Colors.INFO}{args.database}{Colors.RESET} was not found.')
        if args.modules:
            all_modules = self._get_all_modules()
            for module in args.modules:
                if module not in all_modules:
                    exit(f'{Tags.FAIL} Module {Colors.INFO}{module}{Colors.RESET} was not found.  Make sure it\'s defined in {Colors.INFO}{self.config_file}{Colors.RESET}.')
            args.modules = Helpers.remove_duplicates(args.modules)
        if args.files:
            for index, file in enumerate(args.files):
                args.files[index] = f"{self.config.get('default', 'cache_dir')}{os.sep}{os.path.basename(file)}"
                if not os.path.exists(args.files[index]):
                    exit(f'{Tags.FAIL} Cache file {Colors.INFO}{args.files[index]}{Colors.RESET} was not found.')
            args.files = Helpers.remove_duplicates(args.files)
        return args

    def _write_file(self, filepath, data, as_bytes=False):
        """
        Writes a target file with data.  Uses a file lock to prevent concurrent changes.

        :param filepath: File path string.
        :param data: Data to write.
        :param as_bytes: If true, will open the file in binary mode.
        :return: None.
        """
        file_lock = self._get_file_lock(filepath)
        try:
            with file_lock.acquire(timeout=self.lock_timeout), (open(filepath, 'wb') if as_bytes else open(filepath, 'w')) as f:
                f.write(data)
        except Timeout:
            Helpers.print_and_log(f'{Tags.FAIL} Could not acquire write lock on {Colors.INFO}{filepath}{Colors.RESET} after {self.lock_timeout} seconds because another instance of this application is using it.  Try again later.')
        finally:
            self._release_file_lock(file_lock)

    def _get_all_modules(self):
        """
        Retrieves all module names from the configuration sections.

        :return: List of all module names.
        """
        return self.config.sections()

    def _get_all_module_files(self, module=None):
        """
        Fetches all module names and files from the configuration.

        :param module: If specified, only the mapping for this module will be returned.
        :return: Dict of all module names mapped to their module file.
        """
        return dict(map(lambda m: (m, f"{self.config.get('default', 'module_dir')}{os.sep}{m}{os.extsep}{self.config.get('default', 'module_ext')}"), [module] if module else self._get_all_modules()))

    def _get_all_module_classes(self, module):
        """
        Inspects a Python module for classes which subclass WatchtowerModule and properly implement WatchtowerModuleInterface.

        :param module: Python module to inspect for WatchtowerModule subclasses.
        :return: List of all classes which properly implement WatchtowerModuleInterface.
        """
        return list(map(lambda k: k, [(name, klass) for name, klass in getmembers(module, isclass) for base in klass.__bases__ if type(base) == type(WatchtowerModule)]))

    def _get_all_cache_files(self, match=''):
        """
        Retrieves all cache files from the cache directory.

        :param match: Specifying match will only return files that begin with this string.
        :return: List of cache file strings.
        """
        return list(map(lambda f: f"{self.config.get('default', 'cache_dir')}{os.sep}{f}", [file for file in Helpers.list_visible_files(self.config.get('default', 'cache_dir')) if os.path.basename(file).startswith(match)]))

    def _generate_file_lockname(self, filepath):
        """
        Generates a lock filename for a given filepath.

        :param filepath: An absolute path to a file.
        :return: Filename string.
        """
        return f"{filepath}{os.extsep}lock"

    def _get_file_lock(self, filepath):
        """
        Gets a file lock on a file.  Note that you still have to call lock.acquire() inside of a with-block.

        :param filepath: An absolute path to a file.
        :return: FileLock object.
        """
        return FileLock(self._generate_file_lockname(filepath))

    def _release_file_lock(self, lock):
        """
        Releases a file lock.

        :param lock: Lock to release.
        :return: None.
        """
        lock.release()
        # Probably a bad idea to call os.remove():
        #   https://github.com/benediktschmitt/py-filelock/issues/31
        #   https://stackoverflow.com/questions/17708885/flock-removing-locked-file-without-race-condition
        if os.path.exists(lock._lock_file): os.remove(lock._lock_file)

    def _find_webserver_pid(self):
        """
        Enumerates running processes and attempts to detect the web server's pid, if any.

        :return: Pid integer, or None.
        """
        for process in psutil.process_iter():
            try:
                for line in process.cmdline():
                    if 'flask' in line and f"{self.config.get('default', 'web_script')}" == process.environ().get('FLASK_APP', None):
                        return process.pid
            except psutil.AccessDenied:
                continue

        return None

    def _import_file(self, db_conn, filepath, force=False):
        """
        Imports a cache file into a given database.

        :param db_conn: Connection to the target database.
        :param filepath: String representing the absolute file path of a cache file.
        :param force: False to prevent duplicate imports, True to import anyway.
        :return: None.
        """
        try:
            with open(filepath, 'r') as f, open(filepath, 'rb') as fb:
                data = json.load(f, object_hook=Helpers.json_deserializer)
                sha1 = hashlib.sha1(fb.read()).hexdigest()
                Watchtower.validate_module_response(data)

                database = Database(db_conn)

                imports_table_name = 'imports'
                imports_table = database.table(imports_table_name)
                import_row = {'module': Helpers.get_module_name_from_file(filepath), 'file': filepath, 'sha1': sha1, 'timestamp': Helpers.generate_utc_datetime()}
                if not imports_table.exists():
                    imports_table.create(suggest_column_types([import_row]), pk='id')
                    [imports_table.create_index([k]) for k in import_row.keys()]
                    imports_table.enable_fts([name for name in imports_table.columns_dict.keys()], create_triggers=True)
                    Helpers.print_and_log(f"{Tags.SUCCESS} Created table: {Colors.INFO}{imports_table_name}{Colors.RESET}")

                if len(list(imports_table.rows_where('sha1 = ?', [sha1]))) and not force:
                    Helpers.print_and_log(f"{Tags.WARN} File {Colors.INFO}{os.path.basename(filepath)}{Colors.RESET} has already been imported and will be skipped.  Run this command again with {Colors.INFO}--force{Colors.RESET} if you want to import it anyway.")
                    return

                imports_table.insert(import_row, alter=True)
                import_id = imports_table.last_pk

                for table_name in data.get('tables'):
                    rows = data.get('tables').get(table_name).get('rows')
                    [r.update({'import_id': import_id}) for r in rows]
                    table = database.table(table_name)
                    pk = data.get('tables').get(table_name).get('pk')
                    if not table.exists():
                        table.create(suggest_column_types(rows), pk=pk)
                        table.add_foreign_key('import_id', 'imports', 'id')
                        table.enable_fts([name for name in table.columns_dict.keys()], create_triggers=True)
                        Helpers.print_and_log(f"{Tags.SUCCESS} Created table: {Colors.INFO}{table_name}{Colors.RESET}")
                    Helpers.print_and_log(f"{Tags.INFO} Updating table {Colors.INFO}{table_name}{Colors.RESET}...")
                    table.insert_all(rows, pk=pk, alter=True, replace=True)
                    # Ensure newly created rows get indexed
                    [table.create_index([k]) for k in (set([c.name for c in table.columns]) - (set([i.columns[0] for i in table.indexes])))]
                    Helpers.print_and_log(f"{Tags.SUCCESS} Inserted {Colors.INFO}{len(rows):n}{Colors.RESET} row(s) into table {Colors.INFO}{table_name}{Colors.RESET} (import_id = {Colors.INFO}{import_id}{Colors.RESET}).")
        except (json.JSONDecodeError, AssertionError) as e:
            Helpers.print_and_log(f"{Tags.FAIL} Cache file read failed.  File {Colors.INFO}{filepath}{Colors.RESET} contains data that does not adhere to the Module Response guidelines (see {Colors.INFO}README.md{Colors.RESET}).  As a result, this file will not be imported into the database.\n\nReason: {e}\n")
        except IntegrityError as ie:
            Helpers.print_and_log(f"{Tags.FAIL} Cache file import failed.  File {Colors.INFO}{filepath}{Colors.RESET} contains data that violates a constraint of table {Colors.INFO}{table_name}{Colors.RESET}.  As a result, this file will not be imported into the database.\n\nReason: {ie}\n")

    def _status(self, args):
        """
        Handler for the `watchtower status` command.

        Prints the configuration, module, database, and web server status.

        Optional arguments:
            -d: Specify a database.

        :param args: Namespace object of arguments.
        :return: None.
        """
        db_table = []
        if args.database:
            db_filepath = args.database
            db_updated = Helpers.timestamp_to_human_datetime(os.path.getmtime(os.path.realpath(db_filepath)))
            db_table.append(['last_updated:', f'{Colors.INFO}{db_updated}{Colors.RESET}'])
            db = Database(connect(db_filepath))

            for table in db.table_names():
                if not re.match(Regex.FTS_TABLE, table):
                    rowcount = db[table].count
                    db_table.append([f'{table}:', f'{Colors.INFO}{rowcount:n}{Colors.RESET}'])

            Helpers.print_and_log(f'{Tags.INFO} {Colors.INFO}{os.path.basename(os.path.realpath(db_filepath))}{Colors.RESET}')
            exit(tabulate(db_table, tablefmt='plain'))

        config_table = []
        web_table = []

        for item in self.config.items('default'):
            config_table.append([f'{item[0]}:', f'{Colors.INFO}{item[1]}{Colors.RESET}'])
        for module in self.config.sections():
            config_table.append([f'{Colors.INFO}*{Colors.RESET} {module}:', f"{Colors.INFO}{self.config.get(module, 'description', fallback='')}{Colors.RESET}"])

        Helpers.print_and_log(f"{Tags.INFO} {Colors.INFO}{os.path.basename(self.config_file)}{Colors.RESET}")
        Helpers.print_and_log(tabulate(config_table, tablefmt='plain'))

        Helpers.print_and_log(f"\n{Tags.INFO} {Colors.INFO}{os.path.basename(self.config.get('default', 'web_script'))}{Colors.RESET}")

        log_file = f"{self.config.get('default', 'web_log')}"
        web_pid = self._find_webserver_pid()
        web_table.append(['status:', f'{Colors.SUCCESS}active{Colors.RESET}' if web_pid else f'{Colors.FAIL}inactive{Colors.RESET}'])

        if web_pid:
            web_table.append(['address:', f'{Colors.INFO}http://127.0.0.1:5000/{Colors.RESET}'])
            web_table.append(['log:', f'{Colors.INFO}{log_file}{Colors.RESET}'])
            web_table.append(['pid:', f'{Colors.INFO}{web_pid}{Colors.RESET}'])

        Helpers.print_and_log(tabulate(web_table, tablefmt='plain'))

    def _db_create(self, args):
        """
        Handler for the `watchtower db create` command.

        Creates a new database.

        Optional arguments:
            -n: Specify a name for the database.
            --force: Force overwrite of an existing database.

        :param args: Namespace object of arguments.
        :return: None.
        """
        db_name = args.name if args.name else 'watchtower'
        db = f"{self.config.get('default', 'database_dir')}{os.sep}{db_name}{os.extsep}{self.config.get('default', 'database_ext')}"
        if os.path.exists(db):
            if args.force:
                os.remove(db)
            else:
                exit(f'{Tags.FAIL} Database {Colors.INFO}{db}{Colors.RESET} already exists.  Run this command again with {Colors.INFO}--force{Colors.RESET} if you want to overwrite it.')
        Database(connect(db)).vacuum()  # Cheap trick to create an empty sqlite3 database
        Helpers.print_and_log(f"{Tags.SUCCESS} Database created: {Colors.INFO}{os.path.basename(db)}{Colors.RESET}")

    def _db_optimize(self, args):
        """
        Handler for the `watchtower db optimize` command.

        Optimizes a database.

        Required arguments:
            -d: Specify a database.

        :param args: Namespace object of arguments.
        :return: None.
        """
        if not args.database:
            exit(f'{Tags.FAIL} No database specified.  Run this command again with {Colors.INFO}-d{Colors.RESET} <{Colors.INFO}database{Colors.RESET}>.')

        target_db = args.database
        db = Database(connect(target_db))
        db_lock = self._get_file_lock(target_db)
        before_size = os.stat(os.path.realpath(target_db)).st_size

        try:
            with db_lock.acquire(timeout=self.lock_timeout):
                Helpers.print_and_log(f"{Tags.INFO} Optimizing {Colors.INFO}{os.path.basename(os.path.realpath(target_db))}{Colors.RESET}...")
                for table in db.tables:
                    if table.detect_fts() and re.match(Regex.FTS_TABLE, table.name):
                        table.optimize()
                db.conn.commit()  # Have to do this before vacuuming or we'll get an exception
                db.vacuum()
                after_size = os.stat(os.path.realpath(target_db)).st_size
                Helpers.print_and_log(f"{Tags.INFO} Reduced size by {Colors.INFO}{before_size-after_size:n}{Colors.RESET} byte(s).")
        except Timeout:
            Helpers.print_and_log(
                f'{Tags.FAIL} Could not acquire write lock on {Colors.INFO}{target_db}{Colors.RESET} after {Colors.INFO}{self.lock_timeout}{Colors.RESET} seconds because another instance of this application is using it.  Try again later.')
        finally:
            self._release_file_lock(db_lock)

    def _run(self, args):
        """
        Handler for the `watchtower run` command.

        Executes the run method for all modules.

        Optional arguments:
            -m: Specify a particular module.
            -a: Specify arguments for the run method (-a can be used multiple times).

        :param args: Namespace object of arguments.
        :return: None.
        """
        sys.path.append(os.path.realpath(self.config.get('default', 'module_dir')))
        modules = args.modules if args.modules else [m for m in self._get_all_modules()]

        for module in modules:
            if not re.match(Regex.ARG_NAME, module):
                Helpers.print_and_log(f'{Tags.FAIL} Could not run module {Colors.INFO}{module}{Colors.RESET}: Module names can only use lowercase letters, numbers, and underscores.')
                continue
            if module == 'test':
                # FIXME (jbacco): Known issue where modules named "test" won't run.
                Helpers.print_and_log(f'{Tags.FAIL} Could not run module {Colors.INFO}test{Colors.RESET}: An issue exists which prevents modules named {Colors.INFO}test{Colors.RESET} from running correctly.  Try renaming it.')
                continue
            try:
                args_info = f' with args {Colors.INFO}{args.args}{Colors.RESET}' if args.args and len(args.args) else ''
                Helpers.print_and_log(f"{Tags.INFO} Running module {Colors.INFO}{module}{Colors.RESET}{args_info}...")
                m = import_module(module)
                for name, klass in self._get_all_module_classes(m):
                    try:
                        output = klass().run(args.args)
                    except Exception as e:
                        Helpers.print_and_log(f"{Tags.FAIL} An exception was thrown while trying to execute the {Colors.INFO}run(){Colors.RESET} method of class {Colors.INFO}{name}{Colors.RESET} in {Colors.INFO}{module}{os.extsep}{self.config.get('default', 'module_ext')}{Colors.RESET}.  See details below:\n")
                        log_file = f"{self.config.get('default', 'app_log')}"
                        with open(log_file, 'a') as app_log:
                            traceback.print_exception(type(e), e, e.__traceback__)
                            traceback.print_exception(type(e), e, e.__traceback__, file=app_log)
                        continue
                    try:
                        Watchtower.validate_module_response(output)
                        filepath = Helpers.generate_timestamp_filename(self.config.get('default', 'cache_dir'), module, self.config.get('default', 'cache_ext'))
                        self._write_file(filepath, json.dumps(output, default=Helpers.json_serializer))
                        Helpers.print_and_log(f"{Tags.SUCCESS} Saved cache file: {Colors.INFO}{os.path.basename(filepath)}{Colors.RESET}")
                        Helpers.print_and_log(f"{Tags.INFO} Execution complete.")
                    except (AssertionError, TypeError) as e:
                        if output:
                            temp_fd, temp_path = tempfile.mkstemp()
                            self._write_file(temp_path, str(output))
                            Helpers.print_and_log(f"{Tags.FAIL} Cache file write failed.  The {Colors.INFO}run(){Colors.RESET} method of class {Colors.INFO}{name}{Colors.RESET} in {Colors.INFO}{module}{os.extsep}{self.config.get('default', 'module_ext')}{Colors.RESET} returned data that does not adhere to the Module Response guidelines (see {Colors.INFO}README.md{Colors.RESET}).  As a result, no cache files have been saved and nothing will be imported into the database.\n\nReason: {e}\n\nYou can inspect the response data here: {Colors.INFO}{temp_path}{Colors.RESET}\n")
                        else:
                            Helpers.print_and_log(f"{Tags.WARN} The {Colors.INFO}run(){Colors.RESET} method of class {Colors.INFO}{name}{Colors.RESET} in {Colors.INFO}{module}{os.extsep}{self.config.get('default', 'module_ext')}{Colors.RESET} did not return any data.  As a result, no cache files have been saved and nothing will be imported into the database.")
            except ModuleNotFoundError as mnfe:
                module_filepath = f"{self.config.get('default', 'module_dir')}{os.sep}{module}{os.extsep}{self.config.get('default', 'module_ext')}"
                if not os.path.exists(module_filepath):
                    Helpers.print_and_log(f"{Tags.FAIL} File {Colors.INFO}{module_filepath}{Colors.RESET} for module {Colors.INFO}{module}{Colors.RESET} does not exist.  Try adding it and then run this command again.")
                else:
                    Helpers.print_and_log(f"{Tags.FAIL} An error occurred while trying to run {Colors.INFO}{module_filepath}{Colors.RESET} for module {Colors.INFO}{module}{Colors.RESET}.  See details below:\n\n{mnfe}\n")
            except InvalidImplementation as ii:
                lines = str(ii).split('\n')
                klass = lines[1].split(' ')[1]
                issues = '\n'.join(map(str, lines[2:]))
                Helpers.print_and_log(f"{Tags.FAIL} Execution failed because {Colors.INFO}{klass}{Colors.RESET} in {Colors.INFO}{self.config.get('default', 'module_dir')}{os.sep}{module}{os.extsep}{self.config.get('default', 'module_ext')}{Colors.RESET} does not properly implement the Module interface.\n{issues}\n")

    def _cache_import(self, args):
        """
        Handler for the `watchtower import` command.

        Imports all cache files into a database.

        Required arguments:
            -d: Specify a database.

        Optional arguments:
            -m: Specify a list of modules (-m can be used multiple times).
            -f: Specify a list of cache files (-f can be used multiple times).
            --force: Force import of an existing cache file.

        :param args: Namespace object of arguments.
        :return: None.
        """
        if not args.database:
            exit(f'{Tags.FAIL} No database specified.  Run this command again with {Colors.INFO}-d{Colors.RESET} <{Colors.INFO}database{Colors.RESET}>.')

        files = list(map(lambda f: f, args.files if args.files else [file for module in args.modules for file in self._get_all_cache_files(module)] if args.modules else self._get_all_cache_files()))

        if not len(files):
            exit(f"{Tags.WARN} No cache files found.")

        target_db = args.database

        db_conn = connect(target_db)
        temp_db_conn = connect('')
        db_conn.backup(temp_db_conn)  # Copy the file database to a temporary database (much faster writes)

        db_lock = self._get_file_lock(target_db)

        try:
            with db_lock.acquire(timeout=self.lock_timeout):
                for f in files:
                    Helpers.print_and_log(f"{Tags.INFO} Importing file: {Colors.INFO}{os.path.basename(f)}{Colors.RESET}")
                    self._import_file(temp_db_conn, f, args.force)
                Helpers.print_and_log(f"{Tags.INFO} Committing changes...")
                temp_db_conn.backup(db_conn)  # If we don't get past this, the changes are lost
                Helpers.print_and_log(f"{Tags.INFO} Import complete.")
        except Timeout:
            Helpers.print_and_log(f'{Tags.FAIL} Could not acquire write lock on {Colors.INFO}{target_db}{Colors.RESET} after {Colors.INFO}{self.lock_timeout}{Colors.RESET} seconds because another instance of this application is using it.  Try again later.')
        finally:
            self._release_file_lock(db_lock)

    def _cache_clear(self, args):
        """
        Handler for the `watchtower cache clear` command.

        Clears (deletes) all cache files.

        Optional arguments:
            -m: Specify a list of modules (-m can be used multiple times).

        :param args: Namespace object of arguments.
        :return: None.
        """
        files = list(map(lambda f: f, [file for module in args.modules for file in self._get_all_cache_files(module)] if args.modules else self._get_all_cache_files()))
        cleared = 0
        for f in files:
            file_lock = self._get_file_lock(f)  # If we can't get a file lock, we shouldn't be deleting it
            try:
                with file_lock.acquire(timeout=self.lock_timeout):
                    os.remove(f)
                    cleared += 1
            except Timeout:
                Helpers.print_and_log(f'{Tags.FAIL} File {Colors.INFO}{f}{Colors.RESET} appears to be in use by another instance of this application.  Try again later.')
            finally:
                self._release_file_lock(file_lock)
        Helpers.print_and_log(f"{Tags.INFO} Cleared {Colors.INFO}{cleared}{Colors.RESET} cache file(s).")

    def _web_start(self, args):
        """
        Handler for the `watchtower web start` command.

        Starts the local web server.

        :param args: Namespace object of arguments.
        :return: None.
        """
        if self._find_webserver_pid():
            exit(f"{Tags.WARN} Web server appears to be running.  Check {Colors.INFO}http://127.0.0.1:5000/{Colors.RESET} or try stopping it with {Colors.INFO}watchtower web stop{Colors.RESET} and then run this command again.")

        log_file = f"{self.config.get('default', 'web_log')}"

        with open(log_file, 'a') as web_output:
            env = os.environ.copy()
            env.update({'FLASK_APP': f"{self.config.get('default', 'web_script')}", 'FLASK_ENV': 'development', 'FLASK_DEBUG': '0'})
            process = subprocess.Popen(
                ['python' if os.name == 'nt' else 'python3', '-m', 'flask', 'run'],
                env=env,
                stdout=web_output,
                stderr=web_output,
                shell=True if os.name == 'nt' else False
            )
            Helpers.print_and_log(f"{Tags.SUCCESS} Web server listening on {Colors.INFO}http://127.0.0.1:5000/{Colors.RESET}")
            Helpers.print_and_log(f"{Tags.INFO} Log: {Colors.INFO}{log_file}{Colors.RESET}")

    def _web_stop(self, args):
        """
        Handler for the `watchtower web stop` command.

        Stops the local web server.

        :param args: Namespace object of arguments.
        :return: None.
        """
        pid = self._find_webserver_pid()

        if pid:
            os.kill(pid, signal.SIGINT)
            exit(f"{Tags.SUCCESS} Web server stopped.")

        exit(f"{Tags.WARN} Web server does not appear to be running.")

    def execute_command(self, command, args):
        """
        Executes a Watchtower command (method) by its name.

        :param command: Watchtower command (method) to execute.  Must be declared in the Watchtower.valid_commands list.
        :param args: Namespace object of arguments to pass to the target method.
        :return: None.
        """
        cmd = ' '.join(command) if type(command) is list else command
        args = self._validate_and_normalize_args(args)
        valid_commands = {
            'status': self._status,
            'db create': self._db_create,
            'db optimize': self._db_optimize,
            'run': self._run,
            'import': self._cache_import,
            'cache clear': self._cache_clear,
            'web start': self._web_start,
            'web stop': self._web_stop
        }

        if cmd in valid_commands:
            valid_commands.get(cmd)(args)
        else:
            exit(f'{Tags.FAIL} Command not found.  Try {Colors.INFO}watchtower{Colors.RESET} for a list of commands.')


def _parse_args():
    """
    Parses all command line arguments.  Also handles the help menu.

    :return: Namespace object of arguments.
    """
    parser = argparse.ArgumentParser(prog='watchtower',
                                     add_help=False,
                                     description='',
                                     epilog='',
                                     usage=f'''{Colors.APP}
                                    s                               s                                                           
  x=~                              :8                .uef^"        :8                  x=~                                      
 88x.   .e.   .e.                 .88              :d88E          .88           u.    88x.   .e.   .e.                .u    .   
'8888X.x888:.x888        u       :888ooo       .   `888E         :888ooo  ...ue888b  '8888X.x888:.x888       .u     .d88B :@8c  
 `8888  888X '888k    us888u.  -*8888888  .udR88N   888E .z8k  -*8888888  888R Y888r  `8888  888X '888k   ud8888.  ="8888f8888r 
  X888  888X  888X .@88 "8888"   8888    <888'888k  888E~?888L   8888     888R I888>   X888  888X  888X :888'8888.   4888>'88"  
  X888  888X  888X 9888  9888    8888    9888 'Y"   888E  888E   8888     888R I888>   X888  888X  888X d888 '88%"   4888> '    
  X888  888X  888X 9888  9888    8888    9888       888E  888E   8888     888R I888>   X888  888X  888X 8888.+"      4888>      
 .X888  888X. 888~ 9888  9888   .8888Lu= 9888       888E  888E  .8888Lu= u8888cJ888   .X888  888X. 888~ 8888L       .d888L .+   
 `%88%``"*888Y"    9888  9888   ^%888*   ?8888u../  888E  888E  ^%888*    "*888*P"    `%88%``"*888Y"    '8888c. .+  ^"8888*"    
   `~     `"       "888*""888"    'Y"     "8888P'  m888N= 888>    'Y"       'Y"         `~     `"        "88888%       "Y"      
                    ^Y"   ^Y'               "P'     `Y"   888                                              "YP'                 
                                                         J88"                                                                   
                                                         @%                                                                     
                                                       :"                                                                       
{Colors.RESET}{Colors.COMMAND}attack surface organizational tool{Colors.RESET}

usage: {Colors.APP}watchtower{Colors.RESET} <{Colors.COMMAND}command{Colors.RESET}> [<{Colors.ARGS}args{Colors.RESET}>]

{Colors.COMMAND}status{Colors.RESET}                                  Print the configuration, module, and web server status
{Colors.COMMAND}status{Colors.RESET} -d <{Colors.ARGS}database{Colors.RESET}>                    Print the status of a database
{Colors.COMMAND}db create{Colors.RESET}                               Create a new database
{Colors.COMMAND}db create{Colors.RESET} -n <{Colors.ARGS}name{Colors.RESET}>                     Create a new database with a particular name
{Colors.COMMAND}db optimize{Colors.RESET} -d <{Colors.ARGS}database{Colors.RESET}>               Optimize a database
{Colors.COMMAND}run{Colors.RESET}                                     Run all modules
{Colors.COMMAND}run{Colors.RESET} -m <{Colors.ARGS}module{Colors.RESET}>                         Run a particular module (-m can be used multiple times)
{Colors.COMMAND}run{Colors.RESET} -a <{Colors.ARGS}arg{Colors.RESET}>                            Run all modules and pass an argument (-a can be used multiple times)
{Colors.COMMAND}run{Colors.RESET} -m <{Colors.ARGS}module{Colors.RESET}> -a <{Colors.ARGS}arg{Colors.RESET}>                Run a particular module and pass an argument (-m and -a can be used multiple times)
{Colors.COMMAND}import{Colors.RESET} -d <{Colors.ARGS}database{Colors.RESET}>                    Import all cache files into a database
{Colors.COMMAND}import{Colors.RESET} -d <{Colors.ARGS}database{Colors.RESET}> -m <{Colors.ARGS}module{Colors.RESET}>        Import all cache files for a particular module into a database (-m can be used multiple times)
{Colors.COMMAND}import{Colors.RESET} -d <{Colors.ARGS}database{Colors.RESET}> -f <{Colors.ARGS}filename{Colors.RESET}>      Import a particular cache file into a database (-f can be used multiple times)
{Colors.COMMAND}cache clear{Colors.RESET}                             Clear all cache files
{Colors.COMMAND}cache clear{Colors.RESET} -m <{Colors.ARGS}module{Colors.RESET}>                 Clear all cache files for a particular module (-m can be used multiple times)
{Colors.COMMAND}web start{Colors.RESET}                               Start the local web server
{Colors.COMMAND}web stop{Colors.RESET}                                Stop the local web server

conditional flags:

--force                                 Force a command to allow overwrites/duplicates ({Colors.COMMAND}db create{Colors.RESET}, {Colors.COMMAND}import{Colors.RESET})
''')
    parser.add_argument('command', help='', type=str, default=None, nargs='+')
    parser.add_argument('-n', dest='name', help='', type=str, default=None)
    parser.add_argument('-d', dest='database', help='', type=str, default=None)
    parser.add_argument('-m', dest='modules', help='', type=str, default=None, action='append')
    parser.add_argument('-a', dest='args', help='', type=str, default=None, action='append')
    parser.add_argument('-f', dest='files', help='', type=str, default=None, action='append')
    parser.add_argument('--force', dest='force', help='', default=False, action='store_true')

    if not len(sys.argv) > 1 or sys.argv[1].lower() in ['--help', '-h', 'help']:
        exit(parser.usage)

    try:
        args = parser.parse_args()
        return args
    except ValueError as ve:
        exit(f'{Tags.FAIL} Error while parsing arguments: {ve}')


def parse_config(file):
    """
    Parses a configuration file.

    :param file: Configuration file string.
    :return: ConfigParser object.
    """
    try:
        config = ConfigParser(interpolation=ExtendedInterpolation(), default_section='default', allow_no_value=True)
        config.read(file)
        return config
    except ParsingError as pe:
        lines = str(pe).split('\n')
        errors = '\n'.join(map(str, lines[1:]))
        raise Exception(f'{Tags.FAIL} Configuration file {Colors.INFO}{file}{Colors.RESET} could not be loaded due to parsing errors:\n\n{errors}\n')
    except (DuplicateSectionError, DuplicateOptionError) as de:
        raise Exception(f'{Tags.FAIL} Configuration file {Colors.INFO}{file}{Colors.RESET} could not be loaded due to parsing errors:\n\n{de}\n')


def _main():
    """
    Handler for all `watchtower` command line operations.

    :return: None.
    """
    args = _parse_args()
    command = args.command
    delattr(args, 'command')
    watchtower = Watchtower()
    watchtower.execute_command(command, args)


WatchtowerModule = implements(WatchtowerModuleInterface)

if __name__ == '__main__':
    _main()
