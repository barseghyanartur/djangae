#STANDARD LIB
import datetime
import decimal
import sys
import warnings

#LIBRARIES
from django.conf import settings
from django.core.cache import cache
from django.db.backends import (
    BaseDatabaseOperations,
    BaseDatabaseClient,
    BaseDatabaseIntrospection,
    BaseDatabaseWrapper,
    BaseDatabaseFeatures,
    BaseDatabaseValidation
)
try:
    from django.db.backends.schema import BaseDatabaseSchemaEditor
except ImportError:
    #Django < 1.6 doesn't have BaseDatabaseSchemaEditor
    class BaseDatabaseSchemaEditor(object):
        pass
from django.db.backends.creation import BaseDatabaseCreation
from django.db import IntegrityError
from django.utils import timezone
from google.appengine.api import datastore
from google.appengine.api.datastore_types import Blob, Text, Key
from google.appengine.ext.db import metadata
from google.appengine.ext import testbed

#DJANGAE
from djangae.db.utils import (
    decimal_to_string,
    make_timezone_naive,
)
from djangae.indexing import load_special_indexes, special_indexes_for_column, REQUIRES_SPECIAL_INDEXES
from .commands import (
    SelectCommand,
    InsertCommand,
    FlushCommand,
    UpdateCommand,
    DeleteCommand,
    get_field_from_column
)

class DatabaseError(Exception):
    pass

class IntegrityError(IntegrityError, DatabaseError):
    pass

class NotSupportedError(DatabaseError):
    pass

class CouldBeSupportedError(DatabaseError):
    pass

DEFAULT_CACHE_TIMEOUT = 10

def cache_entity(model, entity):
    unique_combinations = get_uniques_from_model(model)

    unique_keys = []
    for fields in unique_combinations:
        key_parts = []
        for x in fields:
            if x == model._meta.pk.column and x not in entity:
                value = entity.key().id_or_name()
            else:
                value = entity[x]

            key_parts.append((x, value))

        unique_keys.append(generate_unique_key(model, key_parts))

    for key in unique_keys:
        #logging.error("Caching entity with key %s", key)
        cache.set(key, entity, DEFAULT_CACHE_TIMEOUT)

def uncache_entity(model, entity):
    unique_combinations = get_uniques_from_model(model)

    unique_keys = []
    for fields in unique_combinations:
        key_parts = []
        for x in fields:
            if x == model._meta.pk.column and x not in entity:
                value = entity.key().id_or_name()
            else:
                value = entity[x]
            key_parts.append((x, value))

        key = generate_unique_key(model, key_parts)
        cache.delete(key)

def get_uniques_from_model(model):
    uniques = [ [ model._meta.get_field(y).column for y in x ] for x in model._meta.unique_together ]
    uniques.extend([[x.column] for x in model._meta.fields if x.unique])
    return uniques

def generate_unique_key(model, fields_and_values):
    fields_and_values = sorted(fields_and_values, key=lambda x: x[0]) #Sort by field name

    key = '%s.%s|' % (model._meta.app_label, get_datastore_kind(model))
    key += '|'.join(['%s:%s' % (field, value) for field, value in fields_and_values])
    return key

def get_entity_from_cache(key):
    entity = cache.get(key)
#    if entity:
#        logging.error("Got entity from cache with key %s", key)
    return entity

def get_datastore_kind(model):
    db_table = model._meta.db_table

    for parent in model._meta.parents.keys():
        if not parent._meta.parents and not parent._meta.abstract:
            db_table = parent._meta.db_table
            break
    return db_table

class Connection(object):
    """ Dummy connection class """
    def __init__(self, wrapper, params):
        self.creation = wrapper.creation
        self.ops = wrapper.ops
        self.params = params
        self.queries = []

    def rollback(self):
        pass

    def commit(self):
        pass

    def close(self):
        pass


class MockInstance(object):
    """
        This creates a mock instance for use when passing a datastore entity
        into get_prepared_db_value. This is used when performing updates to prevent a complete
        conversion to a Django instance before writing back the entity
    """

    def __init__(self, field, value, is_adding=False):
        class State:
            adding = is_adding

        self._state = State()
        self.field = field
        self.value = value

    def __getattr__(self, attr):
        if attr == self.field.attname:
            return self.value
        return super(MockInstance, self).__getattr__(attr)


def get_prepared_db_value(connection, instance, field, raw=False):
    value = getattr(instance, field.attname) if raw else field.pre_save(instance, instance._state.adding)

    value = field.get_db_prep_save(
        value,
        connection = connection
    )

    value = connection.ops.value_for_db(value, field)

    return value

def django_instance_to_entity(connection, model, fields, raw, instance):
    uses_inheritance = False
    inheritance_root = model
    db_table = get_datastore_kind(model)

    def value_from_instance(_instance, _field):
        value = get_prepared_db_value(connection, _instance, _field, raw)

        if (not _field.null and not _field.primary_key) and value is None:
            raise IntegrityError("You can't set %s (a non-nullable "
                                     "field) to None!" % _field.name)

        is_primary_key = False
        if _field.primary_key and _field.model == inheritance_root:
            is_primary_key = True

        return value, is_primary_key

    if [ x for x in model._meta.get_parent_list() if not x._meta.abstract]:
        #We can simulate multi-table inheritance by using the same approach as
        #datastore "polymodels". Here we store the classes that form the heirarchy
        #and extend the fields to include those from parent models
        classes = [ model._meta.db_table ]
        for parent in model._meta.get_parent_list():
            if not parent._meta.parents:
                #If this is the top parent, override the db_table
                inheritance_root = parent

            classes.append(parent._meta.db_table)
            for field in parent._meta.fields:
                fields.append(field)

        uses_inheritance = True


    #FIXME: This will only work for two levels of inheritance
    for obj in model._meta.get_all_related_objects():
        if model in [ x for x in obj.model._meta.parents if not x._meta.abstract]:
            try:
                related_obj = getattr(instance, obj.var_name)
            except obj.model.DoesNotExist:
                #We don't have a child attached to this field
                #so ignore
                continue

            for field in related_obj._meta.fields:
                fields.append(field)

    field_values = {}
    primary_key = None

    # primary.key = self.model._meta.pk
    for field in fields:
        value, is_primary_key = value_from_instance(instance, field)
        if is_primary_key:
            primary_key = value
        else:
            field_values[field.column] = value

        #Add special indexed fields
        for index in special_indexes_for_column(model, field.column):
            indexer = REQUIRES_SPECIAL_INDEXES[index]
            field_values[indexer.indexed_column_name(field.column)] = indexer.prep_value_for_database(value)

    kwargs = {}
    if primary_key:
        if isinstance(primary_key, int):
            kwargs["id"] = primary_key
        elif isinstance(primary_key, basestring):
            if len(primary_key) >= 500:
                warnings.warn("Truncating primary key"
                    " that is over 500 characters. THIS IS AN ERROR IN YOUR PROGRAM.",
                    RuntimeWarning
                )
                primary_key = primary_key[:500]

            kwargs["name"] = primary_key
        else:
            raise ValueError("Invalid primary key value")

    entity = datastore.Entity(db_table, **kwargs)
    entity.update(field_values)

    if uses_inheritance:
        entity["class"] = classes

    #print inheritance_root.__name__ if inheritance_root else "None", model.__name__, entity
    return entity

class Cursor(object):
    """ Dummy cursor class """
    def __init__(self, connection):
        self.connection = connection
        self.start_cursor = None
        self.returned_ids = []
        self.rowcount = -1
        self.last_select_command = None
        self.last_delete_command = None

    def execute(self, sql, *params):
        if isinstance(sql, SelectCommand):
            #Also catches subclasses of SelectCommand (e.g Update)
            self.last_select_command = sql
            self.rowcount = self.last_select_command.execute() or -1
        elif isinstance(sql, FlushCommand):
            sql.execute()
        elif isinstance(sql, UpdateCommand):
            self.rowcount = sql.execute()
        elif isinstance(sql, DeleteCommand):
            self.rowcount = sql.execute()
        elif isinstance(sql, InsertCommand):
            self.connection.queries.append(sql)
            self.returned_ids = sql.execute()
        else:
            import pdb;pdb.set_trace()
            raise RuntimeError("Can't execute traditional SQL: '%s'", sql)

    def fix_fk_null(self, query, constraint):
        alias = constraint.alias
        table_name = query.alias_map[alias][TABLE_NAME]
        lhs_join_col, rhs_join_col = join_cols(query.alias_map[alias])
        if table_name != constraint.field.rel.to._meta.db_table or \
                rhs_join_col != constraint.field.rel.to._meta.pk.column or \
                lhs_join_col != constraint.field.column:
            return
        next_alias = query.alias_map[alias][LHS_ALIAS]
        if not next_alias:
            return
        self.unref_alias(query, alias)
        alias = next_alias
        constraint.col = constraint.field.column
        constraint.alias = alias

    def next(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def fetchone(self, delete_flag=False):
        try:
            if isinstance(self.last_select_command.results, int):
                #Handle aggregate (e.g. count)
                return (self.last_select_command.results, )
            else:
                entity = self.last_select_command.next_result()
        except StopIteration:
            entity = None

        if entity is None:
            return None

        ## FIXME: Move this to SelectCommand.next_result()
        result = []
        for col in self.last_select_command.queried_fields:
            if col == "__key__":
                key = entity.key()
                self.returned_ids.append(key)
                result.append(key.id_or_name())
            else:
                field = get_field_from_column(self.last_select_command.model, col)
                value = self.connection.ops.convert_values(entity.get(col), field)

                #dates() queries need to have their values manipulated before returning
                #so we do that here if necessary!
                if col in self.last_select_command.field_conversions:
                    value = self.last_select_command.field_conversions[col](value)

                result.append(value)

        return result

    def fetchmany(self, size, delete_flag=False):
        if not self.last_select_command.results:
            return []

        result = []
        i = 0
        while i < size:
            entity = self.fetchone(delete_flag)
            if entity is None:
                break

            result.append(entity)
            i += 1

        return result

    @property
    def lastrowid(self):
        return self.returned_ids[-1].id_or_name()

    def __iter__(self):
        return self

class Database(object):
    """ Fake DB API 2.0 for App engine """

    Error = DatabaseError
    DataError = DatabaseError
    DatabaseError = DatabaseError
    OperationalError = DatabaseError
    IntegrityError = IntegrityError
    InternalError = DatabaseError
    ProgrammingError = DatabaseError
    NotSupportedError = NotSupportedError
    InterfaceError = DatabaseError


class DatabaseOperations(BaseDatabaseOperations):
    compiler_module = "djangae.db.backends.appengine.compiler"

    def quote_name(self, name):
        return name

    def convert_values(self, value, field):
        """ Called when returning values from the datastore"""

        value = super(DatabaseOperations, self).convert_values(value, field)

        db_type = self.connection.creation.db_type(field)
        if db_type == 'string' and isinstance(value, str):
            value = value.decode("utf-8")
        elif db_type == "datetime":
            value = self.connection.ops.value_from_db_datetime(value)
        elif db_type == "date":
            value = self.connection.ops.value_from_db_date(value)
        elif db_type == "time":
            value = self.connection.ops.value_from_db_time(value)
        elif db_type == "decimal":
            value = self.connection.ops.value_from_db_decimal(value)

        return value

    def sql_flush(self, style, tables, seqs, allow_cascade=False):
        from django.conf import settings
        if getattr(settings, "COMPLETE_FLUSH_WHILE_TESTING", False):
            if "test" in sys.argv:
                tables = metadata.get_kinds()

        return [ FlushCommand(table) for table in tables ]

    def prep_lookup_key(self, model, value, field):
        if isinstance(value, basestring):
            value = value[:500]
            left = value[500:]
            if left:
                warnings.warn("Truncating primary key"
                    " that is over 500 characters. THIS IS AN ERROR IN YOUR PROGRAM.",
                    RuntimeWarning
                )
            value = Key.from_path(get_datastore_kind(model), value)
        else:
            value = Key.from_path(get_datastore_kind(model), value)

        return value

    def prep_lookup_decimal(self, model, value, field):
        return self.value_to_db_decimal(value, field.max_digits, field.decimal_places)

    def prep_lookup_value(self, model, value, field):
        if field.primary_key:
            return self.prep_lookup_key(model, value, field)

        db_type = self.connection.creation.db_type(field)
        if db_type == 'decimal':
            return self.prep_lookup_decimal(model, value, field)

        return value

    def value_for_db(self, value, field):
        if value is None:
            return None

        db_type = self.connection.creation.db_type(field)

        if db_type == 'string' or db_type == 'text':
            if isinstance(value, str):
                value = value.decode('utf-8')
            if db_type == 'text':
                value = Text(value)
        elif db_type == 'bytes':
            # Store BlobField, DictField and EmbeddedModelField values as Blobs.
            value = Blob(value)
        elif db_type == 'date':
            value = self.value_to_db_date(value)
        elif db_type == 'datetime':
            value = self.value_to_db_datetime(value)
        elif db_type == 'time':
            value = self.value_to_db_time(value)
        elif db_type == 'decimal':
            value = self.value_to_db_decimal(value, field.max_digits, field.decimal_places)

        return value

    def last_insert_id(self, cursor, db_table, column):
        return cursor.lastrowid

    def fetch_returned_insert_id(self, cursor):
        return cursor.lastrowid

    def value_to_db_datetime(self, value):
        value = make_timezone_naive(value)
        return value

    def value_to_db_date(self, value):
        if value is not None:
            value = datetime.datetime.combine(value, datetime.time())
        return value

    def value_to_db_time(self, value):
        if value is not None:
            value = make_timezone_naive(value)
            value = datetime.datetime.combine(datetime.datetime.fromtimestamp(0), value)
        return value

    def value_to_db_decimal(self, value, max_digits, decimal_places):
        if isinstance(value, decimal.Decimal):
            return decimal_to_string(value, max_digits, decimal_places)
        return value

    ##Unlike value_to_db, these are not overridden or standard Django, it's just nice to have symmetry
    def value_from_db_datetime(self, value):
        if isinstance(value, (int, long)):
            #App Engine Query's don't return datetime fields (unlike Get) I HAVE NO IDEA WHY, APP ENGINE SUCKS MONKEY BALLS
            value = datetime.datetime.fromtimestamp(float(value) / 1000000.0)

        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            value = value.replace(tzinfo=timezone.utc)
        return value

    def value_from_db_date(self, value):
        if isinstance(value, (int, long)):
            #App Engine Query's don't return datetime fields (unlike Get) I HAVE NO IDEA WHY, APP ENGINE SUCKS MONKEY BALLS
            value = datetime.datetime.fromtimestamp(float(value) / 1000000.0)

        return value.date()

    def value_from_db_time(self, value):
        if isinstance(value, (int, long)):
            #App Engine Query's don't return datetime fields (unlike Get) I HAVE NO IDEA WHY, APP ENGINE SUCKS MONKEY BALLS
            value = datetime.datetime.fromtimestamp(float(value) / 1000000.0).time()

        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            value = value.replace(tzinfo=timezone.utc)
        return value.time()

    def value_from_db_decimal(self, value):
        if value:
            value = decimal.Decimal(value)
        return value

class DatabaseClient(BaseDatabaseClient):
    pass


class DatabaseCreation(BaseDatabaseCreation):
    data_types = {
        'AutoField':                  'key',
        'RelatedAutoField':           'key',
        'ForeignKey':                 'key',
        'OneToOneField':              'key',
        'ManyToManyField':            'key',
        'BigIntegerField':            'long',
        'BooleanField':               'bool',
        'CharField':                  'string',
        'CommaSeparatedIntegerField': 'string',
        'DateField':                  'date',
        'DateTimeField':              'datetime',
        'DecimalField':               'decimal',
        'EmailField':                 'string',
        'FileField':                  'string',
        'FilePathField':              'string',
        'FloatField':                 'float',
        'ImageField':                 'string',
        'IntegerField':               'integer',
        'IPAddressField':             'string',
        'NullBooleanField':           'bool',
        'PositiveIntegerField':       'integer',
        'PositiveSmallIntegerField':  'integer',
        'SlugField':                  'string',
        'SmallIntegerField':          'integer',
        'TimeField':                  'time',
        'URLField':                   'string',
        'AbstractIterableField':      'list',
        'ListField':                  'list',
        'RawField':                   'raw',
        'BlobField':                  'bytes',
        'TextField':                  'text',
        'XMLField':                   'text',
        'SetField':                   'list',
        'DictField':                  'bytes',
        'EmbeddedModelField':         'bytes'
    }

    def db_type(self, field):
        return self.data_types[field.__class__.__name__]

    def __init__(self, *args, **kwargs):
        self.testbed = None
        super(DatabaseCreation, self).__init__(*args, **kwargs)

    def sql_create_model(self, model, *args, **kwargs):
        return [], {}

    def sql_for_pending_references(self, model, *args, **kwargs):
        return []

    def sql_indexes_for_model(self, model, *args, **kwargs):
        return []

    def _create_test_db(self, verbosity, autoclobber):
        from google.appengine.datastore import datastore_stub_util
        # Testbed exists in memory
        test_database_name = ':memory:'

        # Init test stubs
        self.testbed = testbed.Testbed()
        self.testbed.activate()

        self.testbed.init_app_identity_stub()
        self.testbed.init_blobstore_stub()
        self.testbed.init_capability_stub()
        self.testbed.init_channel_stub()

        self.testbed.init_datastore_v3_stub(datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=0))
        self.testbed.init_files_stub()
        # FIXME! dependencies PIL
        # self.testbed.init_images_stub()
        self.testbed.init_logservice_stub()
        self.testbed.init_mail_stub()
        self.testbed.init_memcache_stub()
        self.testbed.init_taskqueue_stub()
        self.testbed.init_urlfetch_stub()
        self.testbed.init_user_stub()
        self.testbed.init_xmpp_stub()
        # self.testbed.init_search_stub()

        # Init all the stubs!
        # self.testbed.init_all_stubs()

        return test_database_name


    def _destroy_test_db(self, name, verbosity):
        if self.testbed:
            self.testbed.deactivate()


class DatabaseIntrospection(BaseDatabaseIntrospection):
    def get_table_list(self, cursor):
        return metadata.get_kinds()

class DatabaseSchemaEditor(BaseDatabaseSchemaEditor):
    def column_sql(self, model, field):
        return "", {}

    def create_model(self, model):
        """ Don't do anything when creating tables """
        pass

class DatabaseFeatures(BaseDatabaseFeatures):
    empty_fetchmany_value = []
    supports_transactions = False #FIXME: Make this True!
    can_return_id_from_insert = True
    supports_select_related = False

class DatabaseWrapper(BaseDatabaseWrapper):
    operators = {
        'exact': '= %s',
        'gt': '> %s',
        'gte': '>= %s',
        'lt': '< %s',
        'lte': '<= %s'
    }

    Database = Database

    def __init__(self, *args, **kwargs):
        super(DatabaseWrapper, self).__init__(*args, **kwargs)

        self.features = DatabaseFeatures(self)
        self.ops = DatabaseOperations(self)
        self.client = DatabaseClient(self)
        self.creation = DatabaseCreation(self)
        self.introspection = DatabaseIntrospection(self)
        self.validation = BaseDatabaseValidation(self)

    def is_usable(self):
        return True

    def get_connection_params(self):
        return {}

    def get_new_connection(self, params):
        conn = Connection(self, params)
        load_special_indexes() #make sure special indexes are loaded
        return conn

    def init_connection_state(self):
        pass

    def _set_autocommit(self, enabled):
        pass

    def create_cursor(self):
        if not self.connection:
            self.connection = self.get_new_connection(self.settings_dict)

        return Cursor(self.connection)

    def schema_editor(self, *args, **kwargs):
        return DatabaseSchemaEditor(self, *args, **kwargs)

    def _cursor(self):
        #for < Django 1.6 compatiblity
        return self.create_cursor()
