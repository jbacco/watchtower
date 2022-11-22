$(document).ready(function () {
    // Updates a table's tab label with content.
    let updateTableTabLabel = function(tableName, content, asHtml) {
        let label = ''.concat('#', tableName.replace(/_/g, '-'), '-label');
        if (asHtml) {
            $(label).html(content);
        } else {
            $(label).text(content);
        }
    };

    // Shows or hides the "Loading..." dimmer for a table.
    let toggleLoader = function(tableName, show) {
        let loader = ''.concat('#', tableName.replace(/_/g, '-'), '-loader');
        if (show) {
            $(loader).show();
        } else {
            $(loader).hide();
        }
    }

    // Shows or hides the error message banner for a table.
    let toggleError = function(tableName, message, show) {
        let error = ''.concat('#', tableName.replace(/_/g, '-'), '-error');
        if (show) {
            $(error).html(''.concat('<div class="ui text centered">', message, '</div>'));
            $(error).show();
        } else {
            $(error).hide();
        }
    }

    // Reloads all DataTables with the latest database selection and search query.
    let reloadDataTables = function() {
        let query = $('#global-search').val();
        $('table').each(function () {
            let table = $(this);
            toggleError(table.data('tbl'), null, false)
            toggleLoader(table.data('tbl'), true);
            updateTableTabLabel(table.data('tbl'), '<div><i class="fitted spinner loading icon"></i></div>', true);
            table.DataTable().ajax.url(generateUri(table.data('api'), {database: getDatabase(), table: table.data('tbl'), query: query})).load();
        });
    }

    // Tabify the tables.
    $('.menu .item').tab({
        onVisible: function() {
            // Force responsive tables to render correctly after a tab is clicked.
            $.fn.dataTable.tables({visible: true, api: true}).responsive.recalc();
        }
    });

    // Defaults for all DataTables.
    $.fn.dataTable.ext.errMode = 'none';
    $.extend($.fn.dataTable.defaults, {
        order: [[0, 'desc']],
        dom: 'tBp',
        lengthMenu: [ [10, 25, 50, 100, 500, 1000, -1], [10, 25, 50, 100, 500, 1000, 'All'] ],
        deferRender: true,
        serverSide: true,
        searching: false,
        processing: false,
        responsive: true,
        language: {
            emptyTable: 'No data available.',
        },
    });

    // Initialize each DataTable dynamically.
    $('table').each(function() {
        let query = $('#global-search').val();
        let table = $(this);
        let tableName = table.data('tbl');
        let dtCols = table.data('cols').split(',').map((column, index) => {
            return {position: index, title: column, data: column};
        });

        // Common column names for boolean fields.
        let booleanColumnPrefixes = ['is', 'has', 'can']

        // Render likely targets as a boolean.
        let booleanTargets = dtCols.filter(column => {
            let splitColumn = column.data.toLowerCase().split('_')
            if (splitColumn.length && booleanColumnPrefixes.includes(splitColumn[0])) {
                return true;
            }
        }).map(item => item.position);

        // Common column names for datetime fields.
        let dateTimeColumnNames = ['date', 'datetime', 'timestamp', 'created', 'created_at', 'updated', 'updated_at', 'last_update', 'last_updated', 'published', 'published_at', 'modified', 'modified_at', 'last_modified']

        // Render likely targets as a human datetime.
        let datetimeTargets = dtCols.filter(column => {
            if (dateTimeColumnNames.includes(column.data.toLowerCase())) {
                return true;
            }
        }).map(item => item.position);

        // Initialize datatable.
        let datatable = table.DataTable({
            ajax: {
                url: generateUri(table.data('api'), {database: getDatabase(), table: table.data('tbl'), query: query}),
                type: 'POST',
            },
            buttons: [
                'pageLength',
                { extend: 'copyHtml5' },
                { extend: 'excelHtml5', title: table.data('tbl') },
                { extend: 'csvHtml5', title: table.data('tbl') },
                { extend: 'pdfHtml5', title: table.data('tbl') },
            ],
            columns: dtCols,
            columnDefs: [{
                targets: datetimeTargets,
                render: function(data, type) {
                    if (data) {
                        let format = data.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/) ? 'll' : 'llll z';
                        return (type === 'display' ? '<div data-tooltip="' + moment.tz(data, moment.tz.guess()).format(format) + '">' + data + '</div>' : data);
                    } else {
                        return '';
                    }
                },
            }, {
                targets: booleanTargets,
                render: function (data, type) {
                    return (type === 'display' ? (data === 1) : data);
                },
            }, {
                targets: '_all',
                render: $.fn.dataTable.render.text(),
                width: '3em',
            }],
            autoWidth: false,
            drawCallback: function() {
                updateTableTabLabel(tableName, datatable.page.info().recordsDisplay.toLocaleString(), false);
                toggleLoader(table.data('tbl'), false);
            }
        }).on('error.dt', function(e, settings, techNote, message) {
            let tableName = $(this).data('tbl');
            let errorMessage = ''.concat('Error:', ' ', message.split(' - ')[1]);
            toggleError(tableName, errorMessage, true);
            updateTableTabLabel(tableName, datatable.page.info().recordsDisplay.toLocaleString(), false);
        }).on( 'length.dt', function(e, settings, len) {
            toggleLoader(table.data('tbl'), true);
        })
    });

    // Tell each DataTable to perform a new AJAX call after each keypress within the global search box.
    $('#global-search').keyup(function () {
        reloadDataTables();
    });

    // Triple click copies the clicked text to global search box and forces a global search.
    $(document).on('tripleclick', 'td', function () {
        $('#global-search').val($(this).text()).keyup();
    });
});