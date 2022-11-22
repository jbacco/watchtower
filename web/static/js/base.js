// Generates a URI with parameters.
let generateUri = function(uri, params) {
    return ''.concat(uri, '?', $.param(params));
};

// Fetches the current database name.
let getDatabase = function() {
    return $('#database').val().replace(/\s/g, '_');
};

$(document).ready(function () {
    // Create dropdowns.
    $('.ui.dropdown').dropdown();

    // Reload page when the database changes.
    $('#database').change(function () {
        window.location.href = generateUri(window.location.pathname, {database: getDatabase()});
    });

    // Register database download button handler.
    $('#database-download').click(function() {
        let params = {
            database: getDatabase(),
        }
        window.location.href = ''.concat($(this).data('api'), '?', $.param(params));
    });
});