const params = new URLSearchParams(window.location.search)

document.getElementById('heading').innerHTML = 'Results for ' + params.get('q')
