const params = new URLSearchParams(window.location.search)

document.getElementById('heading').textContent = 'Results for ' + params.get('q')
