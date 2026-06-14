# 1. Insecure file download (Path traversal risk)
filename = request.args.get('file')
return send_file(os.path.join('/static', filename))

# 2. Sanitized file download (Path traversal protected)
from werkzeug.utils import secure_filename
filename = secure_filename(request.args.get('file'))
return send_from_directory('/static', filename)
