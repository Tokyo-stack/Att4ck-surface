# 1. Insecure file upload handling
file = request.files['file']
file.save(os.path.join('/uploads', file.filename))

# 2. Sanitized file upload handling
from werkzeug.utils import secure_filename
file = request.files['file']
filename = secure_filename(file.filename)
file.save(os.path.join('/uploads', filename))
