from flask import Flask, render_template, request, jsonify, send_file
from crypto_utils import CryptoManager
import json
import qrcode
import os
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
crypto_manager = CryptoManager()

# Store keys in memory (in production, you'd want to store these securely)
keys = {}

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

os.makedirs('static', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    private_key, public_key = crypto_manager.generate_rsa_keys()
    key_id = len(keys)  # Simple key ID generation
    keys[key_id] = {
        'private_key': private_key,
        'public_key': public_key
    }
    return jsonify({
        'key_id': key_id,
        'public_key': public_key.decode('utf-8')
    })

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        message = data['message']
        key_id = int(data['key_id'])
        
        if key_id not in keys:
            return jsonify({'error': 'Invalid key ID'}), 400
        
        encrypted_data = crypto_manager.encrypt_message(
            message, 
            keys[key_id]['public_key']
        )
        return jsonify(encrypted_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        encrypted_data = data['encrypted_data']
        key_id = int(data['key_id'])
        
        if key_id not in keys:
            return jsonify({'error': 'Invalid key ID'}), 400
        
        decrypted_message = crypto_manager.decrypt_message(
            encrypted_data,
            keys[key_id]['private_key']
        )
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    try:
        data = request.get_json()
        if not data or 'encrypted_data' not in data:
            return jsonify({'error': 'No encrypted data provided'}), 400
            
        encrypted_data = json.dumps(data['encrypted_data'])
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(encrypted_data)
        qr.make(fit=True)

        # Generate unique filename
        qr_filename = f'qr_code_{hash(encrypted_data)}.png'
        qr_code_path = os.path.join('static', qr_filename)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_code_path)

        return jsonify({'qr_code_path': f'/{qr_code_path}'})
    except Exception as e:
        print(f"QR Generation Error: {str(e)}")  # For debugging
        return jsonify({'error': str(e)}), 400

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        key_id = int(request.form['key_id'])
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if key_id not in keys:
            return jsonify({'error': 'Invalid key ID'}), 400
            
        if file and allowed_file(file.filename):
            # Read file data
            file_data = file.read()
            filename = secure_filename(file.filename)
            
            # Encrypt file data
            encrypted_data = crypto_manager.encrypt_file(
                file_data,
                keys[key_id]['public_key']
            )
            
            # Add filename to encrypted data
            encrypted_data['filename'] = filename
            
            return jsonify(encrypted_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    try:
        data = request.get_json()
        encrypted_data = data['encrypted_data']
        key_id = int(data['key_id'])
        
        if key_id not in keys:
            return jsonify({'error': 'Invalid key ID'}), 400
            
        # Get the original filename
        filename = encrypted_data.pop('filename')
        
        # Decrypt the file
        decrypted_data = crypto_manager.decrypt_file(
            encrypted_data,
            keys[key_id]['private_key']
        )
        
        # Create a BytesIO object
        file_obj = io.BytesIO(decrypted_data)
        
        # Send the file
        return send_file(
            file_obj,
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True) 