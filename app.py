from flask import Flask, request, redirect, url_for, render_template, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import io
import os
from flask import send_file
from flask_migrate import Migrate

# Initializing flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Creating upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#setting up the sql database
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

#flask login-manager
login_manager = LoginManager()
login_manager.init_app(app)

#tables for realtionship between users and files
files_shared = db.Table('files_shared',
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# User model
class User(UserMixin, db.Model):
    """
    User model for storing user-related data.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    shared_files = db.relationship('File', secondary=files_shared, 
                                   backref=db.backref('shared_with_users', lazy='dynamic'))

# File model
class File(db.Model):
    """
    File model for storing file-related data.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    hash_digest = db.Column(db.String(64))
    shared_users = db.Column(db.String)
    encryption_key = db.Column(db.String(64))  # Assuming a 32-byte key encoded in hex
    iv = db.Column(db.String(32))              # Assuming a 16-byte IV encoded in hex


@login_manager.user_loader
def load_user(user_id):
    """
    Load user given the user ID.
    """
    return User.query.get(int(user_id))

#login
login_manager.login_view = 'login'

# Home page route
@app.route('/')
def index():
    """Render the home page."""
    return render_template ('home.html')

# registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username'] 
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')       # Hashing the password for secure storage
        new_user = User(username=username, password_hash=hashed_password) #creating a new user with username and the hashed password
        db.session.add(new_user) #adding it to the database
        db.session.commit()  
        return redirect(url_for('login')) # moving to the login page after succesful registration
    return render_template('register.html') 

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Handle user login."""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):   # Check if the user exists and the password is correct
            login_user(user)
            return redirect(url_for('dashboard'))        # Log in the user and redirect to the dashboard
        else:
            return render_template ('invalid.html')       # If login details are incorrect, show an invalid login template
    return render_template('login.html')

#Logout route 
@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()    # logging out user
    return redirect(url_for('index'))

@app.route('/invalid', methods= ['GET','POST'])  # an invalid route if the user details are incorrect
def invalid():
    pass

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Render the dashboard page showing owned and shared files.
    """
    # Fetching files owned by the user
    owned_files = File.query.filter_by(user_id=current_user.id).all()

    # Fetching files shared with the user
    # This query retrieves all files where the current user's username is included in the 'shared_users' field
    shared_files = File.query.filter(File.shared_users.contains(current_user.username)).all()

    #Displaying owned and shared files
    all_files = owned_files + shared_files

    # data which will be displayed showing the file details 
    file_data = [{
        'name': file.name,
        'download_url': url_for('download_file', file_id=file.id),
        'id': file.id,
        'is_owner': file.user_id == current_user.id  #indicating if the user is the owner of the file
    } for file in all_files]

    return render_template('dashboard.html', name=current_user.username, files=file_data)


def encrypt_file(file_data):
    """
    Encrypt file data using AES encryption.

    :param file_data: Data to encrypt
    :return: tuple of encrypted data, IV, and key
    """
    key = get_random_bytes(16)     # Generating a random 16-byte key for AES encryption
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))     # Encrypting the file data, padding it to ensure it's a multiple of the block size
    iv = cipher.iv
    return ct_bytes, iv, key

def decrypt_file(ct, iv, key):
    """
    Decrypt file data using AES decryption.

    :param ct: Encrypted data
    :param iv: Initialization vector
    :param key: Encryption key
    :return: Decrypted data
    """
    # Creating a new AES cipher in CBC mode 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)     # Decrypting the cipher text and remove padding
    return pt

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """
    Allows authenticated users to upload files. 
    Handles file encryption and sharing with specified users.
    """
    if request.method == 'POST':
        file = request.files['file']
        shared_users = request.form.get('shared_with')  # Retrieve usernames to share the file with

        # List to hold valid usernames for sharing
        valid_usernames = []

        # Message to provide feedback to the user
        user_feedback = ''

        # Processing the file if it's present
        if file:
            filename = secure_filename(file.filename)  # Secure the filename
            file_data = file.read()
            encrypted_data, iv, key = encrypt_file(file_data)  # Encrypt the file
            hash_digest = hashlib.sha256(file_data).hexdigest()  # Generate hash for integrity check

            # Creating a new file record
            new_file = File(name=filename, data=encrypted_data, user_id=current_user.id, hash_digest=hash_digest, encryption_key=key.hex(),
    iv=iv.hex())

            # Processing shared users if any
            if shared_users:
                shared_usernames = [username.strip() for username in shared_users.split(',')]
                invalid_usernames = []

                # Validating each username
                for username in shared_usernames:
                    user = User.query.filter_by(username=username).first()

                    if user:
                        valid_usernames.append(username)
                    else:
                        invalid_usernames.append(username)

                # Updating file record with valid usernames
                if valid_usernames:
                    new_file.shared_users = ','.join(valid_usernames)
                    user_feedback += 'File shared with: ' + ', '.join(valid_usernames) + '. '
                if invalid_usernames:
                    user_feedback += 'Invalid usernames not found: ' + ', '.join(invalid_usernames) + '.'

            db.session.add(new_file)
            db.session.commit()

            # Store encryption key and IV in environment variables (consider a more secure method for production)
            os.environ[f'file_key_{new_file.id}'] = key.hex()
            os.environ[f'file_iv_{new_file.id}'] = iv.hex()

            flash(user_feedback or 'File uploaded successfully', 'success')
            return redirect(url_for('dashboard'))

    return render_template('upload.html')


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """
    Allows users to download files that they own or have been shared with them.
    Handles decryption of the file for download.
    """
    app.logger.info(f"Attempting to download file with ID: {file_id}")
    
    try:
        file = File.query.get_or_404(file_id)

        # Checking user authorization for the file
        shared_users = file.shared_users.split(',') if file.shared_users else []
        if file.user_id != current_user.id and current_user.username not in shared_users:
            flash('You do not have access to this file.', 'danger')
            return redirect(url_for('dashboard'))

        # Retrieving the encryption key and IV
        key_hex = os.environ.get(f'file_key_{file_id}')
        iv_hex = os.environ.get(f'file_iv_{file_id}')
        
        if key_hex is None or iv_hex is None:
            flash('The encryption key or IV is missing.', 'danger')
            app.logger.error("Key or IV is missing.")
            return redirect(url_for('dashboard'))

        # Decrypting the file
        key = bytes.fromhex(file.encryption_key)
        iv = bytes.fromhex(file.iv)
        decrypted_data = decrypt_file(file.data, iv, key)

        # Verifying file integrity
        hash_check = hashlib.sha256(decrypted_data).hexdigest()
        if hash_check != file.hash_digest:
            flash('File integrity check failed.', 'danger')
            app.logger.error("File integrity check failed.")
            return redirect(url_for('dashboard'))

        app.logger.info(f"Sending file {file.name} to client.")
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=file.name
        )
    
    except Exception as e:
        app.logger.error(f"Error occurred: {e}")
        flash('An error occurred during file download.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/share_file/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    """
    Allows users to share an already uploaded file with other users.
    """
    try:
        file_to_share = File.query.get_or_404(file_id)

        # Checking if the current user is the owner of the file
        if file_to_share.user_id != current_user.id:
            flash('Unauthorized access to the file.', 'danger')
            return redirect(url_for('dashboard'))

        shared_with = request.form.get('shared_with')

        # Initialize shared_users if None
        if file_to_share.shared_users is None:
            file_to_share.shared_users = ""

        # Process sharing if usernames are provided
        if shared_with:
            shared_users = shared_with.split(',')
            invalid_usernames = []

            # Iterating through the usernames and update the sharing status
            for username in shared_users:
                username = username.strip()
                user = User.query.filter_by(username=username).first()

                if user and username not in file_to_share.shared_users.split(','):
                    file_to_share.shared_users += f"{username},"
                elif not user:
                    invalid_usernames.append(username)

            if invalid_usernames:
                flash(f'Could not find users: {", ".join(invalid_usernames)}.', 'warning')
            else:
                flash('File shared successfully', 'success')

            db.session.commit()
        else:
            flash('No username provided for sharing.', 'info')

    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))
    
if __name__ == '__main__':
    with app.app_context():  # providing the application context needed for db.create_all()
        db.create_all()
    app.run(debug=True)

